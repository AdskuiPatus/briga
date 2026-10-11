"""Нагрузочный генератор синтетических записей (раздел 10 кейса).

Контрольная нагрузка: до 100 000 сообщений на 1000 TCP-соединений,
короткие команды и переменные ответы до 64 КиБ. Генератор строит
настоящие Ethernet/IPv4/TCP-кадры протокола демонстрации
(``AA 55 | cmd | len(u16 LE) | payload``), поэтому замеры идут по тому же
коду, что работает на реальных записях.

Свойства:
  * детерминизм: одинаковый seed → одинаковые байты (sha256 стабилен);
  * потоковая запись: файл пишется по мере генерации, пиковая память
    не зависит от размера записи;
  * явный предел: при достижении max_bytes генерация останавливается
    и сообщает, что записано и почему остановлена (без тихого усечения).
"""

from __future__ import annotations

import random
import struct
from pathlib import Path
from typing import Iterator, Optional, Tuple

from .limits import MIB
from .synth import LINKTYPE_ETHERNET, tcp_packet

C_IP, S_IP = "192.168.1.10", "10.0.0.2"
S_PORT = 5000                       # устройство (сервер протокола)
BASE_C_PORT = 40000                 # клиентские порты: BASE + index сессии

MAGIC = b"\xAA\x55"


def _request(cmd: int, payload: bytes) -> bytes:
    return MAGIC + struct.pack("<BH", cmd, len(payload)) + payload


def _response(status: int, payload: bytes) -> bytes:
    return MAGIC + struct.pack("<BH", status, len(payload)) + payload


def generate_packets(sessions: int = 1000,
                     messages: int = 100_000,
                     answer_max: int = 64 * 1024,
                     seed: int = 1) -> Iterator[Tuple[float, bytes]]:
    """Поток кадров (ts, bytes): handshakes + короткие команды/ответы.

    messages — всего прикладных сообщений (запросы и ответы вместе);
    они распределяются по сессиям как последовательность запрос b2a →
    ответ a2b, то есть пар на сессию = messages / 2 / sessions. Ответы
    переменной длины: от 2 байт до answer_max по распределению,
    детерминированному seed.
    """
    rng = random.Random(seed)
    pairs_per_session = max(1, messages // 2 // max(1, sessions))
    t = 0.0
    for si in range(sessions):
        c_port = BASE_C_PORT + si
        seq_c, seq_s = 1000, 5000
        # рукопожатие
        yield t, tcp_packet(src_ip=C_IP, dst_ip=S_IP, sport=c_port,
                            dport=S_PORT, seq=seq_c, flags="S")
        t += 0.0005
        yield t, tcp_packet(src_ip=S_IP, dst_ip=C_IP, sport=S_PORT,
                            dport=c_port, seq=seq_s, flags="SA",
                            ack=seq_c + 1)
        t += 0.0005
        seq_c += 1
        yield t, tcp_packet(src_ip=C_IP, dst_ip=S_IP, sport=c_port,
                            dport=S_PORT, seq=seq_c, flags="A",
                            ack=seq_s + 1)
        seq_s += 1
        t += 0.0005
        for _mi in range(pairs_per_session):
            # короткая команда (2..18 байт payload)
            cmd = 1 + rng.randrange(3)
            req = _request(cmd, bytes(rng.randrange(256)
                                      for _ in range(rng.randrange(16))))
            yield t, tcp_packet(src_ip=C_IP, dst_ip=S_IP, sport=c_port,
                                dport=S_PORT, seq=seq_c, flags="A",
                                ack=seq_s, payload=req)
            seq_c += len(req)
            t += 0.0002
            # переменный ответ: чаще короткий, изредка до answer_max
            if rng.random() < 0.02:
                n = rng.randrange(min(1024, answer_max), answer_max + 1)
            else:
                n = rng.randrange(2, min(64, answer_max + 1))
            resp = _response(0, bytes(n))
            yield t, tcp_packet(src_ip=S_IP, dst_ip=C_IP, sport=S_PORT,
                                dport=c_port, seq=seq_s, flags="A",
                                ack=seq_c, payload=resp)
            seq_s += len(resp)
            t += 0.0002
        # завершение
        yield t, tcp_packet(src_ip=C_IP, dst_ip=S_IP, sport=c_port,
                            dport=S_PORT, seq=seq_c, flags="FA",
                            ack=seq_s)
        t += 0.0005
        yield t, tcp_packet(src_ip=S_IP, dst_ip=C_IP, sport=S_PORT,
                            dport=c_port, seq=seq_s, flags="FA",
                            ack=seq_c + 1)


def _pcapng_header() -> bytes:
    def block(btype: int, payload: bytes) -> bytes:
        pad = (-len(payload)) % 4
        payload += b"\x00" * pad
        total = 12 + len(payload)
        return (struct.pack("<II", btype, total) + payload
                + struct.pack("<I", total))
    return (block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
            + block(0x00000001, struct.pack("<HHI", LINKTYPE_ETHERNET, 0, 0)))


def _pcapng_epb(ts: float, data: bytes) -> bytes:
    ts_raw = int(round(ts * 1_000_000))
    cap = len(data)
    payload = struct.pack("<IIIII", 0, ts_raw >> 32, ts_raw & 0xFFFFFFFF,
                          cap, cap) + data
    pad = (-len(payload)) % 4
    payload += b"\x00" * pad
    total = 12 + len(payload)
    return (struct.pack("<II", 0x00000006, total) + payload
            + struct.pack("<I", total))


def generate_load(out: str | Path,
                  sessions: int = 1000,
                  messages: int = 100_000,
                  answer_max: int = 64 * 1024,
                  seed: int = 1,
                  max_bytes: int = 100 * MIB,
                  progress=None,
                  progress_every: int = 10_000) -> dict:
    """Сгенерировать нагрузочную запись PCAPNG потоково.

    Возвращает сводку: сколько пакетов/сессий/сообщений записано и
    почему остановлена (лимит байтов или исчерпание плана).
    """
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    packets = 0
    msgs = 0
    sessions_seen = 0
    header = _pcapng_header()
    reason = "план исчерпан"
    with open(out, "wb") as fh:
        fh.write(header)
        written = len(header)
        for ts, data in generate_packets(sessions, messages, answer_max,
                                         seed):
            block = _pcapng_epb(ts, data)
            if written + len(block) > max_bytes:
                reason = (f"предел max_bytes={max_bytes} "
                          f"({max_bytes // MIB} МиБ)")
                break
            fh.write(block)
            written += len(block)
            packets += 1
            if data[47:48] == b"\x02":               # TCP SYN — новая сессия
                sessions_seen += 1
            if len(data) > 54:                       # есть payload — сообщение
                msgs += 1
            if progress is not None and packets % max(1, progress_every) == 0:
                progress(packets, written)
    return {
        "path": str(out),
        "bytes": written,
        "packets": packets,
        "sessions": sessions_seen,
        "messages": msgs,
        "seed": seed,
        "stopped_because": reason,
    }
