"""Генерация демонстрационных записей (синтетический «стенд»).

Формат обмена вымышленный (чтобы исследование имело смысл):
  запрос:  AA 55 | cmd(1) | len(2 LE) | payload
  ответ:   AA 55 | status(1) | len(2 LE) | payload
  cmd 0x01 — чтение параметров, 0x02 — установка значения (u16 LE),
  0x03 — получение измерений (переменный размер ответа).

Создаёт:
  examples/demo.pcapng              — полное соединение: рукопожатия, обмен,
                                      сообщение, разорванное на два TCP-сегмента,
                                      ретрансмиссия, FIN/FIN;
  examples/demo_defect.pcapng       — дефекты захвата: начало без рукопожатия,
                                      потерянный сегмент и различающиеся данные
                                      в перекрытии (намеренный артефакт);
  examples/demo_counterexample.pcapng — контрпример для R4: установка 21,
                                      ответ содержит 99 — гипотеза h-echo
                                      должна быть опровергнута данными.
"""

from __future__ import annotations

import struct
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from madrigal.synth import tcp_packet, write_pcapng  # noqa: E402

C_IP, C_PORT = "192.168.1.10", 40000
S_IP, S_PORT = "10.0.0.2", 5000

MAGIC = b"\xAA\x55"


def request(cmd: int, payload: bytes = b"") -> bytes:
    return MAGIC + bytes([cmd]) + struct.pack("<H", len(payload)) + payload


def response(payload: bytes, status: int = 0) -> bytes:
    return MAGIC + bytes([status]) + struct.pack("<H", len(payload)) + payload


class Pcap:
    def __init__(self, t0: float = 1_700_000_000.0):
        self.t = t0
        self.frames: list[tuple[float, bytes]] = []

    def _add(self, frame: bytes) -> None:
        self.frames.append((self.t, frame))
        self.t += 0.05

    def c(self, seq: int, payload: bytes = b"", flags: str = "A", ack: int = 1001):
        self._add(tcp_packet(src_ip=C_IP, dst_ip=S_IP, sport=C_PORT, dport=S_PORT,
                             seq=seq, ack=ack, flags=flags, payload=payload))

    def s(self, seq: int, payload: bytes = b"", flags: str = "A", ack: int = 1001):
        self._add(tcp_packet(src_ip=S_IP, dst_ip=C_IP, sport=S_PORT, dport=C_PORT,
                             seq=seq, ack=ack, flags=flags, payload=payload))


def build_demo() -> list[tuple[float, bytes]]:
    """Полное соединение со всеми особенностями (см. докстринг)."""
    p = Pcap()
    # рукопожатие
    p.c(1000, flags="S")
    p.s(5000, flags="SA", ack=1001)
    p.c(1001, flags="A", ack=5001)

    c_seq, s_seq = 1001, 5001  # next seq обеих сторон

    def client_msg(msg: bytes, retransmit: bool = False) -> None:
        nonlocal c_seq
        p.c(c_seq, msg, ack=s_seq)
        if retransmit:
            p.c(c_seq, msg, ack=s_seq)   # повторная передача
        c_seq += len(msg)

    def device_msg(msg: bytes, split_at: int | None = None) -> None:
        nonlocal s_seq
        if split_at is None:
            p.s(s_seq, msg, ack=c_seq)
            s_seq += len(msg)
        else:
            # одно сообщение, разорванное на два TCP-сегмента
            p.s(s_seq, msg[:split_at], ack=c_seq)
            s_seq += len(msg[:split_at])
            p.s(s_seq, msg[split_at:], ack=c_seq)
            s_seq += len(msg[split_at:])

    # 1) чтение параметров
    client_msg(request(0x01))
    device_msg(response(b"\x10\x20\x30\x40"))

    # 2) установка значения 21 (другое действие — другой параметр)
    client_msg(request(0x02, struct.pack("<H", 21)))
    device_msg(response(struct.pack("<H", 21)))

    # 3) установка значения 37 + ретрансмиссия запроса
    client_msg(request(0x02, struct.pack("<H", 37)), retransmit=True)
    device_msg(response(struct.pack("<H", 37)))

    # 4) измерение малого размера (64 Б)
    client_msg(request(0x03, b"\x01"))
    device_msg(response(bytes(range(64))))

    # 5) измерение большого размера (4000 Б), разорванное на два сегмента
    client_msg(request(0x03, b"\x02"))
    device_msg(response(bytes((i * 7) % 256 for i in range(4000))), split_at=1460)

    # закрытие
    p.c(c_seq, flags="FA", ack=s_seq)
    p.s(s_seq, flags="FA", ack=c_seq + 1)
    return p.frames


def build_defects() -> list[tuple[float, bytes]]:
    """Дефекты захвата: начало без рукопожатия, потерянный сегмент,
    различающиеся данные в перекрытии (намеренный артефакт)."""
    p = Pcap(t0=1_700_000_100.0)
    # соединение начинается в середине — рукопожатие не записано
    p.s(9000, response(bytes(range(32))), ack=7007)   # 37 Б: 9000..9037
    p.c(7000, request(0x02, struct.pack("<H", 55)), ack=9037)  # 7 Б: 7000..7007

    msg = response(bytes(range(100)))                 # 105 Б
    p.s(9037, msg[:40], ack=7007)                     # 9037..9077
    # сегмент 9077..9117 потерян при захвате — в файл не попадает
    p.s(9117, msg[80:], ack=7007)                     # 9117..9142
    # артефакт захвата: сегмент с тем же seq 9037, но другими байтами —
    # даёт проверку отображения неоднозначности (политика first-seen)
    p.s(9037, b"\xFF" * 8, ack=7007)
    return p.frames


def build_counterexample() -> list[tuple[float, bytes]]:
    """Контрпример для проверки гипотез (R4).

    Обмен тем же протоколом, но устройство на установку 21 отвечает 99:
    механическая проверка h-echo обязана это увидеть и опровергнуть
    гипотезу с привязкой к пакетам, а не «подтвердить» её.
    """
    p = Pcap(t0=1_700_000_200.0)
    p.c(1000, flags="S")
    p.s(5000, flags="SA", ack=1001)
    p.c(1001, flags="A", ack=5001)
    c_seq, s_seq = 1001, 5001

    # 1) установка 21 → ответ с ЧУЖИМ значением 99 (нарушение)
    p.c(c_seq, request(0x02, struct.pack("<H", 21)), ack=s_seq)
    c_seq += 7
    p.s(s_seq, response(struct.pack("<H", 99)), ack=c_seq)
    s_seq += 7

    # 2) установка 37 → ответ корректный (вторая пара проходит)
    p.c(c_seq, request(0x02, struct.pack("<H", 37)), ack=s_seq)
    c_seq += 7
    p.s(s_seq, response(struct.pack("<H", 37)), ack=c_seq)
    s_seq += 7

    p.c(c_seq, flags="FA", ack=s_seq)
    p.s(s_seq, flags="FA", ack=c_seq + 1)
    return p.frames


def main() -> None:
    out_dir = Path(__file__).resolve().parent
    demo = out_dir / "demo.pcapng"
    defects = out_dir / "demo_defect.pcapng"
    counter = out_dir / "demo_counterexample.pcapng"
    write_pcapng(demo, build_demo())
    write_pcapng(defects, build_defects())
    write_pcapng(counter, build_counterexample())
    print(f"создано: {demo}")
    print(f"создано: {defects}")
    print(f"создано: {counter}")


if __name__ == "__main__":
    main()
