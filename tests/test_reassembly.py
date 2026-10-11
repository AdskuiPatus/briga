"""Тесты восстановления TCP-потока: порядок, ретрансмиссии, пропуски,
перекрытия, разбиение сессий, midstream (R1 и таблица 7.3 кейса)."""

from __future__ import annotations

import random

from madrigal.synth import tcp_packet, write_pcap, write_pcapng

from madrigal.capture import open_capture
from madrigal.layers import parse_capture
from madrigal.reassembly import (
    DataRun,
    GapRun,
    UnknownDataError,
    build_stream,
)
from madrigal.sessions import build_sessions

C_IP, S_IP = "192.168.1.10", "10.0.0.2"
C_PORT, S_PORT = 40000, 5000


def _c(seq, flags="A", payload=b"", ack=1000, **kw):
    return tcp_packet(src_ip=C_IP, dst_ip=S_IP, sport=C_PORT, dport=S_PORT,
                      seq=seq, flags=flags, payload=payload, ack=ack, **kw)


def _s(seq, flags="A", payload=b"", ack=1001, **kw):
    return tcp_packet(src_ip=S_IP, dst_ip=C_IP, sport=S_PORT, dport=C_PORT,
                      seq=seq, flags=flags, payload=payload, ack=ack, **kw)


def _load(tmp_path, frames, fmt="pcap"):
    path = tmp_path / ("t.pcap" if fmt == "pcap" else "t.pcapng")
    writer = write_pcap if fmt == "pcap" else write_pcapng
    writer(path, frames)
    cap = open_capture(path)
    parsed = parse_capture(cap)
    ts = [p.timestamp for p in cap.packets]
    sessions = build_sessions(ts, parsed)
    return cap, parsed, ts, sessions


def _handshake():
    return [
        (0.0, _c(1000, flags="S")),
        (0.1, _s(5000, flags="SA", ack=1001)),
        (0.2, _c(1001, flags="A", ack=5001)),
    ]


def _stream(ts, parsed, sessions, idx=0, direction=None):
    """Направление по умолчанию — от клиента (C_IP:C_PORT) к устройству.

    Канонические endpoint'ы A/B — сортировка адрес+порт, роли не назначаются;
    конкретное направление запрашивается через Session.direction_of()."""
    if direction is None:
        direction = sessions[idx].direction_of((C_IP, C_PORT))
    return build_stream(ts, parsed, sessions[idx], direction)


# --------------------------------------------------- порядок и байты ----

def test_in_order_stream(tmp_path):
    frames = _handshake() + [
        (0.3, _c(1001, payload=b"AAA")),
        (0.4, _c(1004, payload=b"BBB")),
        (0.5, _c(1007, payload=b"CC")),
        (0.6, _c(1009, flags="FA", ack=5001)),
    ]
    cap, parsed, ts, sessions = _load(tmp_path, frames)
    assert len(sessions) == 1
    st = _stream(ts, parsed, sessions)
    assert st.to_bytes() == b"AAABBBCC"
    assert st.is_complete
    assert st.midstream is False
    assert st.data_length == 8


def test_out_of_order_packets_same_bytes(tmp_path):
    """Изменение порядка пакетов в записи не меняет прикладные байты."""
    frames = _handshake() + [
        (0.3, _c(1001, payload=b"AAA")),
        (0.4, _c(1004, payload=b"BBB")),
        (0.5, _c(1007, payload=b"CC")),
    ]
    expected = b"AAABBBCC"

    for seed in range(5):
        rnd = random.Random(seed)
        shuffled = frames[:]
        rnd.shuffle(shuffled)
        # метки времени не должны влиять на порядок байтов
        shuffled = [(i * 0.01, f) for i, (_, f) in enumerate(shuffled)]
        _, parsed, ts, sessions = _load(tmp_path, shuffled)
        st = _stream(ts, parsed, sessions)
        assert st.to_bytes() == expected, f"seed={seed}"


def test_retransmission_not_duplicated(tmp_path):
    """Одинаковая повторная передача не дублирует байты, пакеты сохраняются."""
    frames = _handshake() + [
        (0.3, _c(1001, payload=b"AAA")),
        (0.35, _c(1001, payload=b"AAA")),   # ретрансмиссия
        (0.4, _c(1004, payload=b"BBB")),
    ]
    cap, parsed, ts, sessions = _load(tmp_path, frames)
    assert len(cap.packets) == len(frames)          # исходные пакеты сохранены
    st = _stream(ts, parsed, sessions)
    assert st.to_bytes() == b"AAABBB"               # без дубликата
    assert len(st.retransmissions) == 1
    assert st.retransmissions[0].packet == 4        # pkt#4 — ретрансмиссия


# ------------------------------------------------------- пропуски ----

def test_gap_is_explicit_and_not_filled(tmp_path):
    frames = _handshake() + [
        (0.3, _c(1001, payload=b"AAA")),
        (0.5, _c(1007, payload=b"CC")),   # сегмент 1004..1007 потерян
    ]
    _, parsed, ts, sessions = _load(tmp_path, frames)
    st = _stream(ts, parsed, sessions)

    assert st.length == 8                     # 3 + gap 3 + 2
    assert st.data_length == 5
    assert len(st.gaps) == 1
    gap = st.gaps[0]
    assert (gap.start, gap.length) == (3, 3)

    # неизвестные байты недоступны и не подменяются
    assert st.at(3) is None and st.at(5) is None
    assert st.at(0) == ord("A") and st.at(6) == ord("C")
    try:
        st.to_bytes()
        raise AssertionError("to_bytes обязан отказать при пропусках")
    except UnknownDataError:
        pass
    assert "??" in st.hexdump()

    # срез явно разделяет известное и неизвестное
    res = st.slice(0, 8)
    assert res.is_complete is False
    assert [(o, b) for o, b in res.pieces] == [(0, b"AAA"), (6, b"CC")]
    assert [(g.start, g.length) for g in res.gaps] == [(3, 3)]


# ---------------------------------------------------- перекрытия ----

def test_conflicting_overlap_first_seen_policy(tmp_path):
    frames = _handshake() + [
        (0.3, _c(1001, payload=b"AAAA")),    # байты 1001..1005
        (0.4, _c(1003, payload=b"ZZZZ")),    # 1003..1007: конфликт 1003..1005
    ]
    _, parsed, ts, sessions = _load(tmp_path, frames)
    st = _stream(ts, parsed, sessions)

    # политика first-seen: остаются байты первого пакета, хвост — от второго
    assert st.to_bytes() == b"AAAAZZ"
    assert len(st.ambiguities) == 1
    amb = st.ambiguities[0]
    assert (amb.start, amb.end) == (2, 4)
    assert amb.kept_packet == 3 and amb.alt_packet == 4
    assert amb.alt_bytes == b"ZZ"
    # неоднозначность видна с привязкой к пакетам в выводе
    assert "неоднозначности" in st.hexdump()


def test_identical_overlap_counts_as_retransmission(tmp_path):
    frames = _handshake() + [
        (0.3, _c(1001, payload=b"ABCD")),
        (0.4, _c(1003, payload=b"CDEF")),    # перекрытие 'CD' == 'CD'
    ]
    _, parsed, ts, sessions = _load(tmp_path, frames)
    st = _stream(ts, parsed, sessions)
    assert st.to_bytes() == b"ABCDEF"
    assert st.ambiguities == []
    assert len(st.retransmissions) == 1
    assert st.retransmissions[0].length == 2


# --------------------------------------------------------- сессии ----

def test_port_reuse_does_not_merge_connections(tmp_path):
    frames = _handshake() + [
        (0.3, _c(1001, payload=b"FIRST")),
        (0.4, _c(1006, flags="FA", ack=5001)),
        (0.5, _s(5001, flags="FA", ack=1007)),
        # тот же 4-tuple, новое соединение
        (1.0, _c(9000, flags="S")),
        (1.1, _s(8000, flags="SA", ack=9001)),
        (1.2, _c(9001, payload=b"SECOND")),
    ]
    _, parsed, ts, sessions = _load(tmp_path, frames)
    assert len(sessions) == 2

    s0, s1 = sessions
    # канонические endpoint'ы: A — с меньшим ключом (ip, port); роли не назначаются
    assert s0.a == s1.a and s0.b == s1.b
    assert {s0.a, s0.b} == {(C_IP, C_PORT), (S_IP, S_PORT)}
    assert _stream(ts, parsed, sessions, 0).to_bytes() == b"FIRST"
    assert _stream(ts, parsed, sessions, 1).to_bytes() == b"SECOND"
    assert s0.closed and s0.fin_count == 2


def test_midstream_start_is_flagged(tmp_path):
    frames = [
        (0.1, _c(1001, payload=b"DATA")),   # запись началась без рукопожатия
        (0.2, _c(1005, payload=b"MORE")),
    ]
    _, parsed, ts, sessions = _load(tmp_path, frames)
    assert len(sessions) == 1
    s = sessions[0]
    assert s.midstream is True
    assert s.saw_syn is False

    st = _stream(ts, parsed, sessions)
    assert st.midstream is True
    assert st.to_bytes() == b"DATAMORE"
    assert any("midstream" in d for d in st.diagnostics)


def test_two_directions_are_separate(tmp_path):
    frames = _handshake() + [
        (0.3, _c(1001, payload=b"PING")),
        (0.4, _s(5001, payload=b"PONG")),
        (0.5, _c(1005, payload=b"BYE")),
    ]
    _, parsed, ts, sessions = _load(tmp_path, frames)
    to_server = sessions[0].direction_of((C_IP, C_PORT))
    to_client = sessions[0].direction_of((S_IP, S_PORT))
    assert _stream(ts, parsed, sessions, 0, to_server).to_bytes() == b"PINGBYE"
    assert _stream(ts, parsed, sessions, 0, to_client).to_bytes() == b"PONG"


def test_stream_from_pcapng_matches_pcap(tmp_path):
    frames = _handshake() + [(0.3, _c(1001, payload=b"SAME"))]
    outs = []
    for fmt in ("pcap", "pcapng"):
        _, parsed, ts, sessions = _load(tmp_path, frames, fmt=fmt)
        outs.append(_stream(ts, parsed, sessions).to_bytes())
    assert outs[0] == outs[1] == b"SAME"


def test_provenance_points_to_source_packets(tmp_path):
    frames = _handshake() + [
        (0.3, _c(1001, payload=b"AAA")),
        (0.4, _c(1004, payload=b"BBB")),
    ]
    _, parsed, ts, sessions = _load(tmp_path, frames)
    st = _stream(ts, parsed, sessions)
    # байты 0..3 — из pkt#3, байты 3..6 — из pkt#4
    assert st.packets_for(0, 3) == [3]
    assert st.packets_for(3, 3) == [4]
    # исходные байты доступны для сверки
    assert st.slice(3, 3).pieces == [(3, b"BBB")]
