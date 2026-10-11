"""Тесты чтения PCAP/PCAPNG и разбора пакетов."""

from __future__ import annotations

import struct

import pytest

from madrigal.synth import tcp_packet, write_pcap, write_pcapng

from madrigal.capture import CaptureError, UnsupportedCapture, open_capture
from madrigal.layers import parse_capture, parse_packet


def _frames():
    return [
        (1_700_000_000.25, tcp_packet(seq=1000, flags="S")),
        (1_700_000_000.30, tcp_packet(seq=2000, flags="SA", ack=1001)),
        (1_700_000_000.35, tcp_packet(seq=1001, flags="A", payload=b"HELLO")),
    ]


# ------------------------------------------------------------ форматы ----

def test_pcap_roundtrip(tmp_path):
    path = tmp_path / "t.pcap"
    src = _frames()
    write_pcap(path, src)
    cap = open_capture(path)
    assert cap.fmt == "pcap"
    assert len(cap.packets) == 3
    for (ts, data), pkt in zip(src, cap.packets):
        assert pkt.data == data
        assert abs(pkt.timestamp - ts) < 1e-5
        assert pkt.linktype == 1
        assert not pkt.truncated
    assert len(cap.sha256) == 64


def test_pcapng_roundtrip(tmp_path):
    path = tmp_path / "t.pcapng"
    src = _frames()
    write_pcapng(path, src)
    cap = open_capture(path)
    assert cap.fmt == "pcapng"
    assert len(cap.packets) == 3
    for (ts, data), pkt in zip(src, cap.packets):
        assert pkt.data == data
        assert abs(pkt.timestamp - ts) < 1e-5
    assert cap.notes == []


def test_pcap_and_pcapng_contain_same_packets(tmp_path):
    a, b = tmp_path / "t.pcap", tmp_path / "t.pcapng"
    src = _frames()
    write_pcap(a, src)
    write_pcapng(b, src)
    ca, cb = open_capture(a), open_capture(b)
    assert [p.data for p in ca.packets] == [p.data for p in cb.packets]


def test_pcap_nanos(tmp_path):
    path = tmp_path / "t.pcap"
    write_pcap(path, _frames())
    raw = bytearray(path.read_bytes())
    raw[0:4] = struct.pack("<I", 0xA1B23C4D)  # nsec magic
    path.write_bytes(bytes(raw))
    cap = open_capture(path)
    assert len(cap.packets) == 3


def test_bad_magic_diagnosed(tmp_path):
    path = tmp_path / "bad.pcap"
    path.write_bytes(b"NOTA" + b"\x00" * 40)
    with pytest.raises((UnsupportedCapture, CaptureError)):
        open_capture(path)


def test_missing_file(tmp_path):
    with pytest.raises(CaptureError):
        open_capture(tmp_path / "nope.pcap")


# ----------------------------------------------------------- разбор ----

def test_parse_tcp_flags_and_payload():
    frame = tcp_packet(sport=40000, dport=6000, seq=12345, ack=999,
                       flags="SA", payload=b"ABC")
    p = parse_packet(frame, linktype=1, index=7)
    assert p.error is None
    assert p.tcp is not None
    assert (p.tcp.src_port, p.tcp.dst_port) == (40000, 6000)
    assert p.tcp.seq == 12345 and p.tcp.ack == 999
    assert p.tcp.syn and p.tcp.ack_flag
    assert p.payload == b"ABC"
    assert p.ip4.src == "192.168.1.10" and p.ip4.dst == "10.0.0.2"


def test_parse_vlan_tagged_frame():
    frame = tcp_packet(payload=b"X")
    tagged = frame[:12] + struct.pack("!HHH", 0x8100, 100, 0x0800) + frame[14:]
    p = parse_packet(tagged, linktype=1)
    assert p.error is None
    assert p.ethernet.vlan_ids == [100]
    assert p.payload == b"X"


def test_parse_truncated_frame():
    p = parse_packet(b"\x00" * 10, linktype=1)
    assert p.error is not None
    assert p.tcp is None


def test_unsupported_linktype():
    p = parse_packet(tcp_packet(), linktype=101)
    assert p.error is not None
    assert "101" in p.error


def test_non_tcp_protocol_diagnosed():
    frame = tcp_packet()
    ip_start = 14
    mutated = bytearray(frame)
    mutated[ip_start + 9] = 17  # UDP вместо TCP
    p = parse_packet(bytes(mutated), linktype=1)
    assert p.error is not None
    assert "не TCP" in p.error


def test_parse_capture_counts(tmp_path):
    path = tmp_path / "t.pcapng"
    write_pcapng(path, _frames())
    cap = open_capture(path)
    parsed = parse_capture(cap)
    assert len(parsed) == len(cap.packets)
    assert all(p.ok for p in parsed)
