"""Minimal streaming pcap / pcapng reader: no dependencies, constant memory.

Yields one ParsedPacket per IPv4 packet (timestamp, addresses, ports, TCP flags,
length). Everything else (IPv6, ARP, ...) is skipped, matching what the XDP
program inspects.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import BinaryIO, Iterator

ETH, RAW_IP, LINUX_SLL, RAW_IP4 = 1, 101, 113, 228


@dataclass(slots=True)
class ParsedPacket:
    ts: float
    src: int
    dst: int
    proto: int
    sport: int
    dport: int
    flags: int
    size: int
    frag: bool = False  # non-first fragment: no transport header, so no ports


def _ipv4(buf: bytes, off: int, ts: float, wire_len: int) -> ParsedPacket | None:
    if len(buf) < off + 20 or buf[off] >> 4 != 4:
        return None
    ihl = (buf[off] & 0x0F) * 4
    total = struct.unpack_from("!H", buf, off + 2)[0]
    frag = struct.unpack_from("!H", buf, off + 6)[0] & 0x1FFF
    proto = buf[off + 9]
    src, dst = struct.unpack_from("!II", buf, off + 12)
    sport = dport = flags = 0
    l4 = off + ihl
    if frag == 0 and proto in (6, 17) and len(buf) >= l4 + 4:
        sport, dport = struct.unpack_from("!HH", buf, l4)
        if proto == 6 and len(buf) >= l4 + 14:
            flags = buf[l4 + 13]
    return ParsedPacket(ts, src, dst, proto, sport, dport, flags, max(total, wire_len - off), frag != 0)


def _link(buf: bytes, linktype: int, ts: float, wire_len: int) -> ParsedPacket | None:
    if linktype == ETH:
        if len(buf) < 14:
            return None
        off, etype = 14, struct.unpack_from("!H", buf, 12)[0]
        while etype in (0x8100, 0x88A8) and len(buf) >= off + 4:  # VLAN tags
            etype = struct.unpack_from("!H", buf, off + 2)[0]
            off += 4
        return _ipv4(buf, off, ts, wire_len) if etype == 0x0800 else None
    if linktype == LINUX_SLL:
        if len(buf) < 16 or struct.unpack_from("!H", buf, 14)[0] != 0x0800:
            return None
        return _ipv4(buf, 16, ts, wire_len)
    if linktype in (RAW_IP, RAW_IP4):
        return _ipv4(buf, 0, ts, wire_len)
    return None


def _classic(f: BinaryIO, magic: bytes) -> Iterator[ParsedPacket]:
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
    nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
    hdr = f.read(20)
    linktype = struct.unpack(endian + "HHiIII", hdr)[5] & 0xFFFF
    div = 1e9 if nano else 1e6
    while True:
        rec = f.read(16)
        if len(rec) < 16:
            return
        sec, frac, incl, orig = struct.unpack(endian + "IIII", rec)
        data = f.read(incl)
        p = _link(data, linktype, sec + frac / div, orig)
        if p:
            yield p


def _pcapng(f: BinaryIO, first: bytes) -> Iterator[ParsedPacket]:
    endian = "<"
    links: list[tuple[int, float]] = []  # (linktype, seconds per timestamp unit) per interface
    block = first
    while True:
        if len(block) < 8:
            return
        btype, blen = struct.unpack(endian + "II", block[:8])
        if btype == 0x0A0D0D0A:  # section header: sets byte order
            bom = f.read(4)
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack(endian + "I", block[4:8])[0]
            body = bom + f.read(blen - 12)
            links = []
        else:
            body = f.read(blen - 8)
        if btype == 1 and len(body) >= 8:  # interface description
            linktype = struct.unpack(endian + "H", body[:2])[0]
            unit = 1e-6
            opts, i = body[8:-4], 0
            while i + 4 <= len(opts):
                code, olen = struct.unpack(endian + "HH", opts[i:i + 4])
                if code == 0:
                    break
                if code == 9 and olen >= 1:  # if_tsresol
                    v = opts[i + 4]
                    unit = 2.0 ** -(v & 0x7F) if v & 0x80 else 10.0 ** -v
                i += 4 + olen + (-olen % 4)
            links.append((linktype, unit))
        elif btype == 6 and len(body) >= 20:  # enhanced packet
            iface, hi, lo, incl, orig = struct.unpack(endian + "IIIII", body[:20])
            linktype, unit = links[iface] if iface < len(links) else (ETH, 1e-6)
            p = _link(body[20:20 + incl], linktype, ((hi << 32) | lo) * unit, orig)
            if p:
                yield p
        elif btype == 3 and len(body) >= 4:  # simple packet
            orig = struct.unpack(endian + "I", body[:4])[0]
            linktype = links[0][0] if links else ETH
            p = _link(body[4:4 + orig], linktype, 0.0, orig)
            if p:
                yield p
        block = f.read(8)


def read_packets(path: str) -> Iterator[ParsedPacket]:
    with open(path, "rb") as f:
        magic = f.read(4)
        if magic == b"\x0a\x0d\x0d\x0a":
            yield from _pcapng(f, magic + f.read(4))
        elif magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            yield from _classic(f, magic)
        else:
            raise ValueError(f"{path}: not a pcap or pcapng file")
