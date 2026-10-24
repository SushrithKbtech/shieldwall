"""Replay CIC-DDoS2019 flow records (the CSV release) through the engine.

The CSV release has no packets, only CICFlowMeter flow rows: source/destination
address and port, protocol, start time, duration, forward packet count, mean packet
length, flag counts and a label. We rebuild a packet stream from them: each attack
flow's forward packets are spread evenly over its duration with its real addresses,
ports, protocol and size. Packet spacing inside a flow is the only approximation.

Reads straight out of the dataset zip, so nothing is unpacked to disk.

    shieldwall replay-cic archive.zip --member 01-12/DrDoS_NTP.csv
"""
from __future__ import annotations

import collections
import csv
import io
import os
import zipfile
from datetime import datetime

from .models import AMP_PORTS, ip_int
from .pcap import ParsedPacket

MAX_PACKETS = 300_000


def _rows(path: str, member: str | None):
    if path.lower().endswith(".zip"):
        z = zipfile.ZipFile(path)
        raw = z.open(member)
    else:
        raw = open(path, "rb")
    with raw:
        r = csv.reader(io.TextIOWrapper(raw, encoding="utf-8", errors="replace"))
        hdr = [h.strip() for h in next(r)]
        ix = {h: i for i, h in enumerate(hdr)}
        for row in r:
            if len(row) == len(hdr):
                yield ix, row


def _ts(s: str) -> float:
    return datetime.strptime(s[:26], "%Y-%m-%d %H:%M:%S.%f").timestamp() if "." in s else \
        datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S").timestamp()


def load_cic(path: str, member: str | None = None, seconds: int = 30) -> tuple[list[ParsedPacket], float, dict]:
    if not os.path.exists(path):
        raise SystemExit(f"{path}: not found")
    """Pass 1: per-second attack packet totals for the victim. Pass 2: rebuild the busiest `seconds`."""
    per_sec: collections.Counter = collections.Counter()
    dsts: collections.Counter = collections.Counter()
    for ix, row in _rows(path, member):
        if row[ix["Label"]] == "BENIGN":
            continue
        dsts[row[ix["Destination IP"]]] += 1
        per_sec[(row[ix["Destination IP"]], int(_ts(row[ix["Timestamp"]])))] += float(row[ix["Total Fwd Packets"]] or 0)
    victim = dsts.most_common(1)[0][0]
    secs = {s: n for (d, s), n in per_sec.items() if d == victim}
    start = max(secs, key=lambda s0: sum(secs.get(s0 + i, 0) for i in range(seconds)))
    end = start + seconds
    total_pkts = sum(secs.get(start + i, 0) for i in range(seconds))
    keep = min(1.0, MAX_PACKETS / total_pkts) if total_pkts else 1.0

    pkts: list[ParsedPacket] = []
    flows = srcs = 0
    src_set, sports = set(), collections.Counter()
    carry = 0.0
    for ix, row in _rows(path, member):
        if row[ix["Label"]] == "BENIGN" or row[ix["Destination IP"]] != victim:
            continue
        t0 = _ts(row[ix["Timestamp"]])
        if not start <= t0 < end:
            continue
        n = int(float(row[ix["Total Fwd Packets"]] or 0))
        if n <= 0:
            continue
        flows += 1
        dur = float(row[ix["Flow Duration"]] or 0) / 1e6
        proto = int(row[ix["Protocol"]])
        src = ip_int(row[ix["Source IP"]])
        sport, dport = int(row[ix["Source Port"]]), int(row[ix["Destination Port"]])
        size = max(60, int(float(row[ix["Fwd Packet Length Mean"]] or 0)) + (40 if proto == 6 else 28))
        syn = int(float(row[ix["SYN Flag Count"]] or 0))
        ack = int(float(row[ix["ACK Flag Count"]] or 0))
        src_set.add(src)
        sports[sport] += n
        carry += n * keep  # proportional thinning keeps every flow's share of the traffic
        emit, carry = int(carry), carry - int(carry)
        for i in range(emit):
            flags = 0
            if proto == 6:
                flags = 0x02 if (i < syn or not ack) else 0x10
            pkts.append(ParsedPacket(t0 + dur * i / max(emit, 1), src, ip_int(victim), proto, sport, dport, flags, size))
    pkts.sort(key=lambda p: p.ts)
    summary = {
        "file": f"{os.path.basename(path)}:{member}" if member else os.path.basename(path),
        "victim": victim,
        "window": f"busiest {seconds} s, starting {datetime.fromtimestamp(start):%Y-%m-%d %H:%M:%S}",
        "flows": flows,
        "packets": int(total_pkts),
        "seconds": seconds,
        "native_pps": round(total_pkts / seconds),
        "unique_sources": len(src_set),
        "udp_share": round(sum(p.proto == 17 for p in pkts) / max(1, len(pkts)), 3),
        "syn_share": round(sum(p.proto == 6 and p.flags == 0x02 for p in pkts) / max(1, len(pkts)), 3),
        "fragment_share": 0.0,
        "top_source_ports": [{"port": p, "service": AMP_PORTS.get(p), "share": round(c / max(1, total_pkts), 3)}
                             for p, c in sports.most_common(4)],
    }
    return pkts, total_pkts / seconds, summary  # true packet rate, restored after thinning
