import os
import struct

from shieldwall.pcap import read_packets
from shieldwall.replay import load_capture, run_once, score

os.environ.setdefault("SHIELDWALL_LLM", "template")
VICTIM = bytes([10, 10, 10, 10])


def udp_frame(src: int, sport: int, dport: int, payload: int, frag_offset: int = 0) -> bytes:
    ip_len = 20 + (8 if frag_offset == 0 else 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ip_len, 1, frag_offset, 64, 17, 0, struct.pack("!I", src), VICTIM)
    l4 = struct.pack("!HHHH", sport, dport, 8 + payload, 0) if frag_offset == 0 else b""
    return b"\x00" * 12 + b"\x08\x00" + ip + l4 + b"x" * payload


def write_pcap(path, frames):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, frame in enumerate(frames):
            ts = i * 0.0001  # 10k packets per second
            f.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)) + frame)


def test_reader_parses_ports_and_fragments(tmp_path):
    p = tmp_path / "t.pcap"
    write_pcap(p, [udp_frame(0x2D000001, 389, 4444, 100), udp_frame(0x2D000002, 0, 0, 100, frag_offset=185)])
    a, b = list(read_packets(str(p)))
    assert (a.sport, a.dport, a.frag) == (389, 4444, False)
    assert b.frag and b.sport == 0


def test_replayed_real_style_cldap_capture_is_caught_and_blocked(tmp_path):
    p = tmp_path / "cldap.pcap"
    frames = []
    for i in range(3000):
        src = 0x2D000000 + (i % 400)
        frames.append(udp_frame(src, 389, 40000 + i % 100, 1200) if i % 5 else udp_frame(src, 0, 0, 600, frag_offset=185))
    write_pcap(p, frames)
    pkts, summary = load_capture(str(p))
    assert summary["victim"] == "10.10.10.10" and 0.15 < summary["fragment_share"] < 0.25
    eng, pts = run_once(pkts, True, attack_at=35, duration=20, tail=10, scale=1.0)
    s = score(pts, 35, 20)
    assert s["detect_s"] is not None and s["detect_s"] <= 3
    assert s["attack_dropped_after_block_pct"] > 99  # signature rule + fragment rule
    assert s["window"]["precision"] == 1.0
    assert any("fragments" in r.describe() for r in eng.controller.rules.values())


def test_single_host_flood_is_blocked_by_heavy_hitter_rule():
    # the CIC-DDoS2019 shape: one never-seen machine, plain TCP ACK packets, no attack fingerprint
    from shieldwall.pcap import ParsedPacket

    attacker = 0xAC100005  # 172.16.0.5
    pkts = [ParsedPacket(i / 40_000, attacker, 0xC0A83201, 6, 1024 + i % 60000, 80, 0x10, 60) for i in range(40_000)]
    eng, pts = run_once(pkts, True, attack_at=35, duration=20, tail=10, scale=1.0)
    s = score(pts, 35, 20)
    assert s["detect_s"] is not None and s["detect_s"] <= 3
    assert s["attack_dropped_after_block_pct"] > 99
    assert s["legit_dropped_pct"] < 0.1
    assert any(r.src == attacker for r in eng.controller.rules.values())
