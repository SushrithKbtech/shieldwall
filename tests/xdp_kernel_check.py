"""Driven by tests/xdp_kernel_test.sh (root, Linux). Not collected by pytest."""
import json
import platform
import subprocess
import sys

sys.path.insert(0, "controlplane")

from shieldwall.bpf_dataplane import BPFDataPlane, _bpftool, _sum_percpu  # noqa: E402
from shieldwall.classifier import Classifier  # noqa: E402
from shieldwall.models import UDP, Rule, ip_int  # noqa: E402
from shieldwall.sketches import BloomFilter  # noqa: E402

MAC = open("/sys/class/net/sw0/address").read().strip()


def send(n: int, sport: int, dport: int, sources: int, size: int, prefix: str) -> None:
    """Send n UDP packets into sw0 from the attacker namespace, spread over `sources` addresses."""
    code = (
        "from scapy.all import Ether, IP, UDP, Raw, sendp\n"
        f"def src(i): j = i % {sources}; return '{prefix}.%d.%d' % (j // 250, j % 250 + 1)\n"
        f"pk = [Ether(dst='{MAC}') / IP(src=src(i), dst='192.168.77.1') / UDP(sport={sport}, dport={dport})"
        f" / Raw(b'x' * {size}) for i in range({n})]\n"
        "sendp(pk, iface='sw1', verbose=False)\n"
    )
    subprocess.run(["ip", "netns", "exec", "swatk", "python3", "-c", code], check=True)


def send_raw(code_body: str) -> None:
    code = "from scapy.all import Ether, IP, TCP, UDP, Raw, sendp\n" + code_body + "\nsendp(pk, iface='sw1', verbose=False)\n"
    subprocess.run(["ip", "netns", "exec", "swatk", "python3", "-c", code], check=True)


def stats() -> dict:
    return _sum_percpu((_bpftool("map", "dump", "name", "stats") or [{}])[0])


def main() -> None:
    dp = BPFDataPlane("sw0", "bpf/xdp_filter.o")
    dp.attach(enforce=True)
    seen = BloomFilter(10_000)
    dp.read_features(seen)  # zero the deltas

    send(400, 50000, 19132, 20, 200, "49.10")  # normal players
    f, _ = dp.read_features(seen)
    print(f"normal window : {f.pps:.0f} pkts, amp share {f.amp_share:.0%}, {f.unique_sources} sources")
    assert f.pps >= 400 and f.amp_share == 0

    send(3000, 389, 40000, 500, 1200, "45.20")  # CLDAP reflection flood from 500 reflectors
    f, _ = dp.read_features(seen)
    c = Classifier().classify(f)
    print(f"attack window : {f.pps:.0f} pkts, amp share {f.amp_share:.0%} from port {f.amp_port}, "
          f"~{f.unique_sources} sources -> {c.label}")
    assert f.amp_port == 389 and f.amp_share > 0.8 and c.kind == "cldap_amplification"
    assert 400 <= f.unique_sources <= 600

    dp.sync_rules([Rule(1, "drop", UDP, sport=389)], ttl_s=60)
    before = stats()
    send(3000, 389, 40000, 500, 1200, "45.20")
    send(400, 50000, 19132, 20, 200, "49.10")
    after = stats()
    dropped = after["dropped"] - before["dropped"]
    passed = (after["pkts"] - before["pkts"]) - dropped
    hits = sum(int(e.get("formatted", e)["value"]["hits"]) for e in _bpftool("map", "dump", "name", "rules"))
    print(f"with rule     : kernel dropped {dropped} attack pkts, passed {passed} player pkts, rule hits {hits}")
    assert dropped >= 3000 and passed >= 400 and passed < 500
    result = {"kernel": platform.release(), "attack_sent": 3000, "attack_dropped": dropped,
              "player_sent": 400, "player_passed": passed, "rule_hits": hits,
              "sources_true": 500, "sources_estimated": f.unique_sources, "classified_as": c.label}

    # IP fragments of oversized replies carry no ports: only the fragment rule can catch them
    dp.sync_rules([Rule(1, "drop", UDP, sport=389), Rule(2, "drop", UDP, frag_only=True, untrusted_only=True)], ttl_s=60)
    before = stats()
    send_raw(f"pk = [Ether(dst='{MAC}') / IP(src='45.20.0.%d' % (i % 200 + 1), dst='192.168.77.1', proto=17, frag=185)"
             " / Raw(b'x' * 600) for i in range(1000)]")
    after = stats()
    frag_dropped = after["dropped"] - before["dropped"]
    print(f"fragments     : kernel saw {after['frag'] - before['frag']} fragments, dropped {frag_dropped}")
    assert frag_dropped >= 1000
    result["fragments_sent"], result["fragments_dropped"] = 1000, frag_dropped

    # heavy hitter: one host flooding TCP SYNs goes into the blocklist; everyone else still passes
    dp.sync_rules([Rule(3, "drop", 0, src=ip_int("45.30.0.9"), src_mask=0xFFFFFFFF)], ttl_s=60)
    before = stats()
    send_raw(f"pk = [Ether(dst='{MAC}') / IP(src='45.30.0.9', dst='192.168.77.1') / TCP(sport=40000 + i % 1000, dport=25565, flags='S') for i in range(2000)]"
             f" + [Ether(dst='{MAC}') / IP(src='49.10.0.%d' % (i % 20 + 1), dst='192.168.77.1') / UDP(sport=50000, dport=19132) / Raw(b'x' * 200) for i in range(300)]")
    after = stats()
    hh_dropped = after["dropped"] - before["dropped"]
    hh_passed = (after["pkts"] - before["pkts"]) - hh_dropped
    print(f"heavy hitter  : blocklist dropped {hh_dropped} packets from 45.30.0.9, passed {hh_passed} others")
    assert hh_dropped >= 2000 and hh_passed >= 300
    result.update(heavy_hitter_sent=2000, heavy_hitter_dropped=hh_dropped, others_passed=hh_passed)

    dp.set_enforce(False)  # dry-run: count hits, drop nothing
    before = stats()
    send(1000, 389, 40000, 500, 1200, "45.20")
    after = stats()
    print(f"dry-run       : dropped {after['dropped'] - before['dropped']} (should be 0)")
    assert after["dropped"] == before["dropped"]

    dp.detach()
    result["dry_run_dropped"] = after["dropped"] - before["dropped"]
    with open("results/kernel_test.json", "w") as fh:
        json.dump(result, fh, indent=2)
    print("KERNEL TEST PASSED")


if __name__ == "__main__":
    main()
