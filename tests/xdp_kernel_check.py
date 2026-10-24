"""Driven by tests/xdp_kernel_test.sh (root, Linux). Not collected by pytest."""
import subprocess
import sys

sys.path.insert(0, "controlplane")

from shieldwall.bpf_dataplane import BPFDataPlane, _bpftool, _sum_percpu  # noqa: E402
from shieldwall.classifier import Classifier  # noqa: E402
from shieldwall.models import UDP, Rule  # noqa: E402
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

    dp.set_enforce(False)  # dry-run: count hits, drop nothing
    before = stats()
    send(1000, 389, 40000, 500, 1200, "45.20")
    after = stats()
    print(f"dry-run       : dropped {after['dropped'] - before['dropped']} (should be 0)")
    assert after["dropped"] == before["dropped"]

    dp.detach()
    print("KERNEL TEST PASSED")


if __name__ == "__main__":
    main()
