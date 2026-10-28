"""Replay a REAL attack capture through the REAL XDP program. Driven by tests/xdp_replay_test.sh.

1. Modelled players (20 addresses, ~300 pps) run throughout so the detector learns a baseline.
2. The real capture, rewritten to the test server's address, is looped into the XDP program.
   The live control loop (read kernel maps -> detect -> classify -> write rules) runs once a
   second, exactly as `shieldwall live` does. We record when it detects and blocks.
3. With the rules in place, the whole capture is sent once more as a controlled pass, then a
   batch of player packets, so drops can be counted exactly from the kernel's counters.

With `analyst` as a second argument the ML tier is forced to be unsure, so the anomaly goes to
the Tier 3 analyst on the live path: it works from packets sampled off the interface, and its
rule must pass the controller's checks and stays in dry-run. This tests that plumbing; it is
not a claim about how often the model is unsure.
"""
import json
import os
import platform
import subprocess
import sys
import time

sys.path.insert(0, "controlplane")

from shieldwall.bpf_dataplane import BPFDataPlane, LiveLoop, PacketSampler, _bpftool, _sum_percpu  # noqa: E402
from shieldwall.mitigation import MitigationConfig  # noqa: E402
from shieldwall.ml import MLVerdict  # noqa: E402

CAPTURE = sys.argv[1]
FORCE_ANALYST = len(sys.argv) > 2 and sys.argv[2] == "analyst"
MAC = open("/sys/class/net/sw0/address").read().strip()
BASELINE_S, ATTACK_S = 20, 12

PLAYER_PKTS = f"""
from scapy.all import Ether, IP, TCP, UDP, Raw
pk = [Ether(dst='{MAC}') / IP(src='49.10.0.%d' % (i % 20 + 1), dst='192.168.77.1') /
      (UDP(sport=50000 + i % 20, dport=19132) if i % 2 else TCP(sport=40000 + i % 20, dport=25565, flags='A')) /
      Raw(b'x' * 120) for i in range(300)]
raw = [bytes(p) for p in pk]
"""

CAPTURE_PKTS = f"""
from scapy.all import rdpcap, Ether, IP, UDP, TCP
raw = []
for p in rdpcap('{CAPTURE}'):
    if IP not in p:
        continue
    q = Ether(dst='{MAC}') / p[IP]
    q[IP].dst = '192.168.77.1'
    del q[IP].chksum
    if q[IP].frag == 0 and (UDP in q or TCP in q):
        del q[(UDP if UDP in q else TCP)].chksum
    raw.append(bytes(q))
"""

PLAYERS_LOOP = PLAYER_PKTS + """
import time
from scapy.all import conf
s = conf.L2socket(iface='sw1')
end = time.time() + {secs}
while time.time() < end:
    t0 = time.time()
    for b in raw:
        s.send(b)
    time.sleep(max(0, 1 - (time.time() - t0)))
"""

ATTACK_LOOP = CAPTURE_PKTS + """
import time
from scapy.all import conf
s = conf.L2socket(iface='sw1')
end = time.time() + {secs}
while time.time() < end:
    for b in raw:
        s.send(b)
        if time.time() >= end:
            break
"""

ONE_PASS = """
from scapy.all import conf
s = conf.L2socket(iface='sw1')
for b in raw:
    s.send(b)
print(len(raw))
"""


def netns(code: str, wait: bool = True):
    cmd = ["ip", "netns", "exec", "swatk", "python3", "-c", code]
    if wait:
        return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL)


def stats() -> dict:
    return _sum_percpu((_bpftool("map", "dump", "name", "stats") or [{}])[0])


class UnsureML:
    def predict(self, f):
        return MLVerdict("udp_flood", 0.3, True, {"udp_flood": 0.3})


def main() -> None:
    dp = BPFDataPlane("sw0", "bpf/xdp_filter.o")
    dp.attach(enforce=True)
    loop = LiveLoop(dp, MitigationConfig(), PacketSampler("sw0"), analyst_async=False)
    if FORCE_ANALYST:
        loop.cls.ml = UnsureML()
    tier = None
    players = netns(PLAYERS_LOOP.format(secs=BASELINE_S + ATTACK_S + 30), wait=False)
    start, attack, attack_t0, detect_s, block_s, label, rules = time.time(), None, None, None, None, None, []
    tail = 3
    while tail > 0:
        time.sleep(1)
        if attack is None and time.time() - start >= BASELINE_S:
            attack = netns(ATTACK_LOOP.format(secs=ATTACK_S), wait=False)  # scapy needs a while to load the file
        f, v, c, _ = loop.tick()
        if attack is not None and attack_t0 is None and f.pps > 3 * max(v.baseline_pps, 1):
            attack_t0 = time.time() - 1  # this window is the first one with attack traffic in it
        if attack is not None and attack.poll() is not None:
            tail -= 1
        rules = [r.describe() for r in loop.ctl.enforced_rules()]
        since = None if attack_t0 is None else round(time.time() - attack_t0)
        if since is not None and c and c.malicious and detect_s is None:
            detect_s, label = since, c.label
        if since is not None and c and tier is None:
            tier = c.source
        if since is not None and rules and block_s is None:
            block_s = since
        print(f"t={time.time() - start:5.1f}s pps={f.pps:8,.0f}  {('ALERT ' + c.label) if c else 'ok':48s} rules={len(rules)}")
    # controlled pass: the whole real capture once, rules active, counted exactly by the kernel
    loop.tick()
    before = stats()
    sent = int(netns(CAPTURE_PKTS + ONE_PASS).strip())
    after = stats()
    dropped = after["dropped"] - before["dropped"]
    # then real-player traffic alone: none of it may be dropped
    before = stats()
    netns(PLAYER_PKTS + ONE_PASS)
    after = stats()
    player_dropped = after["dropped"] - before["dropped"]
    players.terminate()
    dp.detach()

    result = {"capture": os.path.basename(CAPTURE), "kernel": platform.release(), "classified_as": label,
              "classified_by": tier, "detect_s": detect_s, "block_s": block_s, "rules": rules,
              "capture_packets_sent": sent, "capture_packets_dropped": dropped,
              "player_packets_sent": 300, "player_packets_dropped": player_dropped}
    if FORCE_ANALYST:
        a = loop.analyst_results[0] if loop.analyst_results else {}
        result = {"capture": result["capture"], "kernel": result["kernel"], "mode": "analyst (ML forced unsure)",
                  "sampled_attack_packets": len(loop.attack_sample), "proposed": a.get("proposed"),
                  "verdict": (a.get("verdict") or {}).get("verdict"), "backend": a.get("backend"),
                  "dry_run_rules": [r.describe() for r in loop.ctl.rules.values() if r.mode == "dry-run"],
                  "capture_packets_dropped": dropped, "player_packets_dropped": player_dropped}
    print(json.dumps(result, indent=2))
    if FORCE_ANALYST:
        assert result["verdict"] and result["verdict"].startswith("accepted"), "analyst rule was not accepted"
        assert dropped == 0, "an analyst rule must never be enforced on its own"
    else:
        assert label and block_s is not None, "attack was not detected and blocked"
    assert player_dropped == 0
    os.makedirs("results", exist_ok=True)
    path = "results/kernel_replay.json"
    runs = json.load(open(path)) if os.path.exists(path) else []
    runs = [r for r in (runs if isinstance(runs, list) else [runs])
            if (r["capture"], r.get("mode")) != (result["capture"], result.get("mode"))] + [result]
    with open(path, "w") as fh:
        json.dump(runs, fh, indent=2)
    print("KERNEL REPLAY PASSED")


if __name__ == "__main__":
    main()
