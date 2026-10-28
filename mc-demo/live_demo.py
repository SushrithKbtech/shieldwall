#!/usr/bin/env python3
"""Live end-to-end test: a REAL Minecraft server (flying-squid) + a REAL player bot
(mineflayer) on a bandwidth-capped veth, with the REAL ShieldWall XDP program on the
server's interface, under a REAL CLDAP flood. Run once without protection (dry-run)
and once with it (enforce), and compare what the player experiences.

    cd mc-demo && npm install && sudo python3 live_demo.py
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(REPO, "controlplane"))
os.environ.setdefault("SHIELDWALL_LLM", "template")
from shieldwall.bpf_dataplane import BPFDataPlane, LiveLoop          # noqa: E402
from shieldwall.mitigation import MitigationConfig                   # noqa: E402

IFACE, NS = "sw0", "atk"
SRV_IP, ATK_IP = "192.168.77.1", "192.168.77.2"
MCV = os.environ.get("MCV", "1.18.2")
OBJ = os.path.join(REPO, "bpf", "xdp_filter.o")


def sh(cmd):
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def teardown():
    sh(f"ip link set dev {IFACE} xdpgeneric off; ip link del {IFACE}; ip netns del {NS}")


def setup_net(use_tc):
    teardown()
    sh(f"ip netns add {NS}")
    sh(f"ip link add {IFACE} type veth peer name sw1")
    sh(f"ip link set sw1 netns {NS}")
    sh(f"ip addr add {SRV_IP}/24 dev {IFACE}; ip link set {IFACE} up")
    sh(f"ip netns exec {NS} ip addr add {ATK_IP}/24 dev sw1")
    sh(f"ip netns exec {NS} ip link set sw1 up; ip netns exec {NS} ip link set lo up")
    if use_tc:   # a modest uplink so a flood actually competes with the player
        sh(f"tc qdisc add dev {IFACE} clsact")
        sh(f"tc filter add dev {IFACE} ingress matchall action police rate 20mbit burst 64k conform-exceed drop")


def rec(f, v, c, loop, dp, phase):
    return {
        "phase": phase, "pps": round(f.pps), "z": round(v.zscore, 1), "anom": v.anomalous,
        "cls": (c.label if c else None), "src": (getattr(c, "source", None) if c else None),
        "k_pkts": dp.prev.get("pkts", 0), "k_dropped": dp.prev.get("dropped", 0),
        "rules": [r.describe() for r in loop.ctl.rules.values()],
    }


def run_once(mode, use_tc=True, warmup=18, attack_dur=14, tail=4):
    enforce = (mode == "enforce")
    setup_net(use_tc)
    srv = subprocess.Popen(["node", "mc_server.js"], cwd=HERE,
                           stdout=open("/tmp/mc.log", "w"), stderr=subprocess.STDOUT,
                           env={**os.environ, "MCV": MCV})
    for _ in range(50):
        time.sleep(0.4)
        if "MC_SERVER_UP" in open("/tmp/mc.log").read():
            break

    dp = BPFDataPlane(IFACE, OBJ)
    dp.attach(enforce=enforce)
    loop = LiveLoop(dp, MitigationConfig(dry_run=not enforce))

    botlog = open("/tmp/bot.jsonl", "w")
    t_bot = time.time()
    bot = subprocess.Popen(f"ip netns exec {NS} node bot.js".split(), cwd=HERE,
                           stdout=botlog, stderr=subprocess.STDOUT,
                           env={**os.environ, "H": SRV_IP, "MCV": MCV})
    ticks = []
    for _ in range(warmup):
        time.sleep(1); f, v, c, _a = loop.tick(); ticks.append(rec(f, v, c, loop, dp, "warmup"))

    t_atk0 = time.time()
    aenv = {**os.environ, "DST": SRV_IP, "SRC": ATK_IP, "DUR": str(attack_dur), "SIZE": "64"}
    atks = [subprocess.Popen(f"ip netns exec {NS} python3 attack.py".split(), cwd=HERE,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=aenv)
            for _ in range(4)]
    for _ in range(attack_dur):
        time.sleep(1); f, v, c, _a = loop.tick(); ticks.append(rec(f, v, c, loop, dp, "attack"))
    sent = sum(int((a.communicate()[0].decode().split() + ["0", "0"])[1]) for a in atks)
    atk_out = f"{sent:,} packets from 4 workers"
    t_atk1 = time.time()
    for _ in range(tail):
        time.sleep(1); f, v, c, _a = loop.tick(); ticks.append(rec(f, v, c, loop, dp, "tail"))

    bot.terminate(); srv.terminate(); time.sleep(1); botlog.close()
    events = []
    for line in open("/tmp/bot.jsonl"):
        line = line.strip()
        if line.startswith("{"):
            try:
                e = json.loads(line); e["wall"] = t_bot + e["dt"]; events.append(e)
            except json.JSONDecodeError:
                pass
    teardown()

    pings = [e for e in events if e["ev"] == "ping"]
    atk_pings = [e for e in pings if t_atk0 <= e["wall"] <= t_atk1]
    ok = [e["ms"] for e in atk_pings if e.get("ok")]
    kattack = ticks[-1]["k_dropped"] - ticks[warmup - 1]["k_dropped"]
    return {
        "mode": mode, "use_tc": use_tc, "attack": atk_out,
        "spawned": any(e["ev"] == "spawn" for e in events),
        "disconnected_during_attack": any(e["ev"] in ("end", "kicked") and t_atk0 <= e["wall"] <= t_atk1 + 2
                                          for e in events),
        "ping_ok_during_attack": f"{len(ok)}/{len(atk_pings)}",
        "ping_ms_median": (sorted(ok)[len(ok) // 2] if ok else None),
        "attack_classified_as": next((t["cls"] for t in ticks if t["phase"] == "attack" and t["cls"]), None),
        "classified_by_tier": next((t["src"] for t in ticks if t["phase"] == "attack" and t["src"]), None),
        "kernel_attack_packets_dropped": kattack,
        "rules_installed": next(([r for r in t["rules"]] for t in reversed(ticks) if t["rules"]), []),
        "ticks": ticks,
    }


def main():
    results = {}
    for mode in ("dryrun", "enforce"):
        print(f"\n===== RUN: {mode} =====", flush=True)
        r = run_once(mode)
        results[mode] = r
        print(f"  attack            : {r['attack']}")
        print(f"  bot spawned       : {r['spawned']}")
        print(f"  classified as     : {r['attack_classified_as']} (by tier: {r['classified_by_tier']})")
        print(f"  rules installed   : {r['rules_installed']}")
        print(f"  kernel dropped    : {r['kernel_attack_packets_dropped']:,} attack packets")
        print(f"  bot disconnected  : {r['disconnected_during_attack']}")
        print(f"  status pings OK   : {r['ping_ok_during_attack']}  median {r['ping_ms_median']} ms")
    json.dump(results, open(f"{HERE}/live_results.json", "w"), indent=2)
    print("\nsaved live_results.json")


if __name__ == "__main__":
    main()
