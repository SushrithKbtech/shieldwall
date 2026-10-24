"""Evaluation harness: four scenarios, measured honestly, with vs without ShieldWall.

Each scenario runs twice on the identical seeded traffic: once enforcing, once in
dry-run (detector runs, nothing is dropped = "without ShieldWall").
"""
from __future__ import annotations

import os
from dataclasses import dataclass

from .engine import Engine
from .mitigation import MitigationConfig

WARMUP, ATTACK_LEN, TAIL = 40, 60, 40


@dataclass
class Scenario:
    key: str
    name: str
    preset: str
    malicious: bool = True


SCENARIOS = [
    Scenario("S1", "Clean attack: CLDAP amplification", "cldap"),
    Scenario("S2a", "Attack mixed with real traffic: SYN flood on the game port", "syn"),
    Scenario("S2b", "Attack mixed with real traffic: UDP flood", "udp"),
    Scenario("S3", "Legitimate spike, no attack (flash crowd)", "flash_crowd", malicious=False),
    Scenario("S4", "Attack bigger than the link (25 Gbps into 10 Gbps)", "mega_cldap"),
]


def run(sc: Scenario, enforce: bool) -> dict:
    os.environ.setdefault("SHIELDWALL_LLM", "template")
    eng = Engine(mit_cfg=MitigationConfig(dry_run=not enforce), explain_async=False)
    eng.launch(sc.preset, duration=ATTACK_LEN, start=WARMUP)
    points = [eng.step() for _ in range(WARMUP + ATTACK_LEN + TAIL)]
    window = [p for p in points if WARMUP <= p["t"] < WARMUP + ATTACK_LEN]

    offered = sum(p["legit_pps"] for p in window)
    served = sum(p["served_legit"] for p in window)
    dropped_legit = sum(p["legit_dropped"] for p in window)

    detect = next((p["t"] - WARMUP + 1 for p in window if p["anomalous"]), None)
    mitigate = next((p["t"] - WARMUP + 1 for p in window
                     if p["attack_arrived"] and p["attack_passed"] < 0.1 * p["attack_arrived"]
                     and p["served_pct"] >= 95), None)
    incidents = eng.store.incidents(5)
    rules_added = len(eng.store.query("SELECT id FROM events WHERE kind = 'rule_added'"))
    escalated = len(eng.store.query("SELECT id FROM events WHERE kind = 'escalated'")) > 0
    return {
        "served_pct": 100 * served / offered if offered else 100.0,
        "legit_dropped_pct": 100 * dropped_legit / offered if offered else 0.0,
        "detect_s": detect,
        "mitigate_s": mitigate if sc.malicious else None,
        "rules_added": rules_added,
        "escalated": escalated,
        "label": incidents[-1]["label"] if incidents else "none",
        "explanation": incidents[0]["explanation"] if incidents else "",
    }


def _fmt(x, unit="s"):
    return "n/a" if x is None else f"{x}{unit}"


def main(out_path: str | None = None) -> str:
    rows, notes = [], []
    for sc in SCENARIOS:
        off = run(sc, enforce=False)
        on = run(sc, enforce=True)
        fp = "-" if sc.malicious else f"{on['rules_added']} rules, {on['legit_dropped_pct']:.1f}% real traffic dropped"
        rows.append(f"| {sc.key} | {sc.name} | {on['label']} | {off['served_pct']:.1f}% | {on['served_pct']:.1f}% "
                    f"| {_fmt(on['detect_s'])} | {_fmt(on['mitigate_s'])} | {'yes' if on['escalated'] else 'no'} | {fp} |")
        notes.append(f"- **{sc.key}**: {on['explanation']}")

    table = "\n".join([
        "| # | Scenario | Classified as | Real traffic served WITHOUT | Real traffic served WITH | Time to detect | Time to mitigate | Escalated upstream | False positives |",
        "|---|---|---|---|---|---|---|---|---|",
        *rows,
    ])
    report = (
        "# ShieldWall evaluation (simulated lab)\n\n"
        f"Each scenario: {WARMUP}s of normal play to learn the baseline, a {ATTACK_LEN}s event, {TAIL}s of recovery. "
        "1 window = 1 s. Real traffic = ~2,000 pps of Minecraft players. Server capacity 60k pps, uplink 10 Gbps. "
        "'Without' = same seeded traffic with the controller in dry-run.\n\n"
        f"{table}\n\n"
        "## What the LLM layer said (template backend)\n\n" + "\n".join(notes) + "\n\n"
        "## Honest limits\n\n"
        "- These numbers come from the traffic simulator, not yet from packets on a real NIC. "
        "The XDP throughput benchmark (Mpps/core) needs a Linux VM with a native-XDP NIC and is still pending.\n"
        "- S4 recovers only because the simulated upstream ISP accepts our FlowSpec rule. Without upstream help, "
        "no tool on the server can fix a full link.\n"
        "- Time to detect is bounded below by the 1 s window and the 2-window persistence guard.\n"
    )
    print(report)
    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(report)
    return report


if __name__ == "__main__":
    main()
