"""Replay a real attack capture (.pcap / .pcapng) through the full ShieldWall engine.

The attack packets come straight from the capture: real sources, ports, sizes, TCP
flags and IP fragments, replayed at the capture's own packet rate (looped if the
capture is shorter than the attack window). They are mixed into the modelled
player traffic, so we know exactly which packets were attack traffic and can score
detection and mitigation against that ground truth.

    shieldwall replay capture.pcap [more.pcap ...]
"""
from __future__ import annotations

import collections
import json
import os

from .engine import Engine
from .mitigation import MitigationConfig
from .models import AMP_PORTS, Packet
from .pcap import ParsedPacket, read_packets
from .simulator import AttackSpec, SimConfig, TrafficSim

MAX_PACKETS = 200_000


class ReplaySim(TrafficSim):
    """Modelled players plus a real attack capture replayed at its native rate."""

    def __init__(self, cfg: SimConfig, attack: list[ParsedPacket], attack_at: int, duration: int, scale: float = 1.0,
                 rate_pps: float | None = None):
        super().__init__(cfg)
        self.capture = attack
        span = attack[-1].ts - attack[0].ts if len(attack) > 1 else 0.0
        self.native_pps = len(attack) / span if span > 0 else float(len(attack))
        self.rate = rate_pps or self.native_pps * scale
        self.attack_at, self.duration = attack_at, duration
        self.cursor = 0

    def _in_attack(self, t: int) -> bool:
        return self.attack_at <= t < self.attack_at + self.duration

    def active(self, t: int) -> list[AttackSpec]:
        acts = super().active(t)
        if self._in_attack(t):
            acts.append(AttackSpec(kind="replay", start=self.attack_at, end=self.attack_at + self.duration, pps=self.rate))
        return acts

    def offered(self, t: int) -> list[Packet]:
        samples = super().offered(t)
        if not self._in_attack(t):
            return samples
        n, total = self.rate, len(self.capture)
        k = max(1, min(self.cfg.attack_samples, int(n)))
        # this second of attack = the next n packets of the capture; take k of them evenly
        for i in range(k):
            p = self.capture[(self.cursor + int(i * n / k)) % total]
            samples.append(Packet(p.src, p.sport, p.dport, p.proto, p.flags, p.size, n / k, legit=False, frag=p.frag))
        self.cursor = (self.cursor + int(n)) % total
        return samples


def load_capture(path: str, target: str | None = None) -> tuple[list[ParsedPacket], dict]:
    """Two streaming passes: find the victim (most common destination), then keep its packets."""
    from .models import ip_int, ip_str

    dsts = collections.Counter(p.dst for p in read_packets(path))
    if not dsts:
        raise SystemExit(f"{path}: no IPv4 packets")
    victim = ip_int(target) if target else dsts.most_common(1)[0][0]
    pkts = []
    for p in read_packets(path):
        if p.dst == victim:
            pkts.append(p)
            if len(pkts) >= MAX_PACKETS:
                break
    span = pkts[-1].ts - pkts[0].ts if len(pkts) > 1 else 0.0
    ports = collections.Counter(p.sport for p in pkts if p.proto == 17 and not p.frag)
    summary = {
        "file": os.path.basename(path),
        "victim": ip_str(victim),
        "packets": len(pkts),
        "seconds": round(span, 3),
        "native_pps": round(len(pkts) / span) if span > 0 else len(pkts),
        "unique_sources": len({p.src for p in pkts}),
        "avg_size": round(sum(p.size for p in pkts) / len(pkts)),
        "udp_share": round(sum(p.proto == 17 for p in pkts) / len(pkts), 3),
        "syn_share": round(sum(p.proto == 6 and p.flags & 0x12 == 0x02 for p in pkts) / len(pkts), 3),
        "fragment_share": round(sum(p.frag for p in pkts) / len(pkts), 3),
        "top_source_ports": [{"port": port, "service": AMP_PORTS.get(port), "share": round(c / len(pkts), 3)}
                             for port, c in ports.most_common(4)],
    }
    return pkts, summary


def run_once(pkts: list[ParsedPacket], enforce: bool, attack_at: int, duration: int, tail: int,
             scale: float, seed: int = 7, rate_pps: float | None = None) -> tuple[Engine, list[dict]]:
    sim = ReplaySim(SimConfig(seed=seed), pkts, attack_at, duration, scale, rate_pps)
    eng = Engine(sim=sim, mit_cfg=MitigationConfig(dry_run=not enforce), explain_async=False)
    points = [eng.step() for _ in range(attack_at + duration + tail)]
    return eng, points


def score(points: list[dict], attack_at: int, duration: int) -> dict:
    win = collections.Counter()
    for p in points[30:]:
        truth = attack_at <= p["t"] < attack_at + duration
        pred = p["malicious_alert"]
        win["tp" if truth and pred else "fp" if pred else "fn" if truth else "tn"] += 1
    attack = [p for p in points if attack_at <= p["t"] < attack_at + duration]
    arrived = sum(p["attack_arrived"] or 0 for p in attack)
    passed = sum(p["attack_passed"] for p in attack)
    legit = sum(p["legit_pps"] for p in points)
    mit = next((p["t"] for p in attack if p["attack_arrived"] and p["attack_passed"] < 0.1 * p["attack_arrived"]), None)
    after = [p for p in attack if mit is not None and p["t"] >= mit]
    after_arrived = sum(p["attack_arrived"] or 0 for p in after)
    after_dropped = after_arrived - sum(p["attack_passed"] for p in after)
    tp, fp, fn = win["tp"], win["fp"], win["fn"]
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return {
        "detect_s": next((p["t"] - attack_at + 1 for p in attack if p["malicious_alert"]), None),
        "mitigate_s": next((p["t"] - attack_at + 1 for p in attack
                            if p["attack_arrived"] and p["attack_passed"] < 0.1 * p["attack_arrived"]), None),
        "served_pct": 100 * sum(p["served_legit"] for p in attack) / max(1, sum(p["legit_pps"] for p in attack)),
        "attack_dropped_pct": 100 * (arrived - passed) / arrived if arrived else 0.0,
        "attack_dropped_after_block_pct": 100 * after_dropped / after_arrived if after_arrived else 0.0,
        "legit_dropped_pct": 100 * sum(p["legit_dropped"] for p in points) / legit if legit else 0.0,
        "window": {**win, "precision": precision, "recall": recall,
                   "f1": 2 * precision * recall / (precision + recall) if precision + recall else 0.0},
    }


def replay(path: str, target: str | None = None, attack_at: int = 40, duration: int = 30, tail: int = 30,
           scale: float = 1.0, report: bool = False, loaded: tuple | None = None) -> dict:
    if loaded:  # (packets, true packet rate, summary) from another loader, e.g. CIC-DDoS2019 flows
        pkts, rate, summary = loaded
    else:
        pkts, summary = load_capture(path, target)
        rate = None
    off_eng, off_pts = run_once(pkts, False, attack_at, duration, tail, scale, rate_pps=rate)
    on_eng, on_pts = run_once(pkts, True, attack_at, duration, tail, scale, rate_pps=rate)
    on, off = score(on_pts, attack_at, duration), score(off_pts, attack_at, duration)
    incidents = [i for i in on_eng.store.incidents(10) if i["malicious"]]
    rules = [e["detail"] for e in on_eng.store.query("SELECT detail FROM events WHERE kind = 'rule_added' ORDER BY id")]
    result = {
        "capture": summary,
        "label": incidents[-1]["label"] if incidents else "not detected",
        "rules": rules,
        "with": on,
        "without": {"served_pct": off["served_pct"]},
        "explanation": incidents[-1]["explanation"] if incidents else "",
    }
    if report:
        from .llm_report import incident_report
        result["report"] = incident_report(on_eng)
    return result


PCAP_INTRO = (
    "Real attack packets (sources, ports, sizes, flags, fragments) from public captures, replayed at their own "
    "packet rate for 30 s on top of modelled player traffic (~2,000 pps). Ground truth = which packets came from "
    "the capture. Captures: github.com/StopDDoS/packet-captures (\"packet captures of real-world ddos attacks\"). "
    "Reproduce with `shieldwall replay <file.pcap>`."
)
CIC_INTRO = (
    "CIC-DDoS2019 (CSV release, CICFlowMeter flow records). For each file, the busiest 30 s of attack flows to the "
    "victim are rebuilt into a packet stream (real addresses, ports, protocol, packet counts, sizes and timing per "
    "flow; packet spacing inside a flow is approximated) and replayed at the true packet rate on top of modelled "
    "player traffic. Ground truth = the dataset's own attack labels. "
    "Reproduce with `shieldwall replay-cic archive.zip --member 01-12/Syn.csv`."
)


def write_results(results: list[dict], out_dir: str, stem: str, title: str, intro: str) -> str:
    rows = []
    for r in results:
        c, w = r["capture"], r["with"]
        rows.append(f"| {c['file']} | {c['packets']:,} pkts, {c['native_pps']:,} pps, {c['unique_sources']:,} sources, "
                    f"{c['fragment_share']:.0%} fragments | {r['label']} | {w['detect_s'] or '-'} s | "
                    f"{w['mitigate_s'] or '-'} s | {w['attack_dropped_pct']:.1f}% ({w['attack_dropped_after_block_pct']:.1f}%) | "
                    f"{w['legit_dropped_pct']:.3f}% | "
                    f"{r['without']['served_pct']:.1f}% → {w['served_pct']:.1f}% | {w['window']['precision']:.3f} / "
                    f"{w['window']['recall']:.3f} / {w['window']['f1']:.3f} |")
    md = "\n".join([
        f"# {title}",
        "",
        intro,
        "",
        "| Capture | What is in it | Classified as | Detect | Block | Attack dropped: whole attack (once blocking) "
        "| Real traffic dropped | Players served (without → with) | Precision / recall / F1 (per second) |",
        "|---|---|---|---|---|---|---|---|---|",
        *rows,
        "",
        "## Rules ShieldWall wrote",
        "",
        *[f"- **{r['capture']['file']}**: " + "; ".join(r["rules"] or ["none"]) for r in results],
        "",
    ])
    print(md)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, f"{stem}.md"), "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(os.path.join(out_dir, f"{stem}.json"), "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, default=str)
    return md


def main(paths: list[str], out_dir: str = "results", target: str | None = None, report: bool = False,
         name: str = "replay") -> list[dict]:
    os.environ.setdefault("SHIELDWALL_LLM", "template")
    results = [replay(p, target, report=report) for p in paths]
    write_results(results, out_dir, name, "Replay of real DDoS captures", PCAP_INTRO)
    return results


def main_cic(path: str, members: list[str], out_dir: str = "results", report: bool = False,
             name: str = "replay_cic") -> list[dict]:
    from .cic import load_cic

    os.environ.setdefault("SHIELDWALL_LLM", "template")
    results = [replay(path, report=report, loaded=load_cic(path, m)) for m in members]
    write_results(results, out_dir, name, "Replay of CIC-DDoS2019 flow records", CIC_INTRO)
    return results
