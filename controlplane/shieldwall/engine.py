"""The control loop: every second, read -> featurise -> detect -> classify -> act -> explain."""
from __future__ import annotations

import threading
from collections import OrderedDict, deque

from .classifier import Classification, Classifier
from .detectors import Detector, DetectorConfig
from .features import Featurizer
from .llm import backend_label, explain_incident, template_explanation
from .mitigation import MitigationConfig, MitigationController
from .models import ACK, AMP_PORTS, UDP
from .simulator import MC_BEDROCK, AttackSpec, SimConfig, SimDataPlane, TrafficSim
from .store import EventStore

def _top_ports(samples, attr: str, n: int = 3) -> list[dict]:
    total = sum(p.w for p in samples) or 1.0
    by: dict[int, float] = {}
    for p in samples:
        if not p.frag:
            by[getattr(p, attr)] = by.get(getattr(p, attr), 0.0) + p.w
    return [{"port": port, "share": round(w / total, 3)} for port, w in sorted(by.items(), key=lambda kv: -kv[1])[:n]]


def profile(f, samples=()) -> dict:
    """What the traffic looked like at the incident's peak, in report-friendly form."""
    return {
        "top_source_ports": _top_ports(samples, "sport"), "top_destination_ports": _top_ports(samples, "dport"),
        "packets_per_second": round(f.pps), "gbps": round(f.bps / 1e9, 3), "distinct_sources": f.unique_sources,
        "share_from_never_seen_sources": round(f.new_source_share, 3), "udp_share": round(f.udp_share, 3),
        "syn_to_ack_ratio": round(f.syn_ack_ratio, 2), "amplification_share": round(f.amp_share, 3),
        "amplification_source_ports": [{"port": p, "service": AMP_PORTS.get(p)} for p in f.amp_ports],
        "fragment_share": round(f.frag_share, 3),
        "top_talkers": [{"ip": ip, "packets_per_second": round(n), "share": round(n / f.pps, 3) if f.pps else 0}
                        for ip, n in f.top_talkers[:3]],
    }


REBASELINE_AFTER = 30  # windows of confirmed legitimate surge before it becomes the new normal

PRESETS = {
    "cldap": dict(kind="cldap", pps=200_000, ramp=2),
    "dns": dict(kind="dns", pps=150_000, ramp=2),
    "ntp": dict(kind="ntp", pps=120_000, ramp=2),
    "syn": dict(kind="syn", pps=150_000, ramp=2),
    "udp": dict(kind="udp", pps=120_000, ramp=3),
    "flash_crowd": dict(kind="flash_crowd", pps=5_000, ramp=8),
    "mega_cldap": dict(kind="cldap", pps=2_200_000, ramp=2),  # ~25 Gbps into a 10 Gbps link
}


class Engine:
    def __init__(self, sim_cfg: SimConfig | None = None, det_cfg: DetectorConfig | None = None,
                 mit_cfg: MitigationConfig | None = None, store_path: str = ":memory:",
                 explain_async: bool = True, history: int = 180, sim: TrafficSim | None = None):
        self.sim = sim or TrafficSim(sim_cfg)
        self.mit_cfg = mit_cfg or MitigationConfig()
        self.dp = SimDataPlane(self.sim, self.mit_cfg.allowlist)
        self.featurizer = Featurizer()
        self.detector = Detector(det_cfg)
        self.classifier = Classifier()
        self.controller = MitigationController(self.mit_cfg, link_bps=self.sim.cfg.link_bps)
        self.store = EventStore(store_path)
        self.explain_async = explain_async
        self.t = 0
        self.lock = threading.RLock()
        self.history: deque[dict] = deque(maxlen=history)
        self.trusted: OrderedDict[int, None] = OrderedDict()

        self.incident: dict | None = None
        self._benign = 0
        self.last_incident: dict | None = None
        self.attack_sample: list = []  # traffic at the incident's peak, for reports and rule validation
        self.calm_sample: list = []    # recent normal traffic, so suggested rules can be tested against players
        self.last_classification: Classification | None = None
        self.last_features = None
        self.last_verdict = None

    # -- scenario control ----------------------------------------------------
    def launch(self, preset: str, duration: int | None = None, start: int | None = None) -> None:
        p = dict(PRESETS[preset])
        start = self.t if start is None else start
        with self.lock:
            self.sim.add_attack(AttackSpec(start=start, end=None if duration is None else start + duration, **p))
            self.store.event(start, "scenario", f"traffic scenario '{preset}' scheduled at t={start}s")

    def stop_attacks(self) -> None:
        with self.lock:
            self.sim.stop_all(self.t)
            self.store.event(self.t, "scenario", "all traffic scenarios stopped")

    # -- one control-loop window ---------------------------------------------
    def step(self) -> dict:
        with self.lock:
            t = self.t
            window, res = self.dp.tick(t)
            f = self.featurizer.featurize(window)
            v = self.detector.update(f)
            c = self.classifier.classify(f) if v.anomalous else None
            actions = self.controller.step(t, v.anomalous, c, f, v.baseline_pps, res.rule_hits, res.upstream_hits)

            # write rules into the data plane's maps (they take effect next window)
            self.dp.rules = self.controller.enforced_rules()
            self.dp.upstream = list(self.controller.upstream_rules.values())

            self._bookkeep(t, f, v, c, actions, res)
            inc = self.incident
            if v.anomalous and inc is not None and f.pps >= inc.get("profile_pps", 0):
                inc["profile_pps"] = f.pps
                inc["profile"] = profile(f, window.samples)
                self.attack_sample = list(window.samples)

            # Real servers grow: a surge confirmed as legitimate for long enough becomes the new normal.
            self._benign = self._benign + 1 if c and c.kind == "legit_surge" else 0
            rebaseline = self._benign >= REBASELINE_AFTER
            if rebaseline:
                self.detector.rebaseline(f)
                self._benign = 0
                self.store.event(t, "rebaselined", f"sustained legitimate surge: {f.pps:,.0f} pps is the new normal",
                                 self.incident["id"] if self.incident else None)

            calm = rebaseline or (not v.anomalous and not any(v.votes.values()))
            if calm:
                self.calm_sample = list(window.samples)
                self.featurizer.learn(window)
                self.classifier.learn(f)
                self._learn_trusted(window)

            point = {
                "t": t,
                "pps": round(f.pps),
                "passed_pps": round(res.passed_legit + res.passed_attack),
                "legit_pps": round(res.offered_legit),
                "attack_pps": round(res.offered_attack),
                "served_pct": round(res.legit_served_pct, 1),
                "baseline": round(v.baseline_pps),
                "gbps": round(f.bps / 1e9, 2),
                "zscore": round(v.zscore, 1),
                "cusum": round(v.cusum, 1),
                "entropy": round(f.src_entropy, 2),
                "anomalous": v.anomalous,
                "malicious_alert": bool(c and c.malicious),
                "stage": self.controller.stage,
                # raw ground truth from the simulator, used by the evaluation harness
                "served_legit": res.served_legit,
                "legit_dropped": res.legit_after_link - res.passed_legit,
                "attack_arrived": res.offered_attack and (f.pps - res.legit_after_link),
                "attack_passed": res.passed_attack,
            }
            self.history.append(point)
            self.store.metric(t, pps=f.pps, bps=f.bps, passed_pps=point["passed_pps"],
                              served_pct=point["served_pct"], zscore=v.zscore, cusum=v.cusum,
                              entropy=f.src_entropy, anomalous=v.anomalous)
            self.last_features, self.last_verdict, self.last_classification = f, v, c
            self.t += 1
            return point

    def _learn_trusted(self, window) -> None:
        # Sources that complete TCP handshakes or talk to the game's UDP port in calm times.
        for p in window.samples:
            if (p.flags & ACK) or (p.proto == UDP and p.dport == MC_BEDROCK):
                self.trusted[p.src] = None
                self.trusted.move_to_end(p.src)
        while len(self.trusted) > 65_536:
            self.trusted.popitem(last=False)
        self.dp.trusted = set(self.trusted)

    # -- incidents, events, explanations ---------------------------------------
    def _bookkeep(self, t, f, v, c, actions, res) -> None:
        inc = self.incident
        if v.anomalous and inc is None:
            iid = self.store.open_incident(t, c.kind, c.label, c.malicious, c.evidence)
            starts = [a.start for a in self.sim.active(t)]
            inc = self.incident = {
                "id": iid, "start": t, "kind": c.kind, "label": c.label, "malicious": c.malicious,
                "peak_pps": f.pps, "sources": f.unique_sources, "evidence": c.evidence,
                "attack_start": min(starts) if starts else None, "detect_s": None,
                "mitigate_s": None, "escalated": False, "legit_offered": 0.0, "legit_served": 0.0,
                "explanation": "",
            }
            if inc["attack_start"] is not None:
                inc["detect_s"] = t - inc["attack_start"] + 1
            self.store.event(t, "alert", f"anomaly confirmed: {c.label} "
                             f"(z={v.zscore:.1f}, CUSUM={v.cusum:.1f}, votes={sum(v.votes.values())}/3)", iid)
            self._explain(inc)
        elif v.anomalous and inc is not None:
            if c.malicious and not inc["malicious"] or (c.malicious and c.kind != inc["kind"]):
                inc.update(kind=c.kind, label=c.label, malicious=True, evidence=c.evidence)
                self.store.update_incident(inc["id"], kind=c.kind, label=c.label, malicious=1)
                self.store.event(t, "classified", f"re-classified as {c.label}", inc["id"])
            inc["peak_pps"] = max(inc["peak_pps"], f.pps)
            inc["sources"] = max(inc["sources"], f.unique_sources)

        if (inc is not None and inc["malicious"] and inc["mitigate_s"] is None and inc["attack_start"] is not None
                and sum(res.rule_hits.values()) > 0):
            # a rule still active from an earlier incident is already dropping this attack
            inc["mitigate_s"] = t - inc["attack_start"] + 1
            self._explain(inc)
        if inc is not None:
            inc["legit_offered"] += res.offered_legit
            inc["legit_served"] += res.served_legit

        for a in actions:
            self.store.event(t, a.kind, a.detail, inc["id"] if inc else None)
            if inc and a.kind == "rule_added" and inc["mitigate_s"] is None and inc["attack_start"] is not None:
                # rule written at end of window t -> enforced from window t+1
                inc["mitigate_s"] = t - inc["attack_start"] + 2
                self._explain(inc)
            if inc and a.kind == "escalated":
                inc["escalated"] = True
                self._explain(inc)

        # An incident stays open while the provider is still filtering it upstream: the flood is
        # still happening, we just no longer see it on our side of the link.
        if inc is not None and not v.anomalous and not self.controller.upstream_rules:
            served = 100 * inc["legit_served"] / inc["legit_offered"] if inc["legit_offered"] else 100.0
            self.store.update_incident(inc["id"], ended_t=t, peak_pps=inc["peak_pps"], sources=inc["sources"],
                                       detect_s=inc["detect_s"], mitigate_s=inc["mitigate_s"])
            self.store.event(t, "resolved", f"incident #{inc['id']} over after {t - inc['start']}s; "
                             f"{served:.1f}% of real traffic served", inc["id"])
            inc["served_pct"] = served
            self._explain(inc)
            self.last_incident = inc
            self.incident = None

    def _facts(self, inc: dict) -> dict:
        served = inc.get("served_pct")  # only known once the incident is over
        return {
            "incident": inc["id"], "label": inc["label"], "malicious": inc["malicious"],
            "peak_pps": round(inc["peak_pps"]), "sources": inc["sources"], "detect_s": inc["detect_s"],
            "mitigate_s": inc["mitigate_s"], "served_pct": None if served is None else round(served, 1),
            "escalated": inc["escalated"],
            "evidence": inc["evidence"], "resolved": served is not None,
            "incident_over": served is not None,
            "blocking_now": bool(self.controller.enforced_rules() or self.controller.upstream_rules),
            "players_now": ("real player traffic is getting through normally again"
                            if inc["mitigate_s"] is not None and served is None else None),
        }

    def _explain(self, inc: dict) -> None:
        facts = self._facts(inc)
        inc["explanation"] = template_explanation(facts)
        self.store.update_incident(inc["id"], explanation=inc["explanation"])
        if not self.explain_async:
            return

        inc["explain_seq"] = seq = inc.get("explain_seq", 0) + 1

        def work():  # off the hot path: the control loop never waits for the LLM
            text = explain_incident(facts)
            if inc["explain_seq"] != seq:  # a newer explanation was requested; drop this stale one
                return
            inc["explanation"] = text
            self.store.update_incident(inc["id"], explanation=text)

        threading.Thread(target=work, daemon=True).start()

    # -- dashboard view ------------------------------------------------------
    def snapshot(self) -> dict:
        with self.lock:
            f, v, c = self.last_features, self.last_verdict, self.last_classification
            inc = self.incident
            last_inc = self.store.incidents(1)
            return {
                "t": self.t,
                "history": list(self.history),
                "stage": self.controller.stage,
                "anomalous": bool(v and v.anomalous),
                "votes": v.votes if v else {},
                "classification": c.label if c else None,
                "kind": c.kind if c else None,
                "malicious": bool(c and c.malicious),
                "incident": None if inc is None else {
                    "id": inc["id"], "label": inc["label"], "malicious": inc["malicious"],
                    "since": self.t - inc["start"], "detect_s": inc["detect_s"], "mitigate_s": inc["mitigate_s"],
                    "escalated": inc["escalated"]},
                "features": None if f is None else {
                    "pps": round(f.pps), "gbps": round(f.bps / 1e9, 3), "syn_ack_ratio": round(f.syn_ack_ratio, 2),
                    "amp_share": round(f.amp_share, 3), "udp_share": round(f.udp_share, 3),
                    "unique_sources": f.unique_sources, "new_source_share": round(f.new_source_share, 3),
                    "src_entropy": round(f.src_entropy, 2), "top_talkers": f.top_talkers,
                },
                "rules": [{"id": r.id, "rule": r.describe(), "mode": r.mode, "expires_in": r.expires_at - self.t,
                           "hits": round(r.hits)} for r in self.controller.rules.values()],
                "upstream": [{"id": r.id, "rule": r.describe(), "expires_in": r.expires_at - self.t}
                             for r in self.controller.upstream_rules.values()],
                "explanation": (inc or {}).get("explanation") or (last_inc[0]["explanation"] if last_inc else None),
                "events": self.store.recent_events(25),
                "active_scenarios": [a.kind for a in self.sim.active(self.t)],
                "trusted_sources": len(self.trusted),
                "llm": backend_label(),
            }
