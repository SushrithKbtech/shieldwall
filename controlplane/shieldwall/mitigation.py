"""Step 3 of the control loop: close the loop. Block, then undo, automatically.

Graduated response: observe -> rate-limit -> drop -> escalate upstream.
Every rule expires (~60 s) and is renewed only while it is still matching traffic.
Safety: allowlist (never drop known-good), rule cap, and dry-run mode.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .classifier import Classification
from .models import TCP, UDP, Features, Rule


@dataclass
class MitigationConfig:
    rule_ttl: int = 60
    max_rules: int = 64
    dry_run: bool = False
    allowlist: list[str] = field(default_factory=lambda: ["10.0.0.0/8"])  # admin / monitoring
    escalate_after: int = 3        # windows of link saturation before asking upstream for help
    link_saturation: float = 0.95  # fraction of link capacity that counts as "full"
    renew_min_hits: float = 1.0


@dataclass
class Action:
    kind: str      # "rule_added" | "rule_renewed" | "rule_expired" | "escalated" | "withdrawn" | "observe"
    detail: str
    rule: Rule | None = None


class MitigationController:
    def __init__(self, cfg: MitigationConfig | None = None, link_bps: float | None = None):
        self.cfg = cfg or MitigationConfig()
        self.link_bps = link_bps
        self.rules: dict[int, Rule] = {}
        self.upstream_rules: dict[int, Rule] = {}
        self._next_id = 1
        self._saturated = 0
        self.stage = "observe"

    # -- rule construction -------------------------------------------------
    def _rules_for(self, c: Classification, f: Features, baseline_pps: float, t: int) -> list[Rule]:
        exp = t + self.cfg.rule_ttl
        mode = "dry-run" if self.cfg.dry_run else "enforce"
        if c.kind.endswith("_amplification") and f.amp_port:
            # Clean fingerprint -> precise signature drop. Real players never match it.
            return [Rule(0, "drop", UDP, sport=f.amp_port, expires_at=exp, mode=mode,
                         reason=f"{c.label}: signature drop")]
        if c.kind == "syn_flood":
            # Unknown sources may still open connections, but only at a sane rate.
            return [Rule(0, "rate_limit", TCP, syn_only=True, untrusted_only=True,
                         rate_pps=max(200.0, baseline_pps * 0.05), expires_at=exp, mode=mode,
                         reason=f"{c.label}: token-bucket on new connections")]
        if c.kind == "udp_flood":
            return [Rule(0, "rate_limit", UDP, untrusted_only=True,
                         rate_pps=max(500.0, baseline_pps * 0.3), expires_at=exp, mode=mode,
                         reason=f"{c.label}: token-bucket on unknown UDP sources")]
        return []

    def _same(self, a: Rule, b: Rule) -> bool:
        return (a.action, a.proto, a.sport, a.dport, a.syn_only, a.untrusted_only) == (
            b.action, b.proto, b.sport, b.dport, b.syn_only, b.untrusted_only)

    # -- main step ---------------------------------------------------------
    def step(self, t: int, anomalous: bool, c: Classification | None, f: Features,
             baseline_pps: float, rule_hits: dict[int, float],
             upstream_hits: dict[int, float]) -> list[Action]:
        actions: list[Action] = []

        for rid, hits in rule_hits.items():
            if rid in self.rules:
                self.rules[rid].hits += hits

        # 1. add or renew rules for a confirmed, classified attack
        if anomalous and c and c.malicious:
            for want in self._rules_for(c, f, baseline_pps, t):
                existing = next((r for r in self.rules.values() if self._same(r, want)), None)
                if existing:
                    existing.expires_at = t + self.cfg.rule_ttl
                    continue
                if len(self.rules) >= self.cfg.max_rules:
                    actions.append(Action("observe", "rule cap reached; not adding more rules"))
                    continue
                want.id = self._next_id
                self._next_id += 1
                self.rules[want.id] = want
                actions.append(Action("rule_added", want.describe(), want))
            self.stage = "drop" if any(r.action == "drop" for r in self.rules.values()) else "rate_limit"
        elif anomalous and c:
            self.stage = "observe"
            # Only report "observe" once per incident; the engine dedupes.

        # 2. renew rules still matching traffic; expire the rest
        for rid, rule in list(self.rules.items()):
            if rule_hits.get(rid, 0.0) >= self.cfg.renew_min_hits and rule.expires_at - t < self.cfg.rule_ttl:
                rule.expires_at = t + self.cfg.rule_ttl
            if t >= rule.expires_at:
                del self.rules[rid]
                actions.append(Action("rule_expired", rule.describe(), rule))

        # 3. escalate upstream if the link itself is full (no local tool can fix that)
        if self.link_bps and f.bps >= self.cfg.link_saturation * self.link_bps:
            self._saturated += 1
        else:
            self._saturated = 0
        if self._saturated >= self.cfg.escalate_after:
            for rule in self.rules.values():
                if rule.action == "drop" and rule.id not in self.upstream_rules and rule.mode == "enforce":
                    up = Rule(**{**rule.__dict__})
                    up.expires_at = t + self.cfg.rule_ttl * 5
                    self.upstream_rules[rule.id] = up
                    self.stage = "escalate"
                    actions.append(Action("escalated", f"BGP FlowSpec to upstream: {rule.describe()}", up))

        for rid, up in list(self.upstream_rules.items()):
            if upstream_hits.get(rid, 0.0) >= self.cfg.renew_min_hits:
                up.expires_at = max(up.expires_at, t + self.cfg.rule_ttl)
            if t >= up.expires_at:
                del self.upstream_rules[rid]
                actions.append(Action("withdrawn", f"FlowSpec withdrawn: {up.describe()}", up))

        if not self.rules and not self.upstream_rules and not anomalous:
            self.stage = "observe"
        return actions

    def enforced_rules(self) -> list[Rule]:
        return [r for r in self.rules.values() if r.mode == "enforce"]
