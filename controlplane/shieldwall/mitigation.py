"""Step 3 of the control loop: close the loop. Block, then undo, automatically.

Graduated response: observe -> rate-limit -> drop -> escalate upstream.
Every rule expires (~60 s) and is renewed only while it is still matching traffic.
Safety: allowlist (never drop known-good), rule cap, and dry-run mode.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .classifier import Classification
from .models import TCP, UDP, Features, Rule, ip_int


@dataclass
class MitigationConfig:
    rule_ttl: int = 60
    max_rules: int = 64
    dry_run: bool = False
    allowlist: list[str] = field(default_factory=lambda: ["10.0.0.0/8"])  # admin / monitoring
    escalate_after: int = 3        # windows of link saturation before asking upstream for help
    link_saturation: float = 0.95  # fraction of link capacity that counts as "full"
    renew_min_hits: float = 1.0
    service_ports: tuple[int, ...] = (25565, 19132)  # the protected game's ports (Minecraft Java / Bedrock)


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
        rules = self._fingerprint_rules(c, f, baseline_pps, t)
        # Not for amplification: port rules already stop reflected traffic, and the biggest reflector is
        # often a public resolver (8.8.8.8 in a real capture) that the server itself relies on.
        if (f.top_src is not None and f.top_src_new and f.top_share >= 0.3
                and not c.kind.endswith("_amplification")):
            # Heavy hitter: one never-seen address sends a big share of an attack. If its traffic mostly goes to
            # the game's own ports it may be many players behind one shared address (a campus or mobile network),
            # so it is rate-limited to a fair share instead of blocked; otherwise just that address is dropped.
            shared = f.top_src_to_service >= 0.5
            rules.append(Rule(0, "rate_limit" if shared else "drop", 0, src=f.top_src, src_mask=0xFFFFFFFF,
                              rate_pps=max(500.0, baseline_pps) if shared else 0.0, expires_at=t + self.cfg.rule_ttl,
                              mode="dry-run" if self.cfg.dry_run else "enforce",
                              reason=f"{c.label}: heavy hitter sending {f.top_share:.0%} of traffic"
                                     + (" (possible shared address, rate-limited)" if shared else "")))
        return rules

    def _fingerprint_rules(self, c: Classification, f: Features, baseline_pps: float, t: int) -> list[Rule]:
        exp = t + self.cfg.rule_ttl
        mode = "dry-run" if self.cfg.dry_run else "enforce"
        if c.kind.endswith("_amplification") and f.amp_port:
            # Clean fingerprint -> precise signature drop per reflected service port (all vectors of a
            # multi-vector attack). Real players never match it.
            # every reflection port present, even small ones: the server never uses these services
            rules = [Rule(0, "drop", UDP, sport=port, expires_at=exp, mode=mode, reason=f"{c.label}: signature drop")
                     for port in (f.amp_ports_seen or f.amp_ports or [f.amp_port])]
            if f.frag_share >= 0.05:
                # Fragments of oversized replies carry no ports; drop those from unknown sources too.
                rules.append(Rule(0, "drop", UDP, frag_only=True, untrusted_only=True, expires_at=exp, mode=mode,
                                  reason=f"{c.label}: fragments of reflected replies"))
            return rules
        if c.kind == "syn_flood":
            # Unknown sources may still open connections, but only at a sane rate.
            return [Rule(0, "rate_limit", TCP, syn_only=True, untrusted_only=True,
                         rate_pps=max(100.0, baseline_pps * 0.02), expires_at=exp, mode=mode,
                         reason=f"{c.label}: token-bucket on new connections")]
        if c.kind == "udp_flood":
            return [Rule(0, "rate_limit", UDP, untrusted_only=True,
                         rate_pps=max(500.0, baseline_pps * 0.3), expires_at=exp, mode=mode,
                         reason=f"{c.label}: token-bucket on unknown UDP sources")]
        return []

    def _same(self, a: Rule, b: Rule) -> bool:
        return (a.action, a.proto, a.sport, a.dport, a.syn_only, a.untrusted_only, a.frag_only, a.src, a.src_mask) == (
            b.action, b.proto, b.sport, b.dport, b.syn_only, b.untrusted_only, b.frag_only, b.src, b.src_mask)

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


# -- validating rules suggested by the LLM -------------------------------------
# The LLM may propose rules, but only the controller decides. A suggestion is turned
# into a Rule and tested against real traffic samples before it is ever installed,
# and accepted rules start in dry-run (they log what they would drop, nothing more).

MAX_PLAYER_HIT = 0.01   # may touch at most 1% of recent normal traffic
MIN_ATTACK_HIT = 0.05   # must match at least 5% of the attack traffic


def suggestion_to_rule(s: dict) -> Rule:
    proto = {"udp": UDP, "tcp": TCP, "any": 0}.get(str(s.get("protocol", "")).lower())
    action = s.get("action")
    if proto is None or action not in ("drop", "rate_limit"):
        raise ValueError("unknown protocol or action")
    src = ip_int(s["source_ip"]) if s.get("source_ip") else 0
    ports = [s.get("src_port") or 0, s.get("dst_port") or 0]
    if any(not isinstance(p, int) or not 0 <= p <= 65535 for p in ports):
        raise ValueError("ports must be 0-65535")
    rate = float(s.get("rate_pps") or 0)
    if action == "rate_limit" and not 1 <= rate <= 1_000_000:
        raise ValueError("a rate limit needs rate_pps between 1 and 1,000,000")
    return Rule(0, action, proto, sport=ports[0], dport=ports[1], syn_only=bool(s.get("syn_only")),
                src=src, src_mask=0xFFFFFFFF if src else 0,
                untrusted_only=bool(s.get("unknown_sources_only")), frag_only=bool(s.get("fragments_only")),
                rate_pps=rate, reason=str(s.get("reason", ""))[:200])


def _share(rule: Rule, samples: list, trusted: set[int]) -> float:
    total = sum(p.w for p in samples)
    return sum(p.w for p in samples if rule.matches(p, trusted)) / total if total else 0.0


def validate_suggestion(s: dict, controller: "MitigationController", attack_sample: list, calm_sample: list,
                        trusted: set[int], t: int) -> dict:
    """Return {"rule", "accepted", "verdict"}; install accepted rules in dry-run."""
    try:
        rule = suggestion_to_rule(s)
    except (ValueError, TypeError) as e:
        return {"rule": str(s), "accepted": False, "verdict": f"rejected: {e}"}
    out = {"rule": rule.describe(), "accepted": False, "llm_reason": rule.reason}
    if not (rule.sport or rule.dport or rule.syn_only or rule.frag_only or rule.untrusted_only or rule.src_mask):
        out["verdict"] = "rejected: too broad (would match every packet of that protocol)"
        return out
    if rule.action == "drop" and rule.dport in controller.cfg.service_ports:
        out["verdict"] = (f"rejected: a drop on game port {rule.dport} would lock out new players joining; "
                          "only a rate limit is allowed there")
        return out
    if any(controller._same(rule, r) for r in controller.rules.values()):
        out["verdict"] = "rejected: already in place"
        return out
    players = _share(rule, calm_sample, trusted)
    if players > MAX_PLAYER_HIT:
        out["verdict"] = f"rejected: would hit {players:.1%} of normal player traffic"
        return out
    attack = _share(rule, attack_sample, trusted)
    if attack < MIN_ATTACK_HIT:
        out["verdict"] = f"rejected: matches only {attack:.1%} of the attack traffic"
        return out
    if len(controller.rules) >= controller.cfg.max_rules:
        out["verdict"] = "rejected: rule cap reached"
        return out
    rule.id = controller._next_id
    controller._next_id += 1
    rule.mode, rule.expires_at = "dry-run", t + controller.cfg.rule_ttl
    rule.reason = f"suggested by LLM, validated: {rule.reason}"
    controller.rules[rule.id] = rule
    out.update(accepted=True, verdict=f"accepted in dry-run: matches {attack:.0%} of the attack, "
                                      f"{players:.2%} of normal traffic")
    return out
