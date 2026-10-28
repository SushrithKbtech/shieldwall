"""Tier 3 evaluation: hand the analyst attacks no tier could name, and score what it proposes.

For each attack (real captures, CIC-DDoS2019 files and simulated families) the fingerprints
and the ML tier are both made to come up empty, so the anomaly reaches the analyst exactly as
a real residual would, with nothing but the traffic evidence to go on.
The same incident is then given to both backends:

  * gpt-4o-mini through the production analyst prompt (needs OPENAI_API_KEY),
  * the offline evidence-driven heuristic,

and every proposal goes through the controller's own checks (validate_suggestion). We
report how many are accepted, how much of the attack and of normal player traffic the
proposed rule would match, latency and cost.

    shieldwall analyst-eval --captures DIR --heldout DIR --cic archive.zip --cic-member 01-12/Syn.csv
"""
from __future__ import annotations

import copy
import glob
import json
import os
import statistics

from .analyst import ANALYST_SYSTEM, _heuristic, _parse_rule, _prompt
from .mitigation import _share, suggestion_to_rule, validate_suggestion
from .ml import MLVerdict

PRICE_IN, PRICE_OUT = 0.15, 0.60  # gpt-4o-mini, USD per million tokens
SIM_FAMILIES = ["synack", "udp", "syn", "cldap", "ntp"]


def _unnamed():
    from .classifier import Classification
    return Classification("unknown", "unclassified anomaly", False, 0.4,
                          ["volume is anomalous but no known fingerprint matches"])


class _UnsureML:
    def predict(self, f):
        return MLVerdict("udp_flood", 0.3, True, {"udp_flood": 0.3})


def _residual_engine(sim=None, preset: str | None = None, attack_at: int = 35):
    """Run until the analyst would be called: three seconds into the attack, nothing named it."""
    from .engine import Engine
    from .mitigation import MitigationConfig

    eng = Engine(sim=sim, mit_cfg=MitigationConfig(), explain_async=False)
    # nobody can name it: no fingerprint (even for attacks one would catch) and an unsure model
    named = eng.classifier.fp.classify
    eng.classifier.fp.classify = lambda f: _unnamed() if named(f).malicious else named(f)
    eng.classifier.ml = _UnsureML()
    eng._investigate = lambda inc, c: None  # we call each backend ourselves, on the same incident
    if preset:
        eng.launch(preset, duration=30, start=attack_at)
    for _ in range(attack_at + 3):
        eng.step()
    return eng


def _score(eng, suggestion: dict | None) -> dict:
    if suggestion is None:
        return {"rule": None, "accepted": False, "verdict": "no usable rule in the reply"}
    ctl = copy.deepcopy(eng.controller)
    out = validate_suggestion(suggestion, ctl, eng.attack_sample, eng.calm_sample, set(eng.trusted), eng.t)
    try:
        rule = suggestion_to_rule(suggestion)
        out["attack_share"] = _share(rule, eng.attack_sample, set(eng.trusted))
        out["player_share"] = _share(rule, eng.calm_sample, set(eng.trusted))
    except (ValueError, TypeError):
        out["attack_share"] = out["player_share"] = None
    return out


def evaluate(name: str, eng, use_llm: bool) -> dict:
    inc = eng.incident or {}
    evidence, profile = list(inc.get("evidence", [])), inc.get("profile", {})
    row = {"attack": name, "heuristic": _score(eng, _heuristic(profile))}
    if use_llm:
        from .llm_eval import call

        text, usage = call(f"{ANALYST_SYSTEM}\n\n{_prompt(evidence, profile)}")
        row["llm"] = {**_score(eng, _parse_rule(text)), **usage, "reply": text}
    return row


def _scenarios(captures: list[str], cic: str | None, members: list[str]):
    from .replay import ReplaySim, load_capture
    from .simulator import SimConfig

    for fam in SIM_FAMILIES:
        yield f"simulated {fam}", lambda fam=fam: _residual_engine(preset=fam)
    for d in captures:
        for path in sorted(glob.glob(os.path.join(d, "*.pcap*"))):
            def build(path=path):
                pkts, _ = load_capture(path)
                return _residual_engine(sim=ReplaySim(SimConfig(seed=7), pkts, 35, 30))
            yield os.path.basename(path), build
    if cic:
        from .cic import load_cic
        for m in members:
            def build(m=m):
                pkts, rate, _ = load_cic(cic, m)
                return _residual_engine(sim=ReplaySim(SimConfig(seed=7), pkts, 35, 30, 1.0, rate))
            yield f"CIC-DDoS2019 {m}", build


def _cell(r: dict) -> str:
    if not r.get("rule"):
        return f"no rule ({r['verdict']})"
    mark = "**accepted**" if r["accepted"] else r["verdict"]
    share = "" if r.get("attack_share") is None else \
        f"; matches {r['attack_share']:.0%} of attack, {r['player_share']:.1%} of players"
    return f"`{r['rule']}`: {mark}{share}"


def main(out_dir: str = "results", captures: list[str] | None = None, cic: str | None = None,
         members: list[str] | None = None) -> dict:
    os.environ["SHIELDWALL_LLM"] = "template"  # incident explanations are not what is being tested here
    use_llm = bool(os.environ.get("OPENAI_API_KEY"))
    rows = []
    for name, build in _scenarios(captures or [], cic, members or []):
        eng = build()
        if eng.incident is None:
            rows.append({"attack": name, "skipped": "not flagged by Tier 1 (below the alert floor)"})
        else:
            rows.append(evaluate(name, eng, use_llm))
        print(name, "->", json.dumps({k: (v.get("verdict") if isinstance(v, dict) else v)
                                      for k, v in rows[-1].items() if k != "attack"}))

    done = [r for r in rows if "skipped" not in r]

    def summary(key: str) -> dict:
        rs = [r[key] for r in done if key in r]
        acc = [r for r in rs if r["accepted"]]
        out = {"incidents": len(rs), "accepted": len(acc),
               "attack_share_accepted": statistics.mean([r["attack_share"] for r in acc]) if acc else 0.0,
               "player_share_accepted": max([r["player_share"] for r in acc], default=0.0)}
        if rs and "latency_s" in rs[0]:
            out["latency_median_s"] = statistics.median(r["latency_s"] for r in rs)
            out["cost_per_proposal_usd"] = statistics.mean(
                (r["tokens_in"] * PRICE_IN + r["tokens_out"] * PRICE_OUT) / 1e6 for r in rs)
        return out

    result = {"summary": {"heuristic": summary("heuristic"), **({"llm": summary("llm")} if use_llm else {})},
              "rows": rows}
    H, Lm = result["summary"]["heuristic"], result["summary"].get("llm")
    lines = ["# Tier 3: the analyst on attacks no tier could name", "",
             "Each attack is replayed with the fingerprints and the ML tier made to come up empty, so it reaches "
             "the analyst the way a real residual would, with only the traffic evidence to go on. Both backends get the same incident, and every proposal goes through the "
             "controller's checks: not too broad, no drop on the game ports, under 1% of normal player traffic, "
             "at least 5% of the attack. Accepted rules are installed in dry-run only.", "",
             "| | Proposals accepted by the controller | Attack matched by accepted rules (mean) "
             "| Worst player traffic hit by an accepted rule |" + (" Median latency | Cost per proposal |" if Lm else ""),
             "|---|---|---|---|" + ("---|---|" if Lm else "")]
    v1_path = os.path.join(out_dir, "analyst_eval_prompt_v1.json")
    V1 = json.load(open(v1_path, encoding="utf-8"))["summary"].get("llm") if os.path.exists(v1_path) else None
    for label, S in (("Offline heuristic", H), ("gpt-4o-mini, prompt v1 (no field guide)", V1), ("gpt-4o-mini", Lm)):
        if S:
            lines.append(f"| {label} | **{S['accepted']}/{S['incidents']}** | {S['attack_share_accepted']:.0%} | "
                         f"{S['player_share_accepted']:.2%} |" + (
                             f" {S['latency_median_s']:.1f} s | ${S['cost_per_proposal_usd']:.5f} |"
                             if "latency_median_s" in S else (" - | - |" if Lm else "")))
    if V1:
        lines += ["", "Prompt v1 gave the model the profile without saying what its fields mean. It put `syn_only` on UDP "
                  "rules, picked UDP for TCP floods, ignored the SYN-ACK share and wrote the text \"null\" for empty "
                  "fields. The final prompt adds a field guide (`PROFILE_GUIDE` in analyst.py) and the protocol of each "
                  "top port; the controller now also reads \"null\" text as an empty field. Both prompts were scored "
                  "on the same incidents, so the final row is not a held-out number. "
                  "[Prompt v1 report](analyst_eval_prompt_v1.md)."]
    lines += ["", "| Attack | Heuristic proposal | " + ("gpt-4o-mini proposal |" if Lm else ""),
              "|---|---|" + ("---|" if Lm else "")]
    for r in rows:
        if "skipped" in r:
            lines.append(f"| {r['attack']} | {r['skipped']} |" + (" |" if Lm else ""))
        else:
            lines.append(f"| {r['attack']} | {_cell(r['heuristic'])} |" + (f" {_cell(r['llm'])} |" if Lm else ""))
    lines.append("")
    md = "\n".join(lines)
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "analyst_eval.md"), "w", encoding="utf-8") as fh:
        fh.write(md)
    with open(os.path.join(out_dir, "analyst_eval.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, default=str)
    print(md)
    return result
