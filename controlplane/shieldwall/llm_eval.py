"""LLM evaluation: is the assistant correct, fast and cheap enough?

For a set of real incidents produced by the engine, we send the exact production
prompt to the model and score every answer automatically:

  grounding  - every number the model writes must match a number in the facts it was
               given (within 5%, so "over 213,000" for 213,661 counts). A number with no
               match is a hallucination.
  label      - an attack explanation must name the right attack; a legitimate surge
               must be described as real players, never as blocked.
  chat       - questions over the SQL event log must contain the expected answer.
  latency, tokens and cost per call.

    shieldwall llm-eval        (needs OPENAI_API_KEY; ~20 calls, well under one cent)
"""
from __future__ import annotations

import collections
import json
import os
import re
import statistics
import time

from .engine import Engine
from .llm import FIELD_GUIDE, SYSTEM, chat_prompt, incident_prompt
from .simulator import SimConfig

PRICE_IN, PRICE_OUT = 0.15, 0.60  # gpt-4o-mini, USD per million tokens
CASES = ["cldap", "dns", "ntp", "syn", "udp", "flash_crowd", "mega_cldap"]
LABEL_WORDS = {"cldap": ["cldap"], "dns": ["dns"], "ntp": ["ntp"], "syn": ["syn"], "udp": ["udp"],
               "mega_cldap": ["cldap"]}
NUM = re.compile(r"(?<![\w.])(\d{1,3}(?:,\d{3})+|\d+)(?:\.(\d+))?")


def numbers_in(text: str) -> list[float]:
    out = []
    for m in NUM.finditer(text):
        whole = m.group(1).replace(",", "")
        out.append(float(f"{whole}.{m.group(2)}" if m.group(2) else whole))
    return out


def fact_numbers(obj) -> list[float]:
    if isinstance(obj, bool) or obj is None:
        return []
    if isinstance(obj, (int, float)):
        return [float(obj)]
    if isinstance(obj, str):
        return numbers_in(obj)
    if isinstance(obj, dict):
        return [n for v in obj.values() for n in fact_numbers(v)]
    if isinstance(obj, (list, tuple)):
        return [n for v in obj for n in fact_numbers(v)]
    return []


def grounded(n: float, facts: list[float]) -> bool:
    return any(abs(n - f) <= max(0.05 * abs(f), 0.5) for f in facts)


def call(prompt: str) -> tuple[str, dict]:
    from openai import OpenAI

    client = OpenAI(timeout=30)
    t0 = time.perf_counter()
    r = client.chat.completions.create(
        model=os.environ.get("SHIELDWALL_OPENAI_MODEL", "gpt-4o-mini"),
        max_tokens=300,
        temperature=0.3,
        messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": prompt}],
    )
    return (r.choices[0].message.content or "").strip(), {
        "latency_s": time.perf_counter() - t0,
        "tokens_in": r.usage.prompt_tokens,
        "tokens_out": r.usage.completion_tokens,
    }


JUDGE_SCHEMA = {
    "type": "object", "additionalProperties": False, "required": ["claims"],
    "properties": {"claims": {"type": "array", "items": {
        "type": "object", "additionalProperties": False, "required": ["claim", "verdict"],
        "properties": {"claim": {"type": "string"},
                       "verdict": {"type": "string", "enum": ["supported", "misattributed", "unsupported"]}}}}},
}


def judge(facts: dict, text: str) -> tuple[list[dict], dict]:
    """LLM-as-judge: is every claim backed by the facts, with the right meaning?"""
    from openai import OpenAI

    client = OpenAI(timeout=60)
    r = client.chat.completions.create(
        model=os.environ.get("SHIELDWALL_OPENAI_MODEL", "gpt-4o-mini"), temperature=0, max_tokens=700,
        response_format={"type": "json_schema", "json_schema": {"name": "judge", "strict": True, "schema": JUDGE_SCHEMA}},
        messages=[
            {"role": "system", "content": "You are a strict fact-checker. Split the explanation into its factual claims. "
                                          "Label each: supported (the facts say this, with this meaning), misattributed "
                                          "(uses a real number or fact but with the wrong meaning), or unsupported "
                                          "(not in the facts). Generic reassurance like 'no action needed' counts as "
                                          "supported only if the facts imply it."},
            {"role": "user", "content": f"{FIELD_GUIDE}\nFacts (JSON): {json.dumps(facts, default=str)}\n\nExplanation: {text}"},
        ],
    )
    return json.loads(r.choices[0].message.content)["claims"], {
        "tokens_in": r.usage.prompt_tokens, "tokens_out": r.usage.completion_tokens}


def incident_facts(preset: str, seed: int) -> dict | None:
    """Run one scenario through the engine and capture the final facts the LLM is given."""
    eng = Engine(sim_cfg=SimConfig(seed=seed), explain_async=False)
    captured = []
    original = eng._explain
    eng._explain = lambda inc: (captured.append(eng._facts(inc)), original(inc))
    eng.launch(preset, duration=40, start=40)
    for _ in range(140):
        eng.step()
    return captured[-1] if captured else None  # a gentle surge may never raise an incident


def main(out_path: str | None = None, seed_offset: int = 0) -> dict:
    if not os.environ.get("OPENAI_API_KEY"):
        raise SystemExit("llm-eval needs OPENAI_API_KEY")
    os.environ["SHIELDWALL_LLM"] = "openai"  # the report/suggestion step must use the model being evaluated
    rows = []
    for seed, preset in enumerate(CASES * 2, start=1 + seed_offset):
        facts = incident_facts(preset, seed)
        if facts is None:
            continue
        text, usage = call(incident_prompt(facts))
        nums = numbers_in(text)
        allowed = fact_numbers(facts)
        bad = [n for n in nums if not grounded(n, allowed)]
        low = text.lower()
        if preset == "flash_crowd":
            label_ok = any(w in low for w in ("legitimate", "real player", "genuine")) and "blocked" not in low
        else:
            label_ok = any(w in low for w in LABEL_WORDS[preset])
        claims, judge_usage = judge(facts, text)
        rows.append({"case": preset, "text": text, "numbers": len(nums), "ungrounded": bad,
                     "label_ok": label_ok, "claims": claims, "judge_usage": judge_usage, **usage})

    # chat over the event log: two attacks, then three questions with known answers
    eng = Engine(sim_cfg=SimConfig(seed=99 + seed_offset), explain_async=False)
    eng.launch("cldap", duration=30, start=40)
    eng.launch("syn", duration=30, start=150)
    for _ in range(260):
        eng.step()
    questions = [
        ("Why did you block port 389?", lambda a: "389" in a or "cldap" in a.lower()),
        ("What attacks happened?", lambda a: "cldap" in a.lower() and "syn" in a.lower()),
        ("How many attacks were there?", lambda a: bool(re.search(r"\b(2|two)\b", a.lower()))),
    ]
    chats = []
    for q, check in questions:
        answer, usage = call(chat_prompt(q, eng.store))
        chats.append({"question": q, "answer": answer, "correct": check(answer), **usage})

    # LLM rule suggestions, checked by the controller
    from .llm_report import incident_report
    suggestions = []
    for seed, preset in enumerate(["cldap", "dns", "syn", "udp", "mega_cldap"], start=200 + seed_offset):
        e = Engine(sim_cfg=SimConfig(seed=seed), explain_async=False)
        e.launch(preset, duration=40, start=40)
        for _ in range(60):
            e.step()
        rep = incident_report(e)
        for sug in rep.get("suggestions", []):
            suggestions.append({"case": preset, **sug})
        chats.append({"question": f"[report] {preset}", "answer": rep.get("markdown", ""), "correct": True,
                      "latency_s": 0.0, **rep.get("usage", {"tokens_in": 0, "tokens_out": 0})})

    calls = rows + chats
    total_nums = sum(r["numbers"] for r in rows)
    total_bad = sum(len(r["ungrounded"]) for r in rows)
    lat = sorted(c["latency_s"] for c in calls if not str(c.get("question", "")).startswith("[report]"))
    cost = sum(c["tokens_in"] * PRICE_IN + c["tokens_out"] * PRICE_OUT for c in calls) / 1e6
    expl_cost = [(r["tokens_in"] * PRICE_IN + r["tokens_out"] * PRICE_OUT) / 1e6 for r in rows]
    real_chats = [c for c in chats if not c["question"].startswith("[report]")]
    all_claims = [c for r in rows for c in r["claims"]]
    verdicts = collections.Counter(c["verdict"] for c in all_claims)
    judge_cost = sum(r["judge_usage"]["tokens_in"] * PRICE_IN + r["judge_usage"]["tokens_out"] * PRICE_OUT for r in rows) / 1e6
    accepted = [x for x in suggestions if x["accepted"]]
    summary = {
        "claims_checked": len(all_claims),
        "claims_supported": verdicts["supported"] / len(all_claims) if all_claims else 1.0,
        "claims_misattributed": verdicts["misattributed"],
        "claims_unsupported": verdicts["unsupported"],
        "fully_faithful": sum(all(c["verdict"] == "supported" for c in r["claims"]) for r in rows) / len(rows),
        "suggestions": len(suggestions),
        "suggestions_accepted": len(accepted),
        "suggestion_reject_reasons": dict(collections.Counter(x["verdict"].split(":")[1].strip().split(" (")[0]
                                                              if ":" in x["verdict"] else x["verdict"]
                                                              for x in suggestions if not x["accepted"])),
        "model": os.environ.get("SHIELDWALL_OPENAI_MODEL", "gpt-4o-mini"),
        "explanations": len(rows),
        "numeric_grounding": 1 - total_bad / total_nums if total_nums else 1.0,
        "numbers_checked": total_nums,
        "hallucinated_numbers": total_bad,
        "fully_grounded": sum(not r["ungrounded"] for r in rows) / len(rows),
        "label_accuracy": sum(r["label_ok"] for r in rows) / len(rows),
        "chat_accuracy": sum(c["correct"] for c in real_chats) / len(real_chats),
        "latency_median_s": statistics.median(lat),
        "latency_p95_s": lat[min(len(lat) - 1, int(0.95 * len(lat)))],
        "tokens_in_avg": statistics.mean(c["tokens_in"] for c in calls),
        "tokens_out_avg": statistics.mean(c["tokens_out"] for c in calls),
        "cost_per_explanation_usd": statistics.mean(expl_cost),
        "total_cost_usd": cost + judge_cost,
    }
    report = {"summary": summary, "explanations": rows, "chat": [c for c in chats if not c["question"].startswith("[report]")],
              "suggestions": suggestions}

    lines = [
        f"# LLM evaluation ({summary['model']})",
        "",
        f"{len(rows)} incident explanations from real engine runs + {len(chats)} chat questions over the event log, "
        "using the exact production prompts. Reproduce with `shieldwall llm-eval`.",
        "",
        "| Metric | Result |",
        "|---|---|",
        f"| Numeric grounding (numbers that match the facts) | {summary['numeric_grounding']:.1%} "
        f"({total_nums - total_bad}/{total_nums}) |",
        f"| Explanations with zero hallucinated numbers | {summary['fully_grounded']:.0%} |",
        f"| Names the correct attack / calls a surge legitimate | {summary['label_accuracy']:.0%} |",
        f"| Chat answers correct | {summary['chat_accuracy']:.0%} |",
        f"| Claims judged supported, with the right meaning (LLM-as-judge) | {summary['claims_supported']:.0%} "
        f"({verdicts['supported']}/{len(all_claims)}; misattributed {verdicts['misattributed']}, unsupported {verdicts['unsupported']}) |",
        f"| Explanations where every claim is supported | {summary['fully_faithful']:.0%} |",
        f"| Rule suggestions accepted by the controller | {len(accepted)}/{len(suggestions)} (all accepted ones start in dry-run) |",
        f"| Latency median / p95 | {summary['latency_median_s']:.1f} s / {summary['latency_p95_s']:.1f} s |",
        f"| Tokens per call (in / out) | {summary['tokens_in_avg']:.0f} / {summary['tokens_out_avg']:.0f} |",
        f"| Cost per explanation | ${summary['cost_per_explanation_usd']:.5f} |",
        f"| Total cost of this evaluation | ${summary['total_cost_usd']:.4f} |",
        "",
        "## Sample answers",
        "",
        *[f"- **{r['case']}**: {r['text']}" + (f" _(ungrounded: {r['ungrounded']})_" if r["ungrounded"] else "")
          for r in rows[: len(CASES)]],
        "",
        *[f"- **Q: {c['question']}** {c['answer']}" for c in chats],
        "",
    ]
    md = "\n".join(lines)
    print(md)
    if out_path:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as fh:
            fh.write(md)
        with open(os.path.splitext(out_path)[0] + ".json", "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
    return report


if __name__ == "__main__":
    main()
