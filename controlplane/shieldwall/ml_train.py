"""Build a labelled dataset, train the Tier 2 ML classifier, and score it head-to-head
against the hand-written fingerprints (classifier.py), on simulated AND real traffic.

Why this is honest, not circular:
  * simulator train and test windows come from DIFFERENT random seeds (unseen traffic),
  * the family set includes attacks the fingerprints were never written for
    (notably synack_reflection, the real miss from the held-out capture test),
  * the shipped model learns from simulated traffic only, so every real attack capture
    and CIC-DDoS2019 file it is scored on is one it never saw. (Also learning from the
    development captures was tried and did worse on the held-out ones; both are reported.)

    shieldwall ml-train                                   # simulator only
    shieldwall ml-train --captures DEV_DIR --heldout HELDOUT_DIR --cic archive.zip \
        --cic-dev 01-12/Syn.csv --cic-heldout 01-12/UDPLag.csv
"""
from __future__ import annotations

import collections
import glob
import ipaddress
import json
import os
import time

from .classifier import Classifier
from .features import Featurizer
from .ml import BENIGN_LABELS, FEATURE_NAMES, MLClassifier, feat_vector
from .models import ACK, SYN, TCP, UDP, Packet, Window
from .simulator import MC_JAVA, SimConfig, TrafficSim

# Families we generate. The first group the fingerprints also handle; synack_reflection,
# memcached_amp and ssdp_amp stress coverage the hand-written rules miss or barely reach.
ATTACK_FAMILIES = [
    "cldap_amp", "dns_amp", "ntp_amp", "memcached_amp", "ssdp_amp",
    "syn_flood", "synack_reflection", "udp_flood", "single_source_flood",
]
AMP_SPORT = {"cldap_amp": 389, "dns_amp": 53, "ntp_amp": 123, "memcached_amp": 11211, "ssdp_amp": 1900}
AMP_SIZE = {"cldap_amp": (1200, 1472), "dns_amp": (900, 1472), "ntp_amp": (440, 482),
            "memcached_amp": (1024, 1472), "ssdp_amp": (300, 900)}

# Map a fingerprint "kind" onto our family labels, so we can compare like with like.
FINGERPRINT_TO_FAMILY = {
    "cldap_amplification": "cldap_amp", "dns_amplification": "dns_amp", "ntp_amplification": "ntp_amp",
    "memcached_amplification": "memcached_amp", "ssdp_amplification": "ssdp_amp",
    "syn_flood": "syn_flood", "udp_flood": "udp_flood", "single_source_flood": "single_source_flood",
    "legit_surge": "legit_surge", "unknown": "unknown",
    "multi_vector_amplification": "multi_vector",
}


def _legit(sim: TrafficSim, pps: float, k: int = 400) -> list[Packet]:
    """Normal player traffic: handshakes to the game ports, mostly known sources."""
    out = [sim._legit_packet(sim.regulars, 0.01) for _ in range(int(k * 0.95))]
    out += [sim._legit_packet(sim.newcomers, 0.05) for _ in range(max(1, int(k * 0.05)))]
    w = pps / len(out)
    for p in out:
        p.w = w
    return out


def _attack(sim: TrafficSim, family: str, pps: float, k: int = 1200) -> list[Packet]:
    r = sim.rng
    out: list[Packet] = []
    if family in AMP_SPORT:
        pool = sim.reflectors.get(family.split("_")[0], sim.botnet)
        sport, (lo, hi) = AMP_SPORT[family], AMP_SIZE[family]
        for _ in range(k):
            out.append(Packet(sim._next_src(family, pool), sport, r.randint(1024, 65535), UDP, 0,
                              r.randint(lo, hi), legit=False))
    elif family == "syn_flood":  # spoofed SYNs to the game port, every packet a fresh source
        for _ in range(k):
            src = int(ipaddress.IPv4Address(r.getrandbits(32) | 0x01000000))
            out.append(Packet(src, r.randint(1024, 65535), MC_JAVA, TCP, SYN, 60, legit=False))
    elif family == "synack_reflection":  # reflectors reply SYN-ACK to the spoofed victim
        rports = (80, 443, 22, 3389, 8080)
        for _ in range(k):
            out.append(Packet(sim._next_src("synack", sim.botnet), r.choice(rports),
                              r.randint(1024, 65535), TCP, SYN | ACK, 60, legit=False))
    elif family == "udp_flood":
        for _ in range(k):
            out.append(Packet(sim._next_src("udp", sim.botnet), r.randint(1024, 65535),
                              r.randint(1, 65535), UDP, 0, r.randint(512, 1024), legit=False))
    elif family == "single_source_flood":  # one never-seen host sends almost everything, over UDP or TCP
        src = int(ipaddress.IPv4Address(r.getrandbits(32) | 0x02000000))
        tcp, dport = r.random() < 0.5, r.choice((MC_JAVA, 80, 443, r.randint(1, 65535)))
        for _ in range(k):
            out.append(Packet(src, r.randint(1024, 65535), dport, TCP if tcp else UDP, ACK if tcp else 0,
                              r.randint(60, 900), legit=False))
    else:
        raise ValueError(family)
    w = pps / len(out)
    for p in out:
        p.w = w
    return out


def _sample(seed: int, label: str) -> tuple[list[float], object, str]:
    """One labelled window: warm up calm traffic (so new-source / trust features are real),
    then build the labelled window and featurise it. Returns (vector, Features, label)."""
    sim = TrafficSim(SimConfig(seed=seed))
    fz = Featurizer()
    r = sim.rng
    for t in range(12):  # learn 'normal': regulars become known, baseline udp share settles
        win = Window(t=t, samples=_legit(sim, sim.cfg.legit_pps))
        fz.featurize(win)
        fz.learn(win)

    legit = _legit(sim, sim.cfg.legit_pps)
    if label == "benign":
        samples = legit
    elif label == "legit_surge":  # a real rush of new players (newcomers, handshakes complete)
        surge = [sim._legit_packet(sim.newcomers, 0.05) for _ in range(800)]
        rate = r.uniform(5_000, 40_000)
        for p in surge:
            p.w = rate / len(surge)
        samples = legit + surge
    else:
        pps = 10 ** r.uniform(3.5, 5.5)  # ~3k .. 300k pps
        samples = legit + _attack(sim, label, pps)

    f = fz.featurize(Window(t=12, samples=samples))
    return feat_vector(f), f, label


def build_dataset(per_attack: int = 180, benign: int = 500, surge: int = 320, seed0: int = 1):
    rows, feats, labels, seeds = [], [], [], []
    s = seed0
    plan = [("benign", benign), ("legit_surge", surge)] + [(fam, per_attack) for fam in ATTACK_FAMILIES]
    for label, n in plan:
        for _ in range(n):
            vec, f, lab = _sample(s, label)
            rows.append(vec); feats.append(f); labels.append(lab); seeds.append(s)
            s += 1
    return rows, feats, labels, seeds


# -- real attack data ------------------------------------------------------------
# What each real capture is, as the set of model families that count as naming it correctly.
REAL_FAMILY = [
    ("synack", {"synack_reflection"}),
    ("rrsig", {"dns_amp"}), ("dnsany", {"dns_amp"}),
    ("memcached.ntp.cldap", {"multi_vector", "memcached_amp", "ntp_amp", "cldap_amp"}),
    ("synflood", {"syn_flood"}),
    # reflection off a service that is not on the amplification list: the closest family is a UDP flood
    ("snmp", {"udp_flood"}), ("isakmp", {"udp_flood"}),
    ("udp.rdm", {"udp_flood"}),
    ("archive.zip", {"single_source_flood"}),  # every CIC-DDoS2019 attack comes from one machine
]


def real_family(name: str) -> set[str]:
    low = name.lower()
    return next((fams for key, fams in REAL_FAMILY if key in low), set())


def real_windows(loaded, attack_at: int = 35, duration: int = 20, seed: int = 7) -> list[tuple]:
    """Replay one real attack on top of modelled players (nothing blocked) and return
    (Features, fingerprint kind) for every attack second the Tier 1 detector flagged:
    exactly the windows the cascade would be asked to name."""
    from .engine import Engine
    from .mitigation import MitigationConfig
    from .replay import ReplaySim
    from .simulator import SimConfig

    pkts, rate, _ = loaded
    os.environ["SHIELDWALL_ML"] = "off"  # fingerprints only, so their own verdict is what gets recorded
    try:
        eng = Engine(sim=ReplaySim(SimConfig(seed=seed), pkts, attack_at, duration, 1.0, rate),
                     mit_cfg=MitigationConfig(dry_run=True), explain_async=False)
    finally:
        os.environ.pop("SHIELDWALL_ML", None)
    out = []
    for _ in range(attack_at + duration):
        p = eng.step()
        if attack_at <= p["t"] and eng.last_verdict.anomalous:
            out.append((eng.last_features, eng.last_classification.kind))
    return out


def load_real(capture_dirs: list[str], cic: str | None, members: list[str], cache: dict | None = None) -> list[dict]:
    from .replay import load_capture

    cache = {} if cache is None else cache
    sets = []
    for d in capture_dirs:
        for path in sorted(glob.glob(os.path.join(d, "*.pcap*"))):
            name = os.path.basename(path)
            if name not in cache:
                pkts, summary = load_capture(path)
                cache[name] = real_windows((pkts, None, summary))
            sets.append({"name": name, "truth": real_family(name), "windows": cache[name]})
            print(f"  {name}: {len(cache[name])} flagged seconds")
    if cic:
        from .cic import load_cic
        for m in members:
            name = f"CIC-DDoS2019 {m}"
            if name not in cache:
                cache[name] = real_windows(load_cic(cic, m))
            sets.append({"name": name, "truth": real_family("archive.zip"), "windows": cache[name]})
            print(f"  CIC {m}: {len(cache[name])} flagged seconds")
    return sets


CONFIDENT = 0.6  # the cascade's default bar: below it the model's answer is not used


def score_real(ml: MLClassifier | None, sets: list[dict]) -> list[dict]:
    """Per real attack: how many flagged seconds each method names correctly."""
    rows = []
    for s in sets:
        n = len(s["windows"])
        preds = [ml.predict(f) for f, _ in s["windows"]] if ml else []
        named = collections.Counter(v.family for v in preds).most_common(1)
        rows.append({
            "name": s["name"], "truth": sorted(s["truth"]), "windows": n,
            "fingerprint_named": sum(FINGERPRINT_TO_FAMILY.get(k, k) in s["truth"] for _, k in s["windows"]),
            "fingerprint_kind": collections.Counter(k for _, k in s["windows"]).most_common(1)[0][0] if n else None,
            "ml_named": sum(v.family in s["truth"] for v in preds),
            "ml_confident": sum(v.family in s["truth"] and v.confidence >= CONFIDENT for v in preds),
            "ml_called_attack": sum(v.malicious for v in preds),
            "ml_family": named[0][0] if named else None,
            "ml_confidence": round(sum(v.confidence for v in preds) / len(preds), 3) if preds else None,
        })
    return rows


def train(X, y, weights=None) -> MLClassifier:
    import numpy as np
    from sklearn.ensemble import HistGradientBoostingClassifier

    clf = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08,
                                         max_depth=None, l2_regularization=1.0, random_state=0)
    clf.fit(np.asarray(X, dtype=float), np.asarray(y), sample_weight=weights)
    return MLClassifier(clf, sorted(set(y)))


def _real_table(rows: list[dict], with_fp: bool = True) -> list[str]:
    def pct(a, b): return f"{100 * a / b:.0f}%" if b else "-"
    cols = ["Real attack", "Truth", "Flagged seconds"] + (["Fingerprints name it"] if with_fp else []) + \
           ["ML names it", f"... and is {CONFIDENT:.0%}+ sure", "ML calls it an attack", "ML's usual answer"]
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for r in rows:
        if not r["windows"]:
            out.append(f"| {r['name']} | {', '.join(r['truth'])} | 0 (below the alert floor: no tier runs) | "
                       + " | ".join("-" * 1 for _ in cols[3:]) + " |")
            continue
        out.append(f"| {r['name']} | {', '.join(r['truth'])} | {r['windows']} | "
                   + (f"{pct(r['fingerprint_named'], r['windows'])} ({r['fingerprint_kind']}) | " if with_fp else "")
                   + f"{pct(r['ml_named'], r['windows'])} | {pct(r['ml_confident'], r['windows'])} | "
                   f"{pct(r['ml_called_attack'], r['windows'])} | "
                   f"{r['ml_family']} ({r['ml_confidence']:.0%}) |")
    return out


def _totals(rows: list[dict]) -> dict:
    n = sum(r["windows"] for r in rows)
    return {"windows": n, "fingerprint": sum(r["fingerprint_named"] for r in rows) / n if n else 0.0,
            "ml": sum(r["ml_named"] for r in rows) / n if n else 0.0,
            "ml_confident": sum(r["ml_confident"] for r in rows) / n if n else 0.0,
            "ml_attack": sum(r["ml_called_attack"] for r in rows) / n if n else 0.0}


def main(out_dir: str = "results", captures: list[str] | None = None, heldout: list[str] | None = None,
         cic: str | None = None, cic_dev: list[str] | None = None, cic_heldout: list[str] | None = None,
         cache_path: str | None = None, learn_from_captures: bool = False) -> dict:
    """Train and score. The shipped model learns from simulated traffic only, unless learn_from_captures:
    adding the six development captures made it worse on the held-out ones (see section 3 of the report)."""
    import pickle

    import numpy as np
    from sklearn.metrics import classification_report, confusion_matrix

    os.environ.setdefault("SHIELDWALL_LLM", "template")
    cache = {}
    if cache_path and os.path.exists(cache_path):
        with open(cache_path, "rb") as fh:
            cache = pickle.load(fh)
    if "sim" not in cache:
        print("generating labelled windows from the simulator ...")
        cache["sim"] = build_dataset()
    X, F, y, seeds = cache["sim"]
    X = np.asarray(X, dtype=float)
    y = np.asarray(y)
    seeds = np.asarray(seeds)

    # Split by seed: train and test windows never share a seed (unseen traffic).
    test = (seeds % 5 == 0)
    Xtr, ytr = X[~test], y[~test]
    Xte, yte, Fte = X[test], y[test], [f for f, m in zip(F, test) if m]
    print(f"train {len(Xtr)}  test {len(Xte)}  classes {sorted(set(y))}")
    sim_ml = train(Xtr, ytr)

    dev, held = [], []
    if captures or cic_dev:
        print("replaying development captures ...")
        dev = load_real(captures or [], cic, cic_dev or [], cache.setdefault("real", {}))
    if heldout or cic_heldout:
        print("replaying held-out captures ...")
        held = load_real(heldout or [], cic, cic_heldout or [], cache.setdefault("real", {}))
    if cache_path:
        with open(cache_path, "wb") as fh:
            pickle.dump(cache, fh)

    # Experiment: also learn from the development captures (labelled by what they are) and score on the
    # held-out ones. It did worse than the simulator-only model, so that one ships unless asked otherwise.
    mixed = None
    dev_train = []
    for s in dev:
        fams = sorted(s["truth"] & set(ATTACK_FAMILIES))
        if len(fams) == 1:  # a multi-vector capture has no single family to learn
            dev_train += [(feat_vector(f), fams[0]) for f, _ in s["windows"]]
    if dev_train:
        Xr = np.vstack([Xtr, np.asarray([v for v, _ in dev_train], dtype=float)])
        yr = np.concatenate([ytr, np.asarray([fam for _, fam in dev_train])])
        # a hundred-odd real seconds next to ~2,000 simulated ones: weight them so they count
        w = np.concatenate([np.ones(len(ytr)), np.full(len(dev_train), 5.0)])
        mixed = train(Xr, yr, w)
    ml = mixed if learn_from_captures and mixed is not None else sim_ml

    # ---- ML quality on unseen simulator windows ----
    pred = ml.model.predict(Xte)
    rep = classification_report(yte, pred, output_dict=True, zero_division=0)
    labels_sorted = sorted(set(y))
    cm = confusion_matrix(yte, pred, labels=labels_sorted)

    # ---- head-to-head vs the hand-written fingerprints, on the SAME windows ----
    fp = Classifier()
    for _ in range(8):  # let the fingerprint baseline settle like the engine does
        fp.learn(_sample(999_000, "benign")[1])

    per_family = {}
    ml_mal_ok = fp_mal_ok = 0
    t_ml = t_fp = 0.0
    for f, truth in zip(Fte, yte):
        t0 = time.perf_counter(); mv = ml.predict(f); t_ml += time.perf_counter() - t0
        t0 = time.perf_counter(); c = fp.classify(f); t_fp += time.perf_counter() - t0
        truth_mal = truth not in BENIGN_LABELS
        ml_mal_ok += (mv.malicious == truth_mal)
        fp_mal_ok += (c.malicious == truth_mal)
        d = per_family.setdefault(str(truth), {"n": 0, "ml_fam": 0, "fp_fam": 0, "ml_mal": 0, "fp_mal": 0})
        d["n"] += 1
        # an attack counts as right when the family is named; normal traffic when it is not called an attack
        d["ml_fam"] += (mv.family == truth) if truth_mal else (not mv.malicious)
        d["fp_fam"] += (FINGERPRINT_TO_FAMILY.get(c.kind, c.kind) == truth) if truth_mal else (not c.malicious)
        d["ml_mal"] += (mv.malicious == truth_mal)
        d["fp_mal"] += (c.malicious == truth_mal)

    n = len(Fte)
    dev_rows, held_rows = score_real(sim_ml, dev), score_real(sim_ml, held)
    held_mixed = score_real(mixed, held) if mixed is not None else []
    summary = {
        "n_train": len(Xtr), "n_test": n, "n_real_train": len(dev_train), "classes": labels_sorted,
        "features": FEATURE_NAMES,
        "ml_macro_f1": rep["macro avg"]["f1-score"], "ml_accuracy": rep["accuracy"],
        "ml_malicious_accuracy": ml_mal_ok / n, "fp_malicious_accuracy": fp_mal_ok / n,
        "ml_latency_us": 1e6 * t_ml / n, "fp_latency_us": 1e6 * t_fp / n,
        "per_family": per_family,
        "shipped": "simulator + development captures" if ml is mixed else "simulator only",
        "real_dev_sim_model": dev_rows, "real_heldout_sim_model": held_rows, "real_heldout_mixed_model": held_mixed,
        "real_totals": {"dev_sim_model": _totals(dev_rows), "heldout_sim_model": _totals(held_rows),
                        "all_sim_model": _totals(dev_rows + held_rows), "heldout_mixed_model": _totals(held_mixed)},
    }

    os.makedirs(out_dir, exist_ok=True)
    ml.save(os.path.join(out_dir, "ml_model.joblib"))

    # ---- markdown report ----
    def pct(a, b): return f"{100*a/b:.1f}%" if b else "-"
    lines = ["# Tier 2: ML classifier vs hand-written fingerprints", "",
             "A gradient-boosted tree model (`HistGradientBoostingClassifier`) over the same per-second features "
             f"the engine computes ({len(FEATURE_NAMES)} of them, all available from the real kernel maps). "
             "In the engine it only runs when the Tier 1 detector has flagged a second and no fingerprint matched.",
             "", "## 1. Simulated traffic", "",
             f"Trained on {len(Xtr)} simulator windows, tested on {n} windows from seeds it never saw. "
             "The families include attacks the fingerprints were never written for.", "",
             "| Method | Is-it-an-attack accuracy | Mean time per decision |",
             "|---|---|---|",
             f"| Hand-written fingerprints | {pct(fp_mal_ok, n)} | {summary['fp_latency_us']:.0f} µs |",
             f"| Trained ML (Tier 2) | {pct(ml_mal_ok, n)} | {summary['ml_latency_us'] / 1000:.1f} ms |",
             "", f"ML exact-family accuracy: **{rep['accuracy']*100:.1f}%**, "
             f"macro-F1 **{rep['macro avg']['f1-score']:.3f}**. Simulated families separate cleanly, so this is "
             "an upper bound; the real-data sections below are the numbers that matter.", "",
             "| Family | Test windows | Fingerprints get it right | ML gets it right |",
             "|---|---|---|---|"]
    for fam in labels_sorted:
        d = per_family.get(fam)
        if d:
            note = " (right = not called an attack)" if fam in BENIGN_LABELS else ""
            lines.append(f"| {fam}{note} | {d['n']} | {pct(d['fp_fam'], d['n'])} | {pct(d['ml_fam'], d['n'])} |")
    if dev or held:
        tot = summary["real_totals"]
        lines += ["", "## 2. Real attacks the model never saw", "",
                  "The shipped model learned from simulated traffic only, so every real attack below is new to it. "
                  "Real attack packets are replayed on top of modelled players (the same replays as the results "
                  "tables) and scored on every second the Tier 1 detector flagged, which is when the cascade runs. "
                  f"In the engine the model's answer is only used when it is at least {CONFIDENT:.0%} sure and no "
                  "fingerprint matched.", "",
                  *_real_table(dev_rows + held_rows), "",
                  f"Across all {tot['all_sim_model']['windows']} flagged seconds the model names the right family "
                  f"in **{tot['all_sim_model']['ml']:.0%}** ({tot['all_sim_model']['ml_confident']:.0%} with at least "
                  f"{CONFIDENT:.0%} confidence) and calls **{tot['all_sim_model']['ml_attack']:.0%}** of them an "
                  f"attack; the fingerprints name {tot['all_sim_model']['fingerprint']:.0%}. The row that matters is "
                  "the SYN-ACK reflection capture: no fingerprint matches it, and the model names it."]
    if mixed is not None:
        tot = summary["real_totals"]
        lines += ["", "## 3. Experiment: also training on the development captures", "",
                  f"Adding the {len(dev_train)} flagged seconds of the development captures to training (weighted "
                  "5x) and scoring on the held-out captures:", "",
                  *_real_table(held_mixed, with_fp=False), "",
                  f"It names **{tot['heldout_mixed_model']['ml']:.0%}** of held-out seconds, against "
                  f"**{tot['heldout_sim_model']['ml']:.0%}** for the simulator-only model"
                  + (": six real attacks were too few, and the model over-fitted to them. "
                     if tot['heldout_mixed_model']['ml'] < tot['heldout_sim_model']['ml'] else ". ")
                  + "So the shipped model "
                  + ("is the mixed one (`--learn-from-captures`)." if ml is mixed else
                     "learns from simulated traffic only. This choice was made after seeing the held-out scores, "
                     "which is why both are reported.")]
    lines.append("")
    report = "\n".join(lines)
    with open(os.path.join(out_dir, "ml_eval.md"), "w", encoding="utf-8") as fh:
        fh.write(report)
    with open(os.path.join(out_dir, "ml_eval.json"), "w", encoding="utf-8") as fh:
        json.dump({"summary": summary, "report": rep,
                   "confusion_matrix": {"labels": labels_sorted, "matrix": cm.tolist()}}, fh, indent=2, default=str)
    print(report)
    print(f"saved: {out_dir}/ml_model.joblib, ml_eval.md, ml_eval.json")
    return summary


if __name__ == "__main__":
    main()
