# ShieldWall v2 — demo runbook

How to reproduce everything on your own Linux PC (or WSL2). Three things: the ML tier,
the cascade tests, and the live Minecraft demo.

## 0. Prerequisites

```bash
sudo apt install clang llvm libbpf-dev linux-tools-generic python3-pip nodejs npm
pip install -e . scikit-learn joblib
make -C bpf                      # builds bpf/xdp_filter.o
```

## 1. Train and evaluate the Tier 2 ML classifier

```bash
python -m shieldwall.ml_train    # writes results/ml_model.joblib, results/ml_eval.md
```

This trains on simulator traffic and scores ML vs the hand-written fingerprints. For the
paper's generalisation test, retrain/evaluate on CIC-DDoS2019 and the public captures —
the feature vector is identical, so the same model format loads. ML's headline result:
it catches `synack_reflection` (the real attack the held-out capture test could not name),
which the fingerprints score 0 on.

## 2. See the three tiers and the analyst

```bash
pytest -q                        # 26 tests, all tiers wired in
```

The cascade (`cascade.py`): fingerprints name known signatures; the ML model names
families with no signature; anything neither can name is flagged for the Tier 3 analyst
(`analyst.py`), which proposes one rule that the controller validates and installs in
dry-run. With `OPENAI_API_KEY`/`ANTHROPIC_API_KEY` set the LLM does the reasoning; with
no key a deterministic heuristic stands in, so the pipeline runs offline.

## 3. Live Minecraft demo

The harness in `mc-demo/` runs a real Minecraft server (flying-squid), a real player bot
(mineflayer), the real XDP program, and a real CLDAP flood, comparing dry-run vs enforce.

```bash
cd mc-demo
npm install flying-squid mineflayer minecraft-protocol
sudo python3 live_demo.py        # writes live_results.json
```

Note: flying-squid 1.12 crashes on join unless you pass `'player-list-text': { header: '', footer: '' }`
in `createMCServer` (already set in `mc_server.js`).

### For the actual viva demo

Use a **real PaperMC server** on your PC (downloadable there — it is blocked in the build
sandbox, which is why the harness uses flying-squid):

1. Download PaperMC, run it, accept the EULA, set `online-mode=false` for test bots.
2. `sudo shieldwall live --iface <your-iface> --dry-run` for 2-3 days against real
   internet traffic — this is your real false-alarm number.
3. Connect with the real Minecraft client and play.
4. From a **separate machine on a capacity-limited link**, replay a recorded public
   capture (not a live attack — never attack a host you do not own). With a real uplink
   limit you will see the player lag/drop on dry-run and stay smooth on enforce — the
   effect the build sandbox could not reproduce (no link bottleneck there).

Keep all attack traffic inside your own lab. Never point a flood at a cloud host; every
provider's acceptable-use policy forbids it.
