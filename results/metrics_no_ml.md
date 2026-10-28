# ShieldWall detection metrics, ML tier off (fingerprints only)

200 randomized trials: 107 attacks (CLDAP, DNS, NTP, SYN, UDP; 3k-300k pps, random start, length and ramp) and 93 negatives (flash crowds of real players, or quiet traffic). Ground truth comes from the simulator. Reproduce with `SHIELDWALL_ML=off shieldwall metrics`.

| Level | Accuracy | Precision | Recall | F1 | TP / FP / FN / TN |
|---|---|---|---|---|---|
| Per 1 s window | 98.668% | 100% | 94.437% | 0.971 | 4,057 / 0 / 239 / 13,646 windows |
| Per packet dropped | 97.209% | 99.991% | 96.642% | 0.983 | 271,958,042 / 24,298 / 9,448,916 / 58,032,915 packets |
| Per trial (incident) | 99.000% | 100% | 98.131% | 0.991 | 105 / 0 / 2 / 93 trials |

- Attack-type classification accuracy (caught attacks): **100.0%**
- Median time to detect: **2 s**
- Real traffic wrongly dropped across all trials: **0.042%**

| Scenario | Trials | Detection | Classification |
|---|---|---|---|
| cldap | 15 | 15/15 detected | 15/15 correct type |
| dns | 20 | 20/20 detected | 20/20 correct type |
| ntp | 13 | 13/13 detected | 13/13 correct type |
| syn | 30 | 30/30 detected | 30/30 correct type |
| udp | 29 | 27/29 detected | 27/29 correct type |
| flash_crowd | 58 | 0/58 wrongly mitigated | - |
| none | 35 | 0/35 wrongly mitigated | - |

**How to read this.** Window-level recall is below 100% partly by design: the 2-window persistence guard means the first 1-2 seconds of every attack are counted as misses, and the alert stays up ~3 s after an attack ends. Those guards are what keep precision high and real players unblocked.

Missed attacks: udp at 6,238 pps, udp at 3,173 pps. The misses are the weakest attacks, close to normal traffic volume.
