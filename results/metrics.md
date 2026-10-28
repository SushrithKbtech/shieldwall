# ShieldWall detection metrics

200 randomized trials: 107 attacks (CLDAP, DNS, NTP, SYN, UDP; 3k-300k pps, random start, length and ramp) and 93 negatives (flash crowds of real players, or quiet traffic). Ground truth comes from the simulator. Reproduce with `shieldwall metrics`.

| Level | Accuracy | Precision | Recall | F1 | TP / FP / FN / TN |
|---|---|---|---|---|---|
| Per 1 s window | 99.392% | 100% | 97.463% | 0.987 | 4,187 / 0 / 109 / 13,646 windows |
| Per packet dropped | 97.359% | 99.990% | 96.824% | 0.984 | 272,469,141 / 26,019 / 8,937,817 / 58,031,194 packets |
| Per trial (incident) | 100% | 100% | 100% | 1.000 | 107 / 0 / 0 / 93 trials |

- Attack-type classification accuracy (caught attacks): **100.0%**
- Median time to detect: **2 s**
- Real traffic wrongly dropped across all trials: **0.045%**

| Scenario | Trials | Detection | Classification |
|---|---|---|---|
| cldap | 15 | 15/15 detected | 15/15 correct type |
| dns | 20 | 20/20 detected | 20/20 correct type |
| ntp | 13 | 13/13 detected | 13/13 correct type |
| syn | 30 | 30/30 detected | 30/30 correct type |
| udp | 29 | 29/29 detected | 29/29 correct type |
| flash_crowd | 58 | 0/58 wrongly mitigated | - |
| none | 35 | 0/35 wrongly mitigated | - |

**How to read this.** Window-level recall is below 100% partly by design: the 2-window persistence guard means the first 1-2 seconds of every attack are counted as misses, and the alert stays up ~3 s after an attack ends. Those guards are what keep precision high and real players unblocked.

No attacks were missed.
