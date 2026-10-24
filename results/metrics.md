# ShieldWall detection metrics

60 randomized trials: 52 attacks (CLDAP, DNS, NTP, SYN, UDP; 3k-300k pps, random start, length and ramp) and 8 negatives (flash crowds of real players, or quiet traffic). Ground truth comes from the simulator. Reproduce with `shieldwall metrics`.

| Level | Accuracy | Precision | Recall | F1 | TP / FP / FN / TN |
|---|---|---|---|---|---|
| Per 1 s window | 97.96% | 100.00% | 94.98% | 0.974 | 2,100 / 0 / 111 / 3,231 windows |
| Per packet dropped | 96.81% | 100.00% | 96.45% | 0.982 | 132,263,589 / 2,380 / 4,865,654 / 15,430,610 packets |
| Per trial (incident) | 98.33% | 100.00% | 98.08% | 0.990 | 51 / 0 / 1 / 8 trials |

- Attack-type classification accuracy (caught attacks): **100.0%**
- Median time to detect: **2 s**
- Real traffic wrongly dropped across all trials: **0.015%**

| Scenario | Trials | Detection | Classification |
|---|---|---|---|
| cldap | 8 | 8/8 detected | 8/8 correct type |
| dns | 9 | 9/9 detected | 9/9 correct type |
| ntp | 10 | 10/10 detected | 10/10 correct type |
| syn | 14 | 14/14 detected | 14/14 correct type |
| udp | 11 | 10/11 detected | 10/11 correct type |
| flash_crowd | 5 | 0/5 wrongly mitigated | - |
| none | 3 | 0/3 wrongly mitigated | - |

**How to read this.** Window-level recall is below 100% partly by design: the 2-window persistence guard means the first 1-2 seconds of every attack are counted as misses, and the alert stays up ~3 s after an attack ends. Those guards are what keep precision high and real players unblocked.

Missed attacks: udp at 6,101 pps. The misses are the weakest attacks, close to normal traffic volume.
