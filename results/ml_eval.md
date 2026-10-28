# ShieldWall Tier 2: ML classifier vs hand-written fingerprints

Trained on 1952 simulator windows, tested on 488 windows from unseen seeds. Same feature vector as the live engine. Families include attacks the fingerprints were never written for.

## Overall

| Method | Is-it-an-attack accuracy | Mean latency |
|---|---|---|
| Hand-written fingerprints | 91.0% | 31.8 us |
| Trained ML (Tier 2) | 100.0% | 44025.4 us |

ML multi-class accuracy (exact family): **100.0%**, macro-F1 **1.000**.

## Per family: who names it correctly

| Family | Test windows | Fingerprint names it | ML names it |
|---|---|---|---|
| benign | 100 | 0.0% | 100.0% |
| cldap_amp | 36 | 100.0% | 100.0% |
| dns_amp | 36 | 100.0% | 100.0% |
| legit_surge | 64 | 23.4% | 100.0% |
| memcached_amp | 36 | 100.0% | 100.0% |
| ntp_amp | 36 | 100.0% | 100.0% |
| single_source_flood | 36 | 100.0% | 100.0% |
| ssdp_amp | 36 | 100.0% | 100.0% |
| syn_flood | 36 | 100.0% | 100.0% |
| synack_reflection | 36 | 0.0% | 100.0% |
| udp_flood | 36 | 77.8% | 100.0% |

The row that matters for the paper is **synack_reflection** -- the real attack the held-out capture test caught but could not name. The fingerprints score ~0 there (no rule matches, so nothing is blocked); the trained model recognises it.
