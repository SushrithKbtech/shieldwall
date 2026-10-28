# Tier 2: ML classifier vs hand-written fingerprints

A gradient-boosted tree model (`HistGradientBoostingClassifier`) over the same per-second features the engine computes (20 of them, all available from the real kernel maps). In the engine it only runs when the Tier 1 detector has flagged a second and no fingerprint matched.

## 1. Simulated traffic

Trained on 1952 simulator windows, tested on 488 windows from seeds it never saw. The families include attacks the fingerprints were never written for.

| Method | Is-it-an-attack accuracy | Mean time per decision |
|---|---|---|
| Hand-written fingerprints | 91.0% | 27 µs |
| Trained ML (Tier 2) | 100.0% | 50.2 ms |

ML exact-family accuracy: **100.0%**, macro-F1 **1.000**. Simulated families separate cleanly, so this is an upper bound; the real-data sections below are the numbers that matter.

| Family | Test windows | Fingerprints get it right | ML gets it right |
|---|---|---|---|
| benign (right = not called an attack) | 100 | 100.0% | 100.0% |
| cldap_amp | 36 | 100.0% | 100.0% |
| dns_amp | 36 | 100.0% | 100.0% |
| legit_surge (right = not called an attack) | 64 | 100.0% | 100.0% |
| memcached_amp | 36 | 100.0% | 100.0% |
| ntp_amp | 36 | 100.0% | 100.0% |
| single_source_flood | 36 | 100.0% | 100.0% |
| ssdp_amp | 36 | 100.0% | 100.0% |
| syn_flood | 36 | 100.0% | 100.0% |
| synack_reflection | 36 | 0.0% | 100.0% |
| udp_flood | 36 | 77.8% | 100.0% |

## 2. Real attacks the model never saw

The shipped model learned from simulated traffic only, so every real attack below is new to it. Real attack packets are replayed on top of modelled players (the same replays as the results tables) and scored on every second the Tier 1 detector flagged, which is when the cascade runs. In the engine the model's answer is only used when it is at least 60% sure and no fingerprint matched.

| Real attack | Truth | Flagged seconds | Fingerprints name it | ML names it | ... and is 60%+ sure | ML calls it an attack | ML's usual answer |
|---|---|---|---|---|---|---|---|
| amp.UDP.DNSANY.pcap | dns_amp | 19 | 100% (dns_amplification) | 100% | 0% | 100% | dns_amp (51%) |
| amp.UDP.memcached.ntp.cldap.pcap | cldap_amp, memcached_amp, multi_vector, ntp_amp | 19 | 100% (multi_vector_amplification) | 100% | 0% | 100% | cldap_amp (23%) |
| pkt.TCP.synflood.spoofed.pcap | syn_flood | 19 | 100% (syn_flood) | 100% | 100% | 100% | syn_flood (98%) |
| CIC-DDoS2019 01-12/Syn.csv | single_source_flood | 19 | 100% (single_source_flood) | 100% | 100% | 100% | single_source_flood (100%) |
| CIC-DDoS2019 01-12/DrDoS_NTP.csv | single_source_flood | 19 | 100% (single_source_flood) | 100% | 100% | 100% | single_source_flood (100%) |
| CIC-DDoS2019 01-12/DrDoS_LDAP.csv | single_source_flood | 19 | 100% (single_source_flood) | 100% | 11% | 100% | single_source_flood (57%) |
| amp.TCP.reflection.SYNACK.pcap | synack_reflection | 19 | 0% (unknown) | 100% | 100% | 100% | synack_reflection (100%) |
| amp.UDP.isakmp.pcap | udp_flood | 19 | 100% (udp_flood) | 100% | 0% | 100% | udp_flood (13%) |
| amp.UDP.snmp.src161.pcapng | udp_flood | 19 | 100% (udp_flood) | 100% | 0% | 100% | udp_flood (13%) |
| amp.dns.RRSIG.fragmented.pcap | dns_amp | 0 (below the alert floor: no tier runs) | - | - | - | - | - |
| pkt.UDP.rdm.fixedlength.pcapng | udp_flood | 4 | 0% (unknown) | 0% | 0% | 100% | single_source_flood (52%) |
| CIC-DDoS2019 01-12/UDPLag.csv | single_source_flood | 19 | 100% (single_source_flood) | 100% | 100% | 100% | single_source_flood (100%) |
| CIC-DDoS2019 03-11/Portmap.csv | single_source_flood | 19 | 100% (single_source_flood) | 100% | 100% | 100% | single_source_flood (100%) |
| CIC-DDoS2019 01-12/DrDoS_SSDP.csv | single_source_flood | 19 | 100% (single_source_flood) | 100% | 100% | 100% | single_source_flood (100%) |

Across all 232 flagged seconds the model names the right family in **98%** (58% with at least 60% confidence) and calls **100%** of them an attack; the fingerprints name 90%. The row that matters is the SYN-ACK reflection capture: no fingerprint matches it, and the model names it.

## 3. Experiment: also training on the development captures

Adding the 95 flagged seconds of the development captures to training (weighted 5x) and scoring on the held-out captures:

| Real attack | Truth | Flagged seconds | ML names it | ... and is 60%+ sure | ML calls it an attack | ML's usual answer |
|---|---|---|---|---|---|---|
| amp.TCP.reflection.SYNACK.pcap | synack_reflection | 19 | 100% | 100% | 100% | synack_reflection (100%) |
| amp.UDP.isakmp.pcap | udp_flood | 19 | 0% | 0% | 100% | syn_flood (47%) |
| amp.UDP.snmp.src161.pcapng | udp_flood | 19 | 100% | 0% | 100% | udp_flood (35%) |
| amp.dns.RRSIG.fragmented.pcap | dns_amp | 0 (below the alert floor: no tier runs) | - | - | - | - |
| pkt.UDP.rdm.fixedlength.pcapng | udp_flood | 4 | 100% | 100% | 100% | udp_flood (74%) |
| CIC-DDoS2019 01-12/UDPLag.csv | single_source_flood | 19 | 100% | 100% | 100% | single_source_flood (100%) |
| CIC-DDoS2019 03-11/Portmap.csv | single_source_flood | 19 | 100% | 100% | 100% | single_source_flood (100%) |
| CIC-DDoS2019 01-12/DrDoS_SSDP.csv | single_source_flood | 19 | 100% | 100% | 100% | single_source_flood (100%) |

It names **84%** of held-out seconds, against **97%** for the simulator-only model: six real attacks were too few, and the model over-fitted to them. So the shipped model learns from simulated traffic only. This choice was made after seeing the held-out scores, which is why both are reported.
