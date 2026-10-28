# Tier 3: the analyst on attacks no tier could name

Each attack is replayed with the fingerprints and the ML tier made to come up empty, so it reaches the analyst the way a real residual would, with only the traffic evidence to go on. Both backends get the same incident, and every proposal goes through the controller's checks: not too broad, no drop on the game ports, under 1% of normal player traffic, at least 5% of the attack. Accepted rules are installed in dry-run only.

| | Proposals accepted by the controller | Attack matched by accepted rules (mean) | Worst player traffic hit by an accepted rule | Median latency | Cost per proposal |
|---|---|---|---|---|---|
| Offline heuristic | **12/14** | 82% | 0.19% | - | - |
| gpt-4o-mini, prompt v1 (no field guide) | **8/14** | 70% | 0.19% | 2.2 s | $0.00018 |
| gpt-4o-mini | **9/14** | 76% | 0.00% | 2.2 s | $0.00021 |

Prompt v1 gave the model the profile without saying what its fields mean. It put `syn_only` on UDP rules, picked UDP for TCP floods, ignored the SYN-ACK share and wrote the text "null" for empty fields. The final prompt adds a field guide (`PROFILE_GUIDE` in analyst.py) and the protocol of each top port; the controller now also reads "null" text as an empty field. Both prompts were scored on the same incidents, so the final row is not a held-out number. [Prompt v1 report](analyst_eval_prompt_v1.md).

| Attack | Heuristic proposal | gpt-4o-mini proposal |
|---|---|---|
| simulated synack | `RATE-LIMIT TCP SYN-ACK only from unknown sources to 100 pps`: **accepted**; matches 98% of attack, 0.0% of players | `DROP TCP src port 22 SYN-ACK only from unknown sources`: **accepted**; matches 21% of attack, 0.0% of players |
| simulated udp | `RATE-LIMIT ALL from unknown sources to 1,000 pps`: rejected: would hit 5.0% of normal player traffic; matches 98% of attack, 5.0% of players | `RATE-LIMIT UDP from unknown sources to 100 pps`: rejected: would hit 1.4% of normal player traffic; matches 98% of attack, 1.4% of players |
| simulated syn | `RATE-LIMIT TCP SYN only from unknown sources to 200 pps`: **accepted**; matches 99% of attack, 0.2% of players | `RATE-LIMIT TCP src port 17901 SYN only from unknown sources to 100 pps`: rejected: matches only 0.1% of the attack traffic; matches 0% of attack, 0.0% of players |
| simulated cldap | `DROP UDP src port 389 from unknown sources`: **accepted**; matches 99% of attack, 0.0% of players | `DROP UDP src port 389 from unknown sources`: **accepted**; matches 99% of attack, 0.0% of players |
| simulated ntp | `DROP UDP src port 123 from unknown sources`: **accepted**; matches 98% of attack, 0.0% of players | `RATE-LIMIT UDP src port 123 from unknown sources to 100 pps`: **accepted**; matches 98% of attack, 0.0% of players |
| amp.UDP.DNSANY.pcap | `DROP UDP src port 53 from unknown sources`: **accepted**; matches 68% of attack, 0.0% of players | `DROP UDP src port 53 from unknown sources`: **accepted**; matches 68% of attack, 0.0% of players |
| amp.UDP.memcached.ntp.cldap.pcap | `DROP UDP src port 11211 from unknown sources`: **accepted**; matches 36% of attack, 0.0% of players | `RATE-LIMIT UDP src port 11211 from unknown sources to 1,000 pps`: **accepted**; matches 36% of attack, 0.0% of players |
| pkt.TCP.synflood.spoofed.pcap | `RATE-LIMIT TCP SYN only from unknown sources to 200 pps`: **accepted**; matches 42% of attack, 0.2% of players | `RATE-LIMIT TCP from 49.185.140.103 src port 58980 SYN only to 20 pps`: rejected: matches only 0.0% of the attack traffic; matches 0% of attack, 0.0% of players |
| amp.TCP.reflection.SYNACK.pcap | `RATE-LIMIT TCP SYN-ACK only from unknown sources to 100 pps`: **accepted**; matches 79% of attack, 0.0% of players | `RATE-LIMIT TCP src port 80 SYN only from unknown sources to 500 pps`: rejected: matches only 0.0% of the attack traffic; matches 0% of attack, 0.0% of players |
| amp.UDP.isakmp.pcap | `DROP UDP src port 4500 from unknown sources`: **accepted**; matches 81% of attack, 0.0% of players | `RATE-LIMIT UDP src port 4500 from unknown sources to 100 pps`: **accepted**; matches 81% of attack, 0.0% of players |
| amp.UDP.snmp.src161.pcapng | `DROP UDP src port 161 from unknown sources`: **accepted**; matches 93% of attack, 0.0% of players | `RATE-LIMIT UDP src port 161 from unknown sources to 1,000 pps`: **accepted**; matches 93% of attack, 0.0% of players |
| amp.dns.RRSIG.fragmented.pcap | not flagged by Tier 1 (below the alert floor) | |
| pkt.UDP.rdm.fixedlength.pcapng | `RATE-LIMIT ALL from unknown sources to 1,000 pps`: rejected: would hit 5.0% of normal player traffic; matches 33% of attack, 5.0% of players | `RATE-LIMIT UDP src port 20480 from unknown sources to 100 pps`: rejected: matches only 0.0% of the attack traffic; matches 0% of attack, 0.0% of players |
| CIC-DDoS2019 01-12/Syn.csv | `DROP ALL from 172.16.0.5`: **accepted**; matches 95% of attack, 0.0% of players | `RATE-LIMIT TCP from 172.16.0.5 from unknown sources to 1,000 pps`: **accepted**; matches 95% of attack, 0.0% of players |
| CIC-DDoS2019 01-12/UDPLag.csv | `DROP ALL from 172.16.0.5`: **accepted**; matches 91% of attack, 0.0% of players | `RATE-LIMIT TCP from 172.16.0.5 from unknown sources to 20,000 pps`: **accepted**; matches 91% of attack, 0.0% of players |
