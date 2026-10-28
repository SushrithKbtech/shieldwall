# Tier 3: the analyst on attacks no tier could name

Each attack is replayed with the fingerprints and the ML tier made to come up empty, so it reaches the analyst the way a real residual would, with only the traffic evidence to go on. Both backends get the same incident, and every proposal goes through the controller's checks: not too broad, no drop on the game ports, under 1% of normal player traffic, at least 5% of the attack. Accepted rules are installed in dry-run only.

| | Proposals accepted by the controller | Attack matched by accepted rules (mean) | Worst player traffic hit by an accepted rule | Median latency | Cost per proposal |
|---|---|---|---|---|---|
| Offline heuristic | **12/14** | 80% | 0.19% | - | - |
| gpt-4o-mini | **8/14** | 70% | 0.19% | 2.2 s | $0.00018 |

| Attack | Heuristic proposal | gpt-4o-mini proposal |
|---|---|---|
| simulated synack | `RATE-LIMIT TCP SYN-ACK only from unknown sources to 100 pps`: **accepted**; matches 98% of attack, 0.0% of players | `RATE-LIMIT TCP src port 22 SYN only from unknown sources to 100 pps`: rejected: matches only 0.0% of the attack traffic; matches 0% of attack, 0.0% of players |
| simulated udp | `RATE-LIMIT ALL from unknown sources to 1,000 pps`: rejected: would hit 5.0% of normal player traffic; matches 98% of attack, 5.0% of players | `RATE-LIMIT UDP from unknown sources to 100 pps`: rejected: would hit 1.4% of normal player traffic; matches 98% of attack, 1.4% of players |
| simulated syn | `RATE-LIMIT TCP SYN only from unknown sources to 200 pps`: **accepted**; matches 99% of attack, 0.2% of players | `RATE-LIMIT ALL SYN only from unknown sources to 100 pps`: **accepted**; matches 99% of attack, 0.2% of players |
| simulated cldap | `DROP UDP src port 389 from unknown sources`: **accepted**; matches 99% of attack, 0.0% of players | `DROP UDP src port 389 SYN only from unknown sources`: rejected: matches only 0.0% of the attack traffic; matches 0% of attack, 0.0% of players |
| simulated ntp | `DROP UDP src port 123 from unknown sources`: **accepted**; matches 98% of attack, 0.0% of players | `DROP UDP src port 123 from unknown sources`: **accepted**; matches 98% of attack, 0.0% of players |
| amp.UDP.DNSANY.pcap | `DROP ALL from 8.8.8.8`: **accepted**; matches 48% of attack, 0.0% of players | `DROP UDP from 8.8.8.8`: **accepted**; matches 48% of attack, 0.0% of players |
| amp.UDP.memcached.ntp.cldap.pcap | `DROP UDP src port 11211 from unknown sources`: **accepted**; matches 36% of attack, 0.0% of players | `RATE-LIMIT UDP src port 11211 from unknown sources to 1,000 pps`: **accepted**; matches 36% of attack, 0.0% of players |
| pkt.TCP.synflood.spoofed.pcap | `RATE-LIMIT TCP SYN only from unknown sources to 200 pps`: **accepted**; matches 42% of attack, 0.2% of players | `RATE-LIMIT UDP SYN only from unknown sources to 20 pps`: rejected: matches only 0.0% of the attack traffic; matches 0% of attack, 0.0% of players |
| amp.TCP.reflection.SYNACK.pcap | `DROP TCP src port 80 from unknown sources`: **accepted**; matches 81% of attack, 0.0% of players | `{'action': 'rate_limit', 'protocol': 'any', 'source_ip': 'null', 'src_port': 80, 'dst_port': 'null', 'syn_only': False, 'synack_only': False, 'fragments_only': False, 'unknown_sources_only': True, 'rate_pps': 500, 'reason': 'Rate limiting unknown sources to mitigate anomalous traffic.'}`: rejected: Expected 4 octets in 'null' |
| amp.UDP.isakmp.pcap | `DROP UDP src port 4500 from unknown sources`: **accepted**; matches 81% of attack, 0.0% of players | `RATE-LIMIT UDP src port 4500 from unknown sources to 100 pps`: **accepted**; matches 81% of attack, 0.0% of players |
| amp.UDP.snmp.src161.pcapng | `DROP UDP src port 161 from unknown sources`: **accepted**; matches 93% of attack, 0.0% of players | `DROP UDP src port 161 from unknown sources`: **accepted**; matches 93% of attack, 0.0% of players |
| amp.dns.RRSIG.fragmented.pcap | not flagged by Tier 1 (below the alert floor) | |
| pkt.UDP.rdm.fixedlength.pcapng | `RATE-LIMIT ALL from unknown sources to 1,000 pps`: rejected: would hit 5.0% of normal player traffic; matches 33% of attack, 5.0% of players | `DROP UDP from 134.209.44.67`: **accepted**; matches 13% of attack, 0.0% of players |
| CIC-DDoS2019 01-12/Syn.csv | `DROP ALL from 172.16.0.5`: **accepted**; matches 95% of attack, 0.0% of players | `DROP UDP from 172.16.0.5`: rejected: matches only 0.0% of the attack traffic; matches 0% of attack, 0.0% of players |
| CIC-DDoS2019 01-12/UDPLag.csv | `DROP ALL from 172.16.0.5`: **accepted**; matches 91% of attack, 0.0% of players | `DROP ALL from 172.16.0.5`: **accepted**; matches 91% of attack, 0.0% of players |
