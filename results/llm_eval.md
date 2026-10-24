# LLM evaluation (gpt-4o-mini)

13 incident explanations from real engine runs + 3 chat questions over the event log, using the exact production prompts. Reproduce with `shieldwall llm-eval`.

| Metric | Result |
|---|---|
| Numeric grounding (numbers that match the facts) | 100.0% (49/49) |
| Explanations with zero hallucinated numbers | 100% |
| Names the correct attack / calls a surge legitimate | 100% |
| Chat answers correct | 100% |
| Latency median / p95 | 1.6 s / 2.7 s |
| Tokens per call (in / out) | 393 / 78 |
| Cost per explanation | $0.00008 |
| Total cost of this evaluation | $0.0017 |

## Sample answers

- **cldap**: Your game server experienced a DDoS attack known as a CLDAP amplification flood, where it received a high volume of malicious traffic from over 2,200 sources. ShieldWall detected and mitigated this attack within a few seconds, successfully serving 98.3% of legitimate traffic, so your players were not affected. No action is needed on your part, as the incident has been resolved.
- **dns**: Your game server experienced a DNS amplification flood attack, where a large volume of malicious traffic peaked at 162,053 packets per second from 2,435 different sources. ShieldWall detected the attack within 2 seconds and mitigated it in 3 seconds, ensuring that 98.5% of legitimate traffic was still served. There is no action needed from you, as the incident has been resolved and players were not affected.
- **ntp**: Your game server experienced a DDoS attack known as an NTP amplification flood, where it received a high volume of malicious traffic peaking at 129,812 packets per second from 1,570 different sources. ShieldWall detected and mitigated the attack quickly, ensuring that 98.8% of legitimate traffic was still served, so your players were not affected. No action is needed on your part, as the issue has been resolved.
- **syn**: Your game server experienced a TCP SYN flood attack, where 2,490 sources attempted to overwhelm the server with connection requests, peaking at 159,402 packets per second. ShieldWall detected the attack quickly and mitigated it within 3 seconds, allowing 98.4% of legitimate traffic to be served without significant impact on players. No action is needed from you at this time, as the incident has been resolved.
- **udp**: Your game server experienced a UDP flood attack, with a peak of 131,378 packets per second coming from 2,479 different sources. ShieldWall detected the attack quickly and mitigated it within 3 seconds, allowing 99.1% of legitimate traffic to continue unaffected. There’s no action needed from you at this time, as the incident has been resolved.
- **flash_crowd**: The incident was a legitimate traffic surge, not a DDoS attack, with a peak of 7395 packets per second from 1882 sources. ShieldWall monitored the situation for 3 seconds and confirmed that all handshakes completed normally, ensuring that 100% of the traffic was served without any disruption to players. There is no action needed from you at this time.
- **mega_cldap**: Your game server experienced a DDoS attack known as a CLDAP amplification flood, where it received a peak of 936,014 packets per second from 2,170 different sources. ShieldWall detected the attack within 2 seconds and mitigated it in 3 seconds, allowing 68.1% of legitimate traffic to be served. No action is required from you at this time, as the incident has been resolved.

- **Q: Why did you block port 389?** Port 389 was blocked because your server was targeted in a CLDAP amplification flood attack. This attack involved a large volume of UDP traffic from that port, which was not initiated by your server but rather reflected replies from other sources. Blocking this port helps prevent such attacks from affecting your server.
- **Q: What attacks happened?** Your server experienced two attacks:

1. A **TCP SYN flood** attack from about 2,468 sources, peaking at 158,720 packets per second. This attack lasted from 151 seconds to 182 seconds.
   
2. A **CLDAP amplification flood** attack from about 2,285 sources, peaking at 212,590 packets per second. This attack lasted from 41 seconds to 72 seconds.

Both attacks were mitigated by ShieldWall within 3 seconds of detection, allowing 98% of real player traffic to get through.
- **Q: How many attacks were there?** There were two attacks on your server. The first was a CLDAP amplification flood, and the second was a TCP SYN flood.
