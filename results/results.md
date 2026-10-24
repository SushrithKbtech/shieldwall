# ShieldWall evaluation (simulated lab)

Each scenario: 40s of normal play to learn the baseline, a 60s event, 40s of recovery. 1 window = 1 s. Real traffic = ~2,000 pps of Minecraft players. Server capacity 60k pps, uplink 10 Gbps. 'Without' = same seeded traffic with the controller in dry-run.

| # | Scenario | Classified as | Real traffic served WITHOUT | Real traffic served WITH | Time to detect | Time to mitigate | Escalated upstream | False positives |
|---|---|---|---|---|---|---|---|---|
| S1 | Clean attack: CLDAP amplification | CLDAP amplification flood | 30.2% | 98.1% | 2s | 3s | no | - |
| S2a | Attack mixed with real traffic: SYN flood on the game port | TCP SYN flood | 40.1% | 98.7% | 2s | 3s | no | - |
| S2b | Attack mixed with real traffic: UDP flood | UDP flood | 50.3% | 99.3% | 2s | 3s | no | - |
| S3 | Legitimate spike, no attack (flash crowd) | legitimate traffic surge | 100.0% | 100.0% | 3s | n/a | no | 0 rules, 0.0% real traffic dropped |
| S4 | Attack bigger than the link (25 Gbps into 10 Gbps) | CLDAP amplification flood | 2.8% | 95.7% | 2s | 4s | yes | - |

## What the LLM layer said (template backend)

- **S1**: Your server was attacked from about 2,213 sources using a CLDAP amplification flood at up to 212,892 packets/s. ShieldWall blocked it 3 seconds after it started. 99% of real player traffic got through during the attack. No action needed from you.
- **S2a**: Your server was attacked from about 2,611 sources using a TCP SYN flood at up to 160,877 packets/s. ShieldWall blocked it 3 seconds after it started. 99% of real player traffic got through during the attack. No action needed from you.
- **S2b**: Your server was attacked from about 2,435 sources using a UDP flood at up to 129,293 packets/s. ShieldWall blocked it 3 seconds after it started. 99% of real player traffic got through during the attack. No action needed from you.
- **S3**: Traffic jumped to 7,246 packets/s, but it looks like real players (handshakes complete, normal protocol mix). ShieldWall is watching and did not block anyone.
- **S4**: Your server was attacked from about 2,170 sources using a CLDAP amplification flood at up to 936,014 packets/s. ShieldWall blocked it 3 seconds after it started. Real players are getting through normally again. The flood was bigger than your internet link, so ShieldWall asked the upstream network to filter it. No action needed from you.

## Honest limits

- These numbers come from the traffic simulator, not yet from packets on a real NIC. The XDP throughput benchmark (Mpps/core) needs a Linux VM with a native-XDP NIC and is still pending.
- S4 recovers only because the simulated upstream ISP accepts our FlowSpec rule. Without upstream help, no tool on the server can fix a full link.
- Time to detect is bounded below by the 1 s window and the 2-window persistence guard.
