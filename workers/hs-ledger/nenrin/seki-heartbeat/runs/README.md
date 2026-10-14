# SEKI heartbeat

Once a day the agent calls HORIZON SHIELD's own paid tool through the SEKI door under the demonstration contract (../../musubi-v0/run0003/contract.json): a report inside its limit, an audit over its limit, a comparison the contract prohibits. The door must admit the first and refuse the other two, and every answer is a signed record on the public ledger. Once the ledger's batch is confirmed in Bitcoin the day is settled with settle v1.15. Principal, agent and door are all The HORIZONs Co., Ltd.; it is a demonstration, not an outside customer, and the pilot's tickets carry no monetary value. heartbeat.py and the workflow seki-heartbeat.yml write this folder.

| day (UTC) | report (limit 20) | audit 30 (limit 25) | compare (prohibited) | settlement |
|---|---|---|---|---|
| 2026-10-14 | admit d1ae4180 | refuse b68d22f9 | refuse b8a704b7 | waiting for Bitcoin |
| 2026-10-13 | admit 8e8b2853 | refuse adc2d46d | refuse ca0a82ec | waiting for Bitcoin |
| 2026-10-12 | admit 97939e52 | refuse 91dd010c | refuse 58f814c1 | waiting for Bitcoin |
| 2026-10-11 | admit 46bd1bc3 | refuse 6caab24b | refuse f47c90c7 | waiting for Bitcoin |
| 2026-10-10 | admit 48a1aa26 | refuse d8468d27 | refuse 52c9d0c7 | waiting for Bitcoin |
