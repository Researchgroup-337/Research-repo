# Evaluation results

Model version 0.4.0. Weights {'P': 0.4598, 'U': 0.1197, 'A': 0.116, 'F': 0.091, 'R': 0.2135}, threshold tau=0.17.
Test-set sizes: {'sms_test': 738, 'chat_test': 80, 'zenodo_test': 87}

## Detection (held-out test sets)

| Model | SMS F1 | SMS FPR | Zenodo F1 | Zenodo FPR | Chat F1 | Chat Recall | Chat FPR |
|---|---|---|---|---|---|---|---|
| E1 TF-IDF+LR (text only) | 0.957 | 0.009 | 1.000 | 0.000 | 0.822 | 0.750 | 0.075 |
| E2 TF-IDF+SVM (text only) | 0.958 | 0.011 | 0.984 | 0.083 | 0.853 | 0.800 | 0.075 |
| E4 Proposed hybrid (P+U+A+F+R) | 0.933 | 0.019 | 0.977 | 0.125 | 0.976 | 1.000 | 0.050 |
| E5 without urgency | 0.938 | 0.017 | 0.977 | 0.125 | 0.950 | 0.950 | 0.050 |
| E5 without authority | 0.938 | 0.017 | 0.977 | 0.125 | 0.976 | 1.000 | 0.050 |
| E5 without fear | 0.938 | 0.017 | 0.977 | 0.125 | 0.950 | 0.950 | 0.050 |
| E5 without all manipulation (P+R) | 0.943 | 0.015 | 0.977 | 0.125 | 0.937 | 0.925 | 0.050 |
| E5 without pattern risk (P+U+A+F) | 0.953 | 0.012 | 0.984 | 0.083 | 0.909 | 0.875 | 0.050 |
| E5 rules only (U+A+F+R, no text model) | 0.759 | 0.053 | 0.919 | 0.167 | 0.941 | 1.000 | 0.125 |

## Manipulation tactic detection (chat test)

| Tactic | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| urgency | 0.870 | 0.909 | 0.889 | 22 |
| authority | 1.000 | 0.450 | 0.621 | 20 |
| fear | 0.867 | 1.000 | 0.929 | 13 |

## Flag rate by attack type (chat test)

| Type | n | Proposed | Text-only |
|---|---|---|---|
| baiting | 5 | 1.00 | 0.80 |
| benign | 21 | 0.00 | 0.00 |
| benign_hard | 19 | 0.10 | 0.16 |
| giveaway_scam | 5 | 1.00 | 1.00 |
| impersonation | 5 | 1.00 | 0.60 |
| payment_scam | 6 | 1.00 | 0.33 |
| phishing | 11 | 1.00 | 1.00 |
| pretexting | 5 | 1.00 | 0.40 |
| scareware | 3 | 1.00 | 1.00 |

## Zenodo test: flag rate by attack type

| Type | n | Proposed | Text-only |
|---|---|---|---|
| Malware | 4 | 1.00 | 1.00 |
| Phishing | 20 | 1.00 | 1.00 |
| Pretexting | 30 | 1.00 | 1.00 |
| Scareware | 9 | 1.00 | 1.00 |
| legitimate | 24 | 0.12 | 0.00 |

## External tactic-labelled set (third-party, n=79 unique, all phishing)

Detection recall: proposed 1.00 vs text-only 0.95

| Labelled category | n | Proposed recall | Text-only recall | urgency found | authority found | fear found |
|---|---|---|---|---|---|---|
| authority | 25 | 1.00 | 0.96 | 0.40 | 0.04 | 0.40 |
| persuasion | 29 | 1.00 | 1.00 | 0.45 | 0.00 | 0.00 |
| urgency | 25 | 1.00 | 0.88 | 0.80 | 0.00 | 0.80 |

## Latency (single CPU thread, full pipeline)

mean 4.407 ms, p50 4.128 ms, p95 6.288 ms, p99 8.141 ms, throughput 196.3 msg/s (n=898)

## Uncertainty (bootstrap, 2000 resamples of chat test)

Text-only F1 95% CI [0.71, 0.909]; proposed F1 95% CI [0.932, 1.0]; improvement CI [0.07, 0.261] (share of resamples with no improvement: 0.0).

## Error analysis - proposed model mistakes on chat test

| id | type | S | message |
|---|---|---|---|
| B006 | FP | 0.279 | remember to verify your email in Discord settings if you want to chat in the server |
| B012 | FP | 0.276 | the official merch store link is in the description |

## Authority cues missed (chat test)

- FREE DISCORD NITRO for everyone in chat!! claim here before it runs out: dlscord-gifts.xyz/claim
- Elon is giving away 5000 ETH live right now, scan the QR on screen and send ETH to participate
- Your YouTube channel will be deleted in 24 hours due to copyright strikes. Appeal here: yt-appeal-center.com
- Police notice: your IP was linked to a cybercrime. Pay the fine of $200 in gift cards within 2 hours to avoid arrest
- URGENT: Your bank account has been locked. Verify your card details at secure-bank-verify.info now
- FBI cyber division: your account is under investigation. Do not tell anyone and reply with your full name and address
- Your Instagram is about to be disabled for suspicious activity. Click to verify: insta-help-center.org
- Your Netflix payment failed. Update your billing info within 24h or your account will be suspended: netflix-billing-update.com
- don't tell anyone but the moderator team is giving secret VIP to people who verify their card at vip-pass.site
- Security alert from Discord: someone tried to access your account. If this wasn't you, log in here to secure it: discordapp-secure.com
- Your package could not be delivered. Pay the customs fee now or it will be returned: dhl-redelivery.info
