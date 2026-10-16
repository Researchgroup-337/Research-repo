# Evaluation results

Model version 0.3.0. Weights {'P': 0.392, 'U': 0.0861, 'A': 0.1667, 'F': 0.1342, 'R': 0.221}, threshold tau=0.18.

## Detection (held-out test sets)

| Model | SMS F1 | SMS FPR | Chat F1 | Chat Recall | Chat FPR |
|---|---|---|---|---|---|
| E1 TF-IDF+LR (text only) | 0.973 | 0.000 | 0.667 | 0.500 | 0.000 |
| E2 TF-IDF+SVM (text only) | 0.973 | 0.000 | 0.644 | 0.475 | 0.000 |
| E4 Proposed hybrid (P+U+A+F+R) | 0.979 | 0.002 | 0.923 | 0.900 | 0.050 |
| E5 without urgency | 0.984 | 0.002 | 0.937 | 0.925 | 0.050 |
| E5 without authority | 0.984 | 0.002 | 0.949 | 0.925 | 0.025 |
| E5 without fear | 0.979 | 0.002 | 0.937 | 0.925 | 0.050 |
| E5 without all manipulation (P+R) | 0.969 | 0.007 | 0.938 | 0.950 | 0.075 |
| E5 without pattern risk (P+U+A+F) | 0.984 | 0.002 | 0.857 | 0.825 | 0.100 |
| E5 rules only (U+A+F+R, no text model) | 0.714 | 0.044 | 0.919 | 1.000 | 0.175 |

## Manipulation tactic detection (chat test)

| Tactic | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| urgency | 0.870 | 0.909 | 0.889 | 22 |
| authority | 1.000 | 0.400 | 0.571 | 20 |
| fear | 0.867 | 1.000 | 0.929 | 13 |

## Flag rate by attack type (chat test)

| Type | n | Proposed | Text-only |
|---|---|---|---|
| baiting | 5 | 0.80 | 0.60 |
| benign | 21 | 0.00 | 0.00 |
| benign_hard | 19 | 0.10 | 0.00 |
| giveaway_scam | 5 | 1.00 | 1.00 |
| impersonation | 5 | 1.00 | 0.20 |
| payment_scam | 6 | 0.83 | 0.17 |
| phishing | 11 | 1.00 | 0.73 |
| pretexting | 5 | 0.60 | 0.00 |
| scareware | 3 | 1.00 | 0.67 |

## Latency (single CPU thread, full pipeline)

mean 2.724 ms, p50 2.742 ms, p95 3.723 ms, p99 4.56 ms, throughput 465.9 msg/s (n=934)

## Uncertainty (bootstrap, 2000 resamples of chat test)

Text-only F1 95% CI [0.517, 0.794]; proposed F1 95% CI [0.852, 0.976]; improvement CI [0.13, 0.402] (share of resamples with no improvement: 0.0).

## Error analysis - proposed model mistakes on chat test

| id | type | S | message |
|---|---|---|---|
| S027 | FN | 0.177 | bro your account is gonna get hacked, there's a bug, give me your 2FA backup codes and I'll secure it |
| S028 | FN | 0.129 | Download this new game beta and test it for me, it's an exe, I'll pay you $20 in Nitro |
| S075 | FN | 0.172 | Hi friend, I'm stuck abroad and lost my wallet, please send me money via Western Union asap |
| S079 | FN | 0.153 | quick question, can you tell me the verification code you just got? I typed my number wrong |
| B008 | FP | 0.224 | the giveaway winner will be announced by the streamer on screen, never DM anyone your details |
| B012 | FP | 0.188 | the official merch store link is in the description |

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
- Riot Games: you have been selected for a ban appeal. Provide your login details to avoid permanent suspension
