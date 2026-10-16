# Chat-scenario test set: annotation guidelines

File: `data/scenarios/chat_scenarios.csv` (160 messages: 80 social-engineering, 80 legitimate).
They are split once (seed 7, stratified by attack type) into **dev** (80) and **test** (80).
Only the dev half was used to tune cue lexicons and to fit severity weights; the test half is reported.

**Why synthetic:** no public dataset contains live-stream chat with manipulation-tactic labels
(the Zenodo multiclass dataset has attack types but no urgency/authority/fear labels, per proposal §2.5).
These messages are modelled on publicly reported Discord/Twitch/Steam scam formats. Domains are invented.

| label | rule (proposal Table 10) | example |
|---|---|---|
| is_se | message tries to make the reader disclose data, pay, click, install or act against their interest | "send me the 6 digit code" |
| urgency | pressures immediate action (time limit, scarcity, "now") | "within 30 minutes" |
| authority | claims or implies a trusted institution or role | "I'm from Twitch Trust & Safety" |
| fear | threatens negative consequences **for the reader** | "your account will be banned" |

Notes
* The speaker's own emotion is **not** fear ("I'm so scared of this boss"); a tactic can appear in benign text
  ("stream starts in 5 minutes" = urgency, but not an attack). That is why tactics alone don't decide the verdict.
* 38 of the 80 legitimate messages are *hard negatives* (security PSAs, real mods, game vocabulary like "police", "bank").

**Known limitation and next step:** the set was drafted with AI assistance and labelled by one person.
Before PP2: (1) a second annotator labels the set independently and Cohen's κ is reported;
(2) annotate a sample of the Zenodo dataset with the same scheme; (3) collect real moderated chat logs where platform terms allow.
