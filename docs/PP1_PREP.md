# PP1 prep: D.M.T. Dissanayaka (IT23223462), 22 Oct 2026

## Before 22 Oct (in this order)

1. **Read and run every module yourself.** Lecture 7: "If you cannot explain, verify and defend it, do not present it as your work." Change something small in each module (e.g. add a cue) and re-run the tests so you know how it behaves.
2. **Push to the group GitHub** in your own branch (`feature/se-detection`), then open a PR. Add Planner tasks for F1, F2 and DistilBERT with evidence links.
3. **Collect user feedback (fills the red box on slide 3).** Show the demo to 3–5 people who moderate Discord/Twitch chats (or active streamers/viewers). Ask:
   - Would this alert help you act faster? What's missing from it?
   - Which flagged message would you NOT have removed? (false-positive check)
   - Is HIGH/CRITICAL the right cut-off for an alert?
   Record the answers, and make **one change** because of them (that's the "what I changed" line).
4. **Check the 160 scenario labels yourself** and fix any you disagree with, then re-run `train.py` + `evaluate.py` (the slide numbers come from `reports/results.json`).
5. **If your Zenodo / other dataset is ready:** `python scripts/train.py --extra data/raw/<file>` → `evaluate.py` → `make_figures.py` → rebuild the slides.
6. **Optional, strong:** run `scripts/finetune_distilbert.py` on Colab and report its test F1 as "Function 2 progress".
7. Fill in `docs/AI_USE_LOG.md` and today's diary entry.
8. Rehearse the 2-minute script (speaker notes, slides 1–3) until it takes 1:50.

## Demo runbook (60–90 s inside the group demo)

```bash
uvicorn se_detector.api:app --port 8004      # start before your slot
# open http://localhost:8004 → "Play demo scenario"
```
1. Point at a LOW benign message ("what settings do you use") → not flagged.
2. Point at "I'm so scared of this boss fight" → fear words, but **not** flagged (the tactic is aimed at nobody).
3. Click the **Twitch Trust & Safety** message → CRITICAL. Read the evidence: urgency "in the next 30 minutes", authority "I'm from Twitch Trust & Safety", fear "permanently banned", the suspicious link, and the URL passed to Gunarathna.
4. Type a live one: `yo I'm a mod, send me the code you just got or you'll lose your account` → flagged MEDIUM (authority + fear + credential request). This shows severity ranks it below the CRITICAL one, so moderators triage.
5. If asked for evidence: `python -m pytest -q` (48 pass + 1 known limitation) and `reports/RESULTS.md`.

**Fallback:** `reports/demo_screenshot.png`. Also record a 60-second screen capture of steps 1–4 beforehand.

## Likely questions, with evidence-based answers

| Question | Answer |
|---|---|
| Why not just use a phishing classifier? | Tested it: TF-IDF+LR trained on SMS + Zenodo scores 0.96 on SMS but only 0.82 on chat and misses 1 in 4 chat scams (recall 0.75). My hybrid: F1 0.94, recall 0.975. Gain CI +0.04 to +0.21. |
| How did you choose the weights? | They weren't chosen by hand. A logistic regression fitted on validation data (SMS + Zenodo validation + chat dev), negative coefficients clipped to 0, normalised to sum 1 → P 0.46, U 0.12, A 0.11, F 0.09, R 0.21. τ = 0.18 tuned for F1 on the same validation set. Test sets are never used. |
| Doesn't the ablation show the tactics don't matter? | At n=80 one message = 1.25 points; the single-tactic differences are noise. The robust result is hybrid vs text-only. Tactics also give the explanation and severity a moderator needs (NFR06). PP2 will test on the larger Zenodo set. |
| Weakest point? | Authority detection: recall 0.40 on chat and only 4% on the independent third-party set. Attackers imply authority ("This is an official notice from Amazon", "As per HMRC regulations") instead of claiming it. Also: protective advice ("never share your password") gets flagged. Both are my next tasks. |
| Isn't the test set biased, since you wrote it? | Partly, so I added two independent sets: the Zenodo dataset and a third-party tactic-labelled set. Also: dev/test split, rules tuned only on dev, bootstrap CIs. Next: second annotator + Cohen's κ. |
| Why is Zenodo F1 so high? | It was 1.000 at first because 43% of test messages had a near-copy in training. I fixed the split (near-duplicate groups) so leakage is 0%. The text model still scores 1.000 there because Zenodo messages are short and formulaic; chat is the harder, more realistic test. |
| Why is the hybrid slightly worse on SMS/Zenodo? | Trade-off: rule signals add recall on chat (+22.5 points) but cause a few extra false positives in-domain (SMS FPR 0.9% → 1.9%). For moderation, missing a scam is worse than one extra review. |
| Did you use all your datasets? | No. I audited three and rejected one: 20,000 rows but only 3 distinct sentences. |
| Why TF-IDF and not DistilBERT already? | It's a baseline the proposal requires, 1.6 MB and 3 ms. DistilBERT is scripted with the same interface; it needs a GPU (Colab) and is the PP2 deliverable. |
| How does it connect to the others? | JSON contract: URLs → Gunarathna; severity + tactics per pseudonymous user → Jayarathna's risk score; alert + evidence → dashboard. |
| Privacy/security? | Local only, no text stored, pseudonymous ids, input caps, HTML escaping in the UI, localhost binding. |
| Grooming (TAF)? | Out of PP1 scope; the off-platform/secrecy pattern ("move to DMs", "don't tell anyone") is the first building block. Needs ethics approval and specialist data. |
| How did you use AI? | (Your honest answer from the AI-use log: what it generated, what you changed, how you verified it.) |
