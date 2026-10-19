"""Fine-tune DistilBERT as a drop-in replacement for the TF-IDF text model (P).

STATUS: first experiment (text model only). Needs a GPU: run it on Google Colab
(Runtime -> Change runtime type -> T4 GPU) with notebooks/distilbert_colab.ipynb, or:

    !pip install -q transformers datasets accelerate
    !python scripts/finetune_distilbert.py --epochs 3

After training it evaluates on the SAME held-out test sets as the TF-IDF baseline
(SMS test, Zenodo test, chat test) and writes reports/distilbert_results.json with a
side-by-side table: TF-IDF + LR (text only) vs DistilBERT (text only).

Then copy models/distilbert back and run:
    python scripts/train.py --text-model distilbert     (PP2 work item)

Why DistilBERT: 40% smaller / 60% faster than BERT with ~97% of its accuracy,
so it can still meet the real-time latency budget on CPU, and contextual
embeddings should catch *implied* authority/urgency that the lexicon misses
(see reports/RESULTS.md, "Authority cues missed").
"""
import argparse
from pathlib import Path

import numpy as np
import pandas as pd


class DistilBertTextModel:
    """Same interface as the sklearn pipeline: predict_proba(list[str]) -> (n, 2)."""

    def __init__(self, path, max_len=128, device=None):
        import torch
        from transformers import AutoModelForSequenceClassification, AutoTokenizer
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(path)
        self.model = AutoModelForSequenceClassification.from_pretrained(path).eval()
        self.device = device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        self.max_len = max_len

    def predict_proba(self, texts):
        with self.torch.no_grad():
            enc = self.tok(list(texts), truncation=True, padding=True, max_length=self.max_len, return_tensors="pt").to(self.device)
            logits = self.model(**enc).logits
            return self.torch.softmax(logits, dim=-1).cpu().numpy()


def main():
    from datasets import Dataset
    from sklearn.metrics import f1_score, precision_score, recall_score
    from transformers import (AutoModelForSequenceClassification, AutoTokenizer, DataCollatorWithPadding,
                              Trainer, TrainingArguments)

    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data/processed")
    ap.add_argument("--out", default="models/distilbert")
    ap.add_argument("--base", default="distilbert-base-uncased")
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--scenarios", default="data/scenarios/chat_scenarios.csv")
    ap.add_argument("--baseline", default="reports/results.json", help="TF-IDF results to compare against")
    ap.add_argument("--extra", nargs="*", default=[], help="extra training CSVs (text,label), e.g. data/extra/extra_train_smishing.csv")
    ap.add_argument("--chat-dev", action="store_true", help="also train on the 80 chat DEV messages (the chat TEST set stays unseen)")
    ap.add_argument("--external", default="data/extra/external_test_real_smishing.csv", help="real scams, never trained on")
    ap.add_argument("--tag", default="", help="suffix for the results file, e.g. v2")
    args = ap.parse_args()

    tok = AutoTokenizer.from_pretrained(args.base)
    def to_ds(df):
        df = df[["text", "label"]].dropna().astype({"text": str, "label": int}).reset_index(drop=True)
        return Dataset.from_pandas(df).map(lambda b: tok(b["text"], truncation=True, max_length=128), batched=True)
    def load(name):
        return pd.read_csv(Path(args.data) / f"{name}.csv")
    tr = load("train")
    parts = [tr[["text", "label"]]]
    for f in args.extra:                                   # extra datasets (already de-duplicated against val/test)
        parts.append(pd.read_csv(f)[["text", "label"]]); print("extra:", f, len(parts[-1]))
    if args.chat_dev:                                      # live-chat examples from the DEV split only
        sc = pd.read_csv(args.scenarios); dev = sc[sc.split == "dev"]
        parts.append(pd.DataFrame({"text": dev.text, "label": dev.is_se})); print("chat dev:", len(dev))
    train_df = pd.concat(parts, ignore_index=True)
    print("training messages:", len(train_df), "scams:", int(train_df.label.sum()))
    train, val, test = to_ds(train_df), to_ds(load("val")), to_ds(load("test"))

    # class weights: SE messages are the minority class
    y = np.array(train["label"]); pos_w = (len(y) - y.sum()) / max(y.sum(), 1)
    model = AutoModelForSequenceClassification.from_pretrained(args.base, num_labels=2)

    import torch
    class WeightedTrainer(Trainer):
        def compute_loss(self, model, inputs, return_outputs=False, **kw):
            labels = inputs.pop("labels")
            out = model(**inputs)
            loss = torch.nn.functional.cross_entropy(out.logits, labels,
                                                     weight=torch.tensor([1.0, float(pos_w)], device=out.logits.device))
            return (loss, out) if return_outputs else loss

    def metrics(p):
        pred = p.predictions.argmax(-1)
        return {"f1": f1_score(p.label_ids, pred), "precision": precision_score(p.label_ids, pred),
                "recall": recall_score(p.label_ids, pred)}

    targs = TrainingArguments(output_dir=args.out + "_ckpt", num_train_epochs=args.epochs, learning_rate=2e-5,
                              per_device_train_batch_size=32, per_device_eval_batch_size=64, weight_decay=0.01,
                              eval_strategy="epoch", save_strategy="epoch", load_best_model_at_end=True,
                              metric_for_best_model="f1", seed=42, report_to=[])
    trainer = WeightedTrainer(model=model, args=targs, train_dataset=train, eval_dataset=val,
                              data_collator=DataCollatorWithPadding(tok), compute_metrics=metrics)
    trainer.train()
    print("TEST (SMS + Zenodo):", trainer.evaluate(test))
    trainer.save_model(args.out); tok.save_pretrained(args.out)
    compare(DistilBertTextModel(args.out), args)


def scores(y, p, thr=0.5):
    """Same metrics as scripts/evaluate.py: F1, recall, false-positive rate."""
    from sklearn.metrics import f1_score, recall_score
    y = np.asarray(y); pred = (np.asarray(p) >= thr).astype(int)
    neg = (y == 0).sum()
    return {"f1": round(float(f1_score(y, pred, zero_division=0)), 4),
            "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
            "fpr": round(float(((pred == 1) & (y == 0)).sum() / neg), 4) if neg else 0.0, "n": int(len(y))}


def compare(model, args):
    """Evaluate DistilBERT on the held-out test sets and print it next to the TF-IDF baseline."""
    import json
    test = pd.read_csv(Path(args.data) / "test.csv")
    sc = pd.read_csv(args.scenarios); chat = sc[sc.split == "test"]
    sets = {"sms_test": test[test.source == "sms_spam_collection"], "zenodo_test": test[test.source == "zenodo_se"]}
    out = {"model": "DistilBERT (text only, fine-tuned)", "epochs": args.epochs,
           "extra_training": args.extra, "chat_dev_in_training": bool(args.chat_dev)}
    for name, df in sets.items():
        out[name] = scores(df.label, predict(model, df.text))
    out["chat_test"] = scores(chat.is_se, predict(model, chat.text))
    if args.external and Path(args.external).exists():     # real scams never trained on: detection rate
        ext = pd.read_csv(args.external)
        out["external_real_smishing"] = {"n": len(ext), "detection_rate": round(float((predict(model, ext.text) >= 0.5).mean()), 4)}

    base = None
    if Path(args.baseline).exists():
        base = json.loads(Path(args.baseline).read_text())["models"]["E1 TF-IDF+LR (text only)"]
    print("\n| Test set | TF-IDF + LR F1 | DistilBERT F1 | TF-IDF recall | DistilBERT recall | DistilBERT FPR |")
    print("|---|---|---|---|---|---|")
    for k in ("chat_test", "sms_test", "zenodo_test"):
        b = base[k] if base else {"f1": float("nan"), "recall": float("nan")}
        print(f"| {k} | {b['f1']:.3f} | {out[k]['f1']:.3f} | {b['recall']:.3f} | {out[k]['recall']:.3f} | {out[k]['fpr']:.3f} |")
    Path("reports").mkdir(exist_ok=True)
    if "external_real_smishing" in out:
        eb = Path("reports/external_test.json")
        ref = json.loads(eb.read_text()) if eb.exists() else {}
        print(f"\nReal scam SMS ({out['external_real_smishing']['n']}, never trained on): DistilBERT detects "
              f"{out['external_real_smishing']['detection_rate']:.3f} | TF-IDF text-only {ref.get('text_only_detection_rate', float('nan')):.3f} "
              f"| my hybrid {ref.get('hybrid_detection_rate', float('nan')):.3f}")
    name = f"reports/distilbert_results{('_' + args.tag) if args.tag else ''}.json"
    Path(name).write_text(json.dumps(out, indent=2))
    print("\nsaved", name)


def predict(model, texts, batch=64):
    texts = [str(t) for t in texts]
    return np.concatenate([model.predict_proba(texts[i:i + batch])[:, 1] for i in range(0, len(texts), batch)])


if __name__ == "__main__":
    main()
