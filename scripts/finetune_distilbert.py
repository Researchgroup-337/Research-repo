"""Fine-tune DistilBERT as a drop-in replacement for the TF-IDF text model (P).

STATUS (PP1): implemented, NOT yet run - needs a GPU and Hugging Face access.
Run on Google Colab (Runtime -> T4 GPU):

    !pip install transformers datasets accelerate scikit-learn joblib
    # upload data/processed/{train,val,test}.csv  (created by scripts/train.py)
    !python finetune_distilbert.py --data data/processed --out models/distilbert

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
    args = ap.parse_args()

    tok = AutoTokenizer.from_pretrained(args.base)
    def load(name):
        df = pd.read_csv(Path(args.data) / f"{name}.csv")[["text", "label"]]
        return Dataset.from_pandas(df).map(lambda b: tok(b["text"], truncation=True, max_length=128), batched=True)
    train, val, test = load("train"), load("val"), load("test")

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
    print("TEST:", trainer.evaluate(test))
    trainer.save_model(args.out); tok.save_pretrained(args.out)


if __name__ == "__main__":
    main()
