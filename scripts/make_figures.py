"""Render evaluation figures from reports/results.json into reports/fig_*.png."""
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parent.parent
R = json.loads((ROOT / "reports/results.json").read_text())
BASE, PROP, INK, MUTED, GRID = "#9AA3AF", "#007F76", "#1A2233", "#6B7280", "#E5E7EB"
plt.rcParams.update({"font.family": "Carlito", "font.size": 13, "axes.edgecolor": GRID, "axes.labelcolor": MUTED,
                     "xtick.color": MUTED, "ytick.color": MUTED, "text.color": INK})

text = R["models"]["E1 TF-IDF+LR (text only)"]
prop = R["models"]["E4 Proposed hybrid (P+U+A+F+R)"]

# Fig 1: headline metrics, grouped horizontal bars
metrics = [("Chat F1", "chat_test", "f1"), ("Chat recall", "chat_test", "recall"),
           ("Chat false-positive rate", "chat_test", "fpr"), ("SMS F1 (in-domain)", "sms_test", "f1")]
fig, ax = plt.subplots(figsize=(7.2, 3.6), dpi=200)
h = 0.36
for i, (lab, ds, m) in enumerate(metrics):
    y = len(metrics) - 1 - i
    for off, val, col in [(h / 2 + 0.02, text[ds][m], BASE), (-h / 2 - 0.02, prop[ds][m], PROP)]:
        ax.barh(y + off, val, height=h, color=col, edgecolor="white", linewidth=1)
        ax.text(val + 0.015, y + off, f"{val:.2f}", va="center", fontsize=12, color=INK)
ax.set_yticks(range(len(metrics))); ax.set_yticklabels([m[0] for m in reversed(metrics)], color=INK)
ax.set_xlim(0, 1.12); ax.set_xticks([0, .25, .5, .75, 1]); ax.grid(axis="x", color=GRID, lw=0.8); ax.set_axisbelow(True)
for s in ("top", "right", "left"):
    ax.spines[s].set_visible(False)
ax.tick_params(axis="y", length=0)
from matplotlib.patches import Patch
ax.legend(handles=[Patch(color=BASE, label="Text-only baseline (TF-IDF + LR)"), Patch(color=PROP, label="Proposed hybrid (P+U+A+F+R)")],
          loc="lower center", bbox_to_anchor=(0.45, 1.0), ncol=2, frameon=False, fontsize=11.5)
fig.tight_layout(); fig.savefig(ROOT / "reports/fig_headline.png", transparent=False, facecolor="white"); plt.close(fig)

# Fig 2: detection rate per attack type (dumbbell)
by = R["by_attack_type_chat_test"]
order = [k for k in ["impersonation", "pretexting", "payment_scam", "phishing", "scareware", "baiting", "giveaway_scam"] if k in by]
fig, ax = plt.subplots(figsize=(7.2, 3.6), dpi=200)
for i, k in enumerate(order):
    y = len(order) - 1 - i
    a, b = by[k]["text_only_flag_rate"], by[k]["proposed_flag_rate"]
    ax.plot([a, b], [y, y], color=GRID, lw=3, zorder=1)
    ax.scatter([a], [y], s=90, color=BASE, zorder=2, edgecolor="white", linewidth=1.5)
    ax.scatter([b], [y], s=90, color=PROP, zorder=3, edgecolor="white", linewidth=1.5)
    ax.text(1.04, y, f"{a:.0%} → {b:.0%}", va="center", fontsize=11.5, color=INK)
ax.set_yticks(range(len(order))); ax.set_yticklabels([f"{k.replace('_', ' ')} (n={by[k]['n']})" for k in reversed(order)], color=INK)
ax.set_xlim(-0.03, 1.25); ax.set_xticks([0, .25, .5, .75, 1]); ax.set_xticklabels(["0%", "25%", "50%", "75%", "100%"])
ax.grid(axis="x", color=GRID, lw=0.8); ax.set_axisbelow(True)
for s in ("top", "right", "left"):
    ax.spines[s].set_visible(False)
ax.tick_params(axis="y", length=0)
ax.legend(handles=[Patch(color=BASE, label="Text-only"), Patch(color=PROP, label="Proposed hybrid")],
          loc="lower center", bbox_to_anchor=(0.45, 1.0), ncol=2, frameon=False, fontsize=11.5)
fig.tight_layout(); fig.savefig(ROOT / "reports/fig_attack_types.png", facecolor="white"); plt.close(fig)
print("ok")
