"""Generate Argus figures v2: individual bar + radar, plus combined two-column."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import numpy as np
import os

OUT = os.path.dirname(__file__)

DPI = 300
# 2100×1050 px → 7.0×3.5 in; shrink slightly so tight-bbox stays within bounds
W_IN = 6.70
H_IN = 3.05

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 8,
    "axes.labelsize": 8.5,
    "axes.titlesize": 9,
    "legend.fontsize": 7.5,
    "xtick.labelsize": 7.5,
    "ytick.labelsize": 7,
})

MODELS = ["GPT-4o", "GPT-4o-mini", "Kimi K2 Instruct", "Claude Sonnet 4.5"]
SUITES = [
    "Command\nExecution",
    "Credential\nExfiltration",
    "Direct Task",
    "File Content",
    "Search Triggered\nExfiltration",
    "Web Content",
]

# ── Benchmark metrics (baseline vs. Argus) ────────────────────────────────────
baseline_dsr = [35.8, 45.0, 40.8,  9.2]
argus_dsr    = [84.2, 78.3, 88.3, 87.5]

suite_dsr = {
    "GPT-4o":            [100, 75, 75,  75,  80, 100],
    "GPT-4o-mini":       [ 80, 100, 40,  65,  95,  90],
    "Kimi K2 Instruct":  [ 90, 95, 75,  80,  95,  95],
    "Claude Sonnet 4.5": [ 90, 90, 60, 100,  95,  90],
}

MODEL_COLORS = {
    "GPT-4o":            "#1565C0",
    "GPT-4o-mini":       "#E65100",
    "Kimi K2 Instruct":  "#2E7D32",
    "Claude Sonnet 4.5": "#6A1B9A",
}

markers = {
    "GPT-4o":            "o",
    "GPT-4o-mini":       "s",
    "Kimi K2 Instruct":  "^",
    "Claude Sonnet 4.5": "D",
}

# ── combined two-column figure ────────────────────────────────────────────────
fig = plt.figure(figsize=(W_IN, H_IN))

# Give radar more horizontal room for spoke labels and legend
gs = gridspec.GridSpec(1, 2, figure=fig,
                       left=0.07, right=0.97,
                       top=0.91, bottom=0.22,
                       wspace=0.40,
                       width_ratios=[1.0, 1.10])

# ── Left: grouped bar chart ───────────────────────────────────────────────────
ax1 = fig.add_subplot(gs[0])
x = np.arange(len(MODELS))
w = 0.35

b1 = ax1.bar(x - w/2, baseline_dsr, w, label="Baseline (No Argus)",
             color="#90CAF9", edgecolor="black", linewidth=0.6)
b2 = ax1.bar(x + w/2, argus_dsr, w, label="Argus (Blocking)",
             color="#1565C0", edgecolor="black", linewidth=0.6)

for bar in b1:
    ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.8,
             f"{bar.get_height():.1f}%", ha="center", va="bottom", fontsize=6.5)
for bar in b2:
    ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.8,
             f"{bar.get_height():.1f}%", ha="center", va="bottom", fontsize=6.5)

ax1.set_ylabel("Defense Success Rate (DSR) (%)")
ax1.set_xlabel("Models")
ax1.set_xticks(x)
ax1.set_xticklabels(MODELS, fontsize=7, rotation=12, ha="right")
ax1.set_ylim(0, 110)
ax1.yaxis.grid(True, alpha=0.35, linestyle="--")
ax1.set_axisbelow(True)
ax1.legend(loc="upper left", fontsize=7)
ax1.spines[["top", "right"]].set_visible(False)
ax1.set_title("(a) Baseline vs. Argus DSR", fontsize=9, pad=6)

# ── Right: radar / spider chart ───────────────────────────────────────────────
ax2 = fig.add_subplot(gs[1], polar=True)
ax2.set_theta_offset(np.pi / 2)
ax2.set_theta_direction(-1)

N = len(SUITES)
angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
angles += angles[:1]

for model in MODELS:
    vals = suite_dsr[model] + suite_dsr[model][:1]
    ax2.plot(angles, vals, marker=markers[model], linewidth=1.5, markersize=4,
             label=model, color=MODEL_COLORS[model])
    ax2.fill(angles, vals, alpha=0.07, color=MODEL_COLORS[model])

ax2.set_xticks(angles[:-1])
ax2.set_xticklabels(SUITES, fontsize=7)
ax2.set_ylim(0, 100)
ax2.set_yticks([20, 40, 60, 80, 100])
ax2.set_yticklabels(["20%", "40%", "60%", "80%", "100%"], fontsize=6, color="grey")
ax2.yaxis.grid(True, linestyle="--", alpha=0.5)
ax2.xaxis.grid(True, linestyle="--", alpha=0.3)

ax2.set_title("(b) Per-Suite DSR (Argus Blocking)", fontsize=9, pad=14)

# Shared model legend centred at the bottom of the figure (inside bounds)
handles, labels = ax2.get_legend_handles_labels()
fig.legend(handles, labels, loc="lower center", ncol=4,
           fontsize=7.5, frameon=True,
           bbox_to_anchor=(0.50, 0.01))

for ext in ("pdf", "png"):
    plt.savefig(os.path.join(OUT, f"combined_dsr_v2.{ext}"),
                dpi=DPI, bbox_inches="tight")
plt.close()

print("Combined two-column figure saved.")

# ── Individual Figure 1: bar chart (≤1000×750 px) ────────────────────────────
# coral-red = baseline "problem", teal = Argus "protection"
BAR_BASELINE = "#EF9A9A"   # soft coral-red
BAR_ARGUS    = "#00897B"   # teal / emerald

fig, ax = plt.subplots(figsize=(2.90, 2.20))

x = np.arange(len(MODELS))
w = 0.35
b1 = ax.bar(x - w/2, baseline_dsr, w, label="Baseline (No Argus)",
            color=BAR_BASELINE, edgecolor="black", linewidth=0.5)
b2 = ax.bar(x + w/2, argus_dsr, w, label="Argus (Blocking)",
            color=BAR_ARGUS, edgecolor="black", linewidth=0.5)

for bar in b1:
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.8,
            f"{bar.get_height():.1f}%", ha="center", va="bottom", fontsize=5)
for bar in b2:
    ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.8,
            f"{bar.get_height():.1f}%", ha="center", va="bottom", fontsize=5)

model_labels = ["GPT-4o", "GPT-4o-mini", "Kimi K2\nInstruct", "Claude\nSonnet 4.5"]
ax.set_xticks(x)
ax.set_xticklabels(model_labels, fontsize=5.5, ha="center")
ax.set_ylabel("Defense Success Rate (DSR) (%)", fontsize=6)
ax.set_xlabel("Models", labelpad=6, fontsize=6)
ax.set_ylim(0, 112)
ax.yaxis.grid(True, alpha=0.35, linestyle="--")
ax.set_axisbelow(True)
ax.legend(loc="upper left", fontsize=5.5)
ax.spines[["top", "right"]].set_visible(False)
plt.tight_layout(pad=0.4)
for ext in ("pdf", "png"):
    plt.savefig(os.path.join(OUT, f"dsr_baseline_vs_argus_v2.{ext}"),
                dpi=DPI, bbox_inches="tight")
plt.close()
print("Individual bar chart saved.")

# ── Individual Figure 2: radar chart (≤1000×750 px) ──────────────────────────
# Nominal 2.3×2.3 in square; right margin holds legend within tight-bbox
fig, ax = plt.subplots(figsize=(2.30, 2.30), subplot_kw=dict(polar=True))
ax.set_theta_offset(np.pi / 2)
ax.set_theta_direction(-1)

N = len(SUITES)
angles = np.linspace(0, 2 * np.pi, N, endpoint=False).tolist()
angles += angles[:1]

for model in MODELS:
    vals = suite_dsr[model] + suite_dsr[model][:1]
    ax.plot(angles, vals, marker=markers[model], linewidth=1.2, markersize=3,
            label=model, color=MODEL_COLORS[model])
    ax.fill(angles, vals, alpha=0.08, color=MODEL_COLORS[model])

ax.set_xticks(angles[:-1])
ax.set_xticklabels(SUITES, fontsize=5.5)
ax.set_ylim(0, 100)
ax.set_yticks([20, 40, 60, 80, 100])
ax.set_yticklabels(["20%", "40%", "60%", "80%", "100%"], fontsize=4.5, color="grey")
ax.yaxis.grid(True, linestyle="--", alpha=0.5)
ax.xaxis.grid(True, linestyle="--", alpha=0.3)

# Legend top-right, above the polar circle
ax.legend(loc="upper left", bbox_to_anchor=(1.12, 1.30),
          fontsize=5.5, frameon=True, borderaxespad=0)
plt.subplots_adjust(left=0.08, right=0.66, top=0.88, bottom=0.08)
for ext in ("pdf", "png"):
    plt.savefig(os.path.join(OUT, f"radar_per_suite_dsr_v2.{ext}"),
                dpi=DPI, bbox_inches="tight")
plt.close()
print("Individual radar chart saved.")

print("\nAll outputs written to:", OUT)
