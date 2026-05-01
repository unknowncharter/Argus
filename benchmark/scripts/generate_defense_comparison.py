"""Defense comparison figures: heatmap + line chart (GPT-4o, ORBIT benchmark).

Both figures fit within 1000×700 px at DPI 300 (≤3.33×2.33 in).

Outputs
-------
defense_comparison.{pdf,png}       — annotated heatmap
defense_comparison_line.{pdf,png}  — multi-line metric chart
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import os

OUT = os.path.dirname(__file__)
DPI = 300

# ── Defense comparison metrics ────────────────────────────────────────────────
# Line-chart order: weakest → strongest defense (narrative arc)
LINE_ORDER = [
    "Baseline",
    "Delimiters",
    "Instr.\nPrevention",
    "Llama\nGuard",
    "Argus",
]
LINE_DSR     = [35.8, 40.8, 44.2, 74.2, 84.2]
LINE_FPR     = [ 2.9, 17.1, 14.3,  8.6,  5.7]
LINE_UTILITY = [85.7, 67.9, 89.3, 83.6, 75.0]

# Heatmap order: best → worst by DSR
HEAT_DEFENSES = ["Argus", "Llama Guard", "Instr. Prevention", "Delimiters", "No Defense"]
METRICS       = ["DSR", "FPR", "Utility"]
INVERT_COL    = [False, True, False]
HEAT_DATA = np.array([
    [84.2,  5.7, 75.0],
    [74.2,  8.6, 83.6],
    [44.2, 14.3, 89.3],
    [40.8, 17.1, 67.9],
    [35.8,  2.9, 85.7],
])

# ── Style ─────────────────────────────────────────────────────────────────────
plt.rcParams.update({
    "font.family": "serif",
    "font.serif":  ["Linux Libertine O", "Linux Libertine", "Times New Roman", "Times", "DejaVu Serif"],
    "font.size":    7.5,
})

C_DSR    = "#1565C0"
C_FPR    = "#B71C1C"
C_UTIL   = "#2E7D32"
C_ARGUS  = "#4A0080"
CMAP     = plt.get_cmap("RdYlGn")

# ══════════════════════════════════════════════════════════════════════════════
# Figure 1 — Heatmap   (target ≤ 1000×700 px @ 300 DPI → ≤3.33×2.33 in)
# ══════════════════════════════════════════════════════════════════════════════
nrows, ncols = HEAT_DATA.shape
CELL_W, CELL_H = 1.0, 0.60

# Per-column normalisation
normed = np.zeros_like(HEAT_DATA)
for j in range(ncols):
    col = HEAT_DATA[:, j]
    lo, hi = col.min(), col.max()
    n = (col - lo) / (hi - lo) if hi > lo else np.full_like(col, 0.5)
    normed[:, j] = 1.0 - n if INVERT_COL[j] else n

fig1, ax1 = plt.subplots(figsize=(3.10, 2.10))
ax1.set_xlim(0, ncols * CELL_W)
ax1.set_ylim(0, nrows * CELL_H)
ax1.set_aspect("auto")

for i in range(nrows):
    row_y = (nrows - 1 - i) * CELL_H
    for j in range(ncols):
        color = CMAP(normed[i, j])
        ax1.add_patch(plt.Rectangle((j * CELL_W, row_y), CELL_W, CELL_H,
                                    color=color, zorder=1))
        lum   = 0.299*color[0] + 0.587*color[1] + 0.114*color[2]
        txt_c = "black" if lum > 0.45 else "white"
        ax1.text(j * CELL_W + CELL_W/2, row_y + CELL_H/2,
                 f"{HEAT_DATA[i,j]:.1f}%",
                 ha="center", va="center",
                 fontsize=8, fontweight="bold", color=txt_c, zorder=2)

# Argus highlight border
top_y = (nrows - 1) * CELL_H
ax1.add_patch(plt.Rectangle((0, top_y), ncols * CELL_W, CELL_H,
                             fill=False, edgecolor=C_ARGUS, linewidth=2.2, zorder=3))

for j in range(ncols + 1):
    ax1.axvline(j * CELL_W, color="white", linewidth=1.2, zorder=4)
for i in range(nrows + 1):
    ax1.axhline(i * CELL_H, color="white", linewidth=1.2, zorder=4)

ax1.set_xticks([(j + 0.5) * CELL_W for j in range(ncols)])
ax1.set_xticklabels(
    [f"{m}\n({'↓' if inv else '↑'} better)" for m, inv in zip(METRICS, INVERT_COL)],
    fontsize=7, va="bottom",
)
ax1.xaxis.set_tick_params(length=0)
ax1.xaxis.tick_top()

ax1.set_yticks([(nrows - 1 - i + 0.5) * CELL_H for i in range(nrows)])
ax1.set_yticklabels(HEAT_DEFENSES, fontsize=7.2, ha="right")
ax1.yaxis.set_tick_params(length=0, pad=3)

for sp in ax1.spines.values():
    sp.set_visible(False)

ax1.set_title("Defense Comparison  (GPT-4o · ORBIT)",
              fontsize=8, pad=26)
fig1.text(0.5, 0.01,
          "Color normalised per column  ·  green = better, red = worse",
          ha="center", va="bottom", fontsize=5.5, color="grey", style="italic")

plt.tight_layout(rect=[0, 0.04, 1, 1])
for ext in ("pdf", "png"):
    fig1.savefig(os.path.join(OUT, f"defense_comparison.{ext}"),
                 dpi=DPI, bbox_inches="tight")
plt.close(fig1)
print("Heatmap saved.")

# ══════════════════════════════════════════════════════════════════════════════
# Figure 2 — Multi-line chart
# 5.0 × 3.2 in @ DPI 300 = 1500 × 960 px.
# Defenses ordered weakest→strongest on X; three lines for DSR / FPR / Utility.
# ══════════════════════════════════════════════════════════════════════════════
x = np.arange(len(LINE_ORDER))

plt.rcParams.update({
    "font.family":    "serif",
    "font.size":       7,
    "axes.labelsize":  7,
    "axes.titlesize":  8,
    "legend.fontsize":  5.5,
    "xtick.labelsize":  6.5,
    "ytick.labelsize":  6.5,
})

def _draw_line_chart(ax, fig, fs_val, fs_legend, lw, ms, label_fs, xoff_right,
                     legend_kw=None):
    """Draw the line chart onto ax. Returns (l_dsr, l_fpr, l_util)."""
    kw = dict(linewidth=lw, markersize=ms, zorder=3, clip_on=False)
    l_dsr,  = ax.plot(x, LINE_DSR,     color=C_DSR,  marker="o",
                      label="DSR (%)", **kw)
    l_util, = ax.plot(x, LINE_UTILITY, color=C_UTIL, marker="^",
                      label="Utility (%)", linestyle="--", **kw)
    l_fpr,  = ax.plot(x, LINE_FPR,     color=C_FPR,  marker="s",
                      label="FPR (%)", linestyle=":", **kw)

    # Value labels per point.
    # For Llama Guard (idx=3): DSR=74.2 is BELOW Utility=83.6, so:
    #   DSR label goes BELOW its point, Utility label goes ABOVE its point.
    # For all others: DSR label above, Utility label below.
    # fmt: (dsr_dy, dsr_va, util_dy, util_va, ha, xoff_mult)
    # fmt: (dsr_dy, dsr_va, util_dy, util_va, ha, xoff_mult)
    cfgs = [
        (+4.5, "bottom", -5.5, "top",    "center", 0),   # No Defense
        (+4.5, "bottom", -5.5, "top",    "center", 0),   # Delimiters
        (+4.5, "bottom", -5.5, "top",    "center", 0),   # Instr. Prevention
        (-5.5, "top",    +5.0, "bottom", "center",  0),  # Llama Guard — DSR just below point, Utility above
        (+4.5, "bottom", -5.5, "top",    "center",  0),  # Argus
    ]
    for xi, (d, f, u) in enumerate(zip(LINE_DSR, LINE_FPR, LINE_UTILITY)):
        ddy, dva, udy, uva, ha, xm = cfgs[xi]
        xo = xoff_right * xm
        ax.text(xi + xo, d + ddy, f"{d:.1f}%", ha=ha, va=dva,
                fontsize=label_fs, color=C_DSR,  fontweight="semibold")
        ax.text(xi + xo, u + udy, f"{u:.1f}%", ha=ha, va=uva,
                fontsize=label_fs, color=C_UTIL, fontweight="semibold")
        # FPR at Argus (idx=4): shift left to avoid crowding the right edge
        fpr_xo = -xoff_right if xi == 4 else 0
        ax.text(xi + fpr_xo, f + 2.8, f"{f:.1f}%", ha="center", va="bottom",
                fontsize=label_fs, color=C_FPR,  fontweight="semibold")

    ax.fill_between(x, LINE_DSR, alpha=0.08, color=C_DSR, zorder=1)
    ax.axvline(x[-1], color=C_ARGUS, linewidth=1.0, linestyle="--",
               alpha=0.45, zorder=1)
    ax.text(x[-1] - xoff_right * 0.8, 30, "Argus",
            fontsize=label_fs + 0.5, color=C_ARGUS,
            fontstyle="italic", va="center", ha="right")

    ax.set_xticks(x)
    ax.set_xticklabels(LINE_ORDER, fontsize=fs_val, rotation=0, ha="center")
    for tick in ax.get_xticklabels():
        tick.set_multialignment("center")
    ax.set_xlabel("Defense", labelpad=4, fontsize=fs_val)
    ax.xaxis.set_label_coords(0.42, -0.26)
    ax.set_ylabel("Value (%)", labelpad=4, fontsize=fs_val)
    ax.set_ylim(0, 118)
    ax.set_xlim(-0.35, len(LINE_ORDER) - 0.35)
    ax.yaxis.grid(True, linestyle="--", alpha=0.30)
    ax.set_axisbelow(True)
    ax.spines[["top", "right"]].set_visible(False)
    # 40px left ≈ 0.048 axes-x, 5px up ≈ 0.010 axes-y (at 1000×700 px canvas)
    default_legend_kw = dict(
        loc="upper right", bbox_to_anchor=(0.857, 1.00),
        frameon=False, borderpad=0.4, handlelength=1.6,
        labelspacing=0.30, handletextpad=0.4, fontsize=max(fs_legend - 0.8, 4.0),
    )
    if legend_kw:
        default_legend_kw.update(legend_kw)
    ax.legend(handles=[l_dsr, l_fpr, l_util], **default_legend_kw)
    return l_dsr, l_fpr, l_util


# ── Small version: exactly 1000×700 px @ 300 DPI (3.333×2.333 in) ────────────
plt.rcParams.update({
    "font.family": "serif",
    "font.serif":  ["Linux Libertine O", "Linux Libertine", "Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 7,
    "axes.labelsize": 7, "xtick.labelsize": 6.5, "ytick.labelsize": 6.5,
})
_W_IN, _H_IN = 1000 / DPI, 700 / DPI   # 3.333 × 2.333 in
fig2, ax2 = plt.subplots(figsize=(_W_IN, _H_IN))
fig2.subplots_adjust(left=0.13, right=0.97, top=0.96, bottom=0.24)
_draw_line_chart(ax2, fig2, fs_val=6.5, fs_legend=5.5, lw=1.6,
                 ms=4.5, label_fs=5.0, xoff_right=0.15)
for ext in ("pdf", "png"):
    fig2.savefig(os.path.join(OUT, f"defense_comparison_line.{ext}"),
                 dpi=DPI)
plt.close(fig2)
print("Small line chart saved.")

# ── Large version: ~2100×1000 px ─────────────────────────────────────────────
plt.rcParams.update({
    "font.family": "serif", "font.size": 12,
    "axes.labelsize": 13, "xtick.labelsize": 12, "ytick.labelsize": 12,
})
fig3, ax3 = plt.subplots(figsize=(7.00, 3.33))
fig3.subplots_adjust(left=0.09, right=0.97, top=0.96, bottom=0.20)
_draw_line_chart(ax3, fig3, fs_val=12, fs_legend=10, lw=2.6,
                 ms=8, label_fs=9.5, xoff_right=0.18)
for ext in ("pdf", "png"):
    fig3.savefig(os.path.join(OUT, f"defense_comparison_line_large.{ext}"),
                 dpi=DPI, bbox_inches="tight")
plt.close(fig3)
print("Large line chart saved.")
print("All outputs written to:", OUT)
