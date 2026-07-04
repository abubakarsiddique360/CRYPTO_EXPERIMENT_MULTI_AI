from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from scripts.latex_style import (
    PLATFORM_COLORS,
    apply_latex_rcparams,
    fig_dpi,
    fig_size,
    legend_inside_kwargs,
    output_dir,
    is_latex_style,
)


PLATFORMS: List[Tuple[str, str]] = [
    ("deepseek", "DeepSeek (deepseek-chat)"),
    ("chatgpt", "ChatGPT (gpt-5-mini)"),
    ("gemini", "Gemini (gemini-3-flash-preview)"),
    ("grok", "Grok (grok-4.1-fast-reasoning)"),
]


def pick_latest(platform: str, condition: str) -> Path:
    raw_dir = Path("data") / "results" / platform / condition / "raw_results"
    cands = [
        p
        for p in raw_dir.glob("*.json")
        if ".bak_" not in p.name and "partial" not in p.name and "CHECKPOINT" not in p.name
    ]
    cands.sort(key=lambda p: (p.stat().st_mtime, p.name))
    if not cands:
        raise FileNotFoundError(f"No raw_results JSON found under {raw_dir}")
    return cands[-1]


def as_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    return str(v).strip().lower() in {"1", "true", "t", "yes", "y"}


def as_float(v: Any) -> Optional[float]:
    try:
        if v is None:
            return None
        return float(v)
    except Exception:
        return None


def rolling_mean(values: List[Optional[float]], window: int) -> List[Optional[float]]:
    if window <= 1:
        return values[:]

    out: List[Optional[float]] = []
    buf: List[float] = []

    for v in values:
        if v is None:
            out.append(None)
            buf.clear()
            continue

        buf.append(v)
        if len(buf) > window:
            buf.pop(0)

        if len(buf) < window:
            out.append(None)
        else:
            out.append(sum(buf) / window)

    return out


def load_results(path: Path) -> List[Dict[str, Any]]:
    doc = json.loads(path.read_text(encoding="utf-8"))
    results = doc.get("results")
    return results if isinstance(results, list) else []


def extract_overall_scores(results: List[Dict[str, Any]]) -> List[Optional[float]]:
    scores: List[Optional[float]] = []
    for r in results:
        ev = r.get("evaluation")
        if not isinstance(ev, dict):
            scores.append(None)
            continue
        if not as_bool(ev.get("response_success", False)):
            scores.append(None)
            continue
        scores.append(as_float(ev.get("overall_score")))
    return scores


def ieee_style() -> None:
    base = {
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "font.size": 8,
        "axes.titlesize": 9,
        "axes.labelsize": 8,
        "legend.fontsize": 7,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "axes.linewidth": 0.8,
    }
    plt.rcParams.update(apply_latex_rcparams(base=base))


def plot_trend(condition: str, out_path: Path, title: str) -> None:
    ieee_style()

    fig, ax = plt.subplots(figsize=fig_size(default=(4.8, 4.8)), dpi=fig_dpi(default=300))

    window = 20
    max_n = 0

    for platform, label in PLATFORMS:
        line_color = PLATFORM_COLORS.get(platform, None)
        short_label = label.split(' (', 1)[0]
        latest = pick_latest(platform, condition)
        results = load_results(latest)
        overall = extract_overall_scores(results)
        trend = rolling_mean(overall, window)

        x = list(range(len(trend)))
        max_n = max(max_n, len(trend))

        ax.plot(
            x,
            trend,
            linewidth=0.9,
            label=short_label,
            color=line_color,
        )

    ax.set_xlabel("Test Sequence")
    ax.set_ylabel("Score")

    ax.set_ylim(0.0, 1.10)
    ax.set_xlim(0, max(0, max_n - 1))

    if max_n >= 800:
        ax.set_xticks([0, 200, 400, 600, 800])
    elif max_n >= 600:
        ax.set_xticks([0, 200, 400, 600])
    elif max_n >= 400:
        ax.set_xticks([0, 200, 400])

    ax.set_yticks([0.0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.grid(True, which="major", axis="both", linewidth=0.25, alpha=0.35)

    lk = {
        "title": f"Overall(n={window} tests)",
        "loc": "upper right",
        "ncol": 2,
        "frameon": True,
        "framealpha": 0.85,
        "edgecolor": "black",
        "borderpad": 0.3,
        "handlelength": 2.2,
        "columnspacing": 1.2,
    }
    lk.update(legend_inside_kwargs(default_ncol=2))
    ax.legend(**lk)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.subplots_adjust(top=0.92, bottom=0.14, left=0.12, right=0.98)
    fig.savefig(out_path)
    plt.close(fig)


def main() -> int:
    out_dir = output_dir()

    plot_trend(
        "algorithm_hidden",
        out_dir / "hidden_performance_trend_over_test_sequence.png",
        "Hidden Algorithm Experiment: Performance Trend Over Test Sequence",
    )

    plot_trend(
        "algorithm_informed",
        out_dir / "informed_performance_trend_over_test_sequence.png",
        "Informed Algorithm Experiment: Performance Trend Over Test Sequence",
    )

    print("Wrote:", out_dir / "hidden_performance_trend_over_test_sequence.png")
    print("Wrote:", out_dir / "informed_performance_trend_over_test_sequence.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())








