from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from scripts.latex_style import PLATFORM_COLORS, apply_latex_rcparams, fig_dpi, fig_size, legend_inside_kwargs, output_dir, is_latex_style


_BASE_RCPARAMS = {
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 9,
    "axes.titlesize": 10,
    "axes.labelsize": 9,
    "xtick.labelsize": 9,
    "ytick.labelsize": 9,
    "legend.fontsize": 9,
    "axes.linewidth": 0.8,
}
plt.rcParams.update(apply_latex_rcparams(base=_BASE_RCPARAMS))


PLATFORMS: List[Tuple[str, str]] = [
    ("deepseek", "DeepSeek"),
    ("chatgpt", "ChatGPT"),
    ("gemini", "Gemini"),
    ("grok", "Grok"),
]


CATEGORY_ORDER = [
    ("classical", "Classical"),
    ("modern symmetric", "Modern Symmetric"),
    ("asymmetric", "Asymmetric"),
    ("hash", "Hash"),
]


def _pick_latest_raw_results(platform: str, condition: str) -> Path:
    raw_dir = Path("data") / "results" / platform / condition / "raw_results"
    candidates = sorted(raw_dir.glob("*.json"))
    candidates = [p for p in candidates if ".bak_" not in p.name and "partial" not in p.name and "CHECKPOINT" not in p.name]
    if not candidates:
        raise FileNotFoundError(f"No raw_results JSON found in: {raw_dir}")
    candidates.sort(key=lambda p: (p.stat().st_mtime, p.name))
    return candidates[-1]


def _load_results(path: Path) -> List[Dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    results = payload.get("results") or []
    return results if isinstance(results, list) else []


def _as_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    return str(v).strip().lower() in {"1", "true", "t", "yes", "y"}


def _safe_float(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except Exception:
        return None


def _get_category(row: Dict[str, Any]) -> str | None:
    # Check original_info first (hidden experiments store ground-truth here)
    oi = row.get("original_info")
    if isinstance(oi, dict):
        c = oi.get("category")
        if isinstance(c, str) and c.strip():
            return c.strip().lower()

    # Check test_case (informed experiments store ground-truth here)
    tc = row.get("test_case")
    if isinstance(tc, dict):
        c = tc.get("category")
        if isinstance(c, str) and c.strip():
            return c.strip().lower().replace("_", " ")

    # Fallback: evaluation stores the category for some platforms
    ev = row.get("evaluation")
    if isinstance(ev, dict):
        c = ev.get("category")
        if isinstance(c, str) and c.strip():
            return c.strip().lower().replace("_", " ")

    return None


def _iter_success(rows: Iterable[Dict[str, Any]]) -> Iterable[Tuple[str, float]]:
    for r in rows:
        ev = r.get("evaluation")
        if not isinstance(ev, dict):
            continue
        if not _as_bool(ev.get("response_success", False)):
            continue
        cat = _get_category(r)
        if not cat:
            continue
        score = _safe_float(ev.get("overall_score"))
        if score is None:
            continue
        yield cat, score


def _mean(xs: List[float]) -> float:
    return float(sum(xs) / len(xs)) if xs else 0.0


def _std(xs: List[float]) -> float:
    if len(xs) <= 1:
        return 0.0
    m = _mean(xs)
    # sample std (ddof=1)
    var = sum((x - m) ** 2 for x in xs) / (len(xs) - 1)
    return float(var ** 0.5)


@dataclass
class CategoryStats:
    mean_by_cat: Dict[str, float]
    std_by_cat: Dict[str, float]


def compute_category_stats(platform: str, condition: str) -> CategoryStats:
    path = _pick_latest_raw_results(platform, condition)
    rows = _load_results(path)

    buckets: Dict[str, List[float]] = {k: [] for k, _ in CATEGORY_ORDER}
    for cat, score in _iter_success(rows):
        # normalize category name variants
        if cat == "modern_symmetric":
            cat = "modern symmetric"
        if cat in buckets:
            buckets[cat].append(score)

    mean_by_cat = {k: _mean(v) for k, v in buckets.items()}
    std_by_cat = {k: _std(v) for k, v in buckets.items()}
    return CategoryStats(mean_by_cat=mean_by_cat, std_by_cat=std_by_cat)


def plot_category_breakdown(*, condition: str, title: str, out_name: str) -> None:
    out_path = output_dir() / out_name
    out_path.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=fig_size(default=(4.8, 4.8)), dpi=fig_dpi(default=300))

    cats = [k for k, _ in CATEGORY_ORDER]
    labels = [lbl for _k, lbl in CATEGORY_ORDER]

    x = list(range(len(cats)))
    width = 0.18

    for i, (platform, plat_label) in enumerate(PLATFORMS):
        bar_color = PLATFORM_COLORS.get(platform, None)
        stats = compute_category_stats(platform, condition)
        means = [stats.mean_by_cat.get(c, 0.0) for c in cats]
        stds = [stats.std_by_cat.get(c, 0.0) for c in cats]
        xs = [xi - 1.5 * width + i * width for xi in x]
        ax.bar(
            xs,
            means,
            width=width,
            label=plat_label,
            color=bar_color,
            edgecolor="black",
            linewidth=(0.25 if is_latex_style() else 0.35),
            yerr=stds,
            ecolor="black",
            capsize=(2 if is_latex_style() else 3),
            error_kw={"elinewidth": (0.55 if is_latex_style() else 1.0)},
        )

    ax.set_xlabel("Algorithm Category")
    ax.set_ylabel("Average Score")

    ax.set_xticks(x)
    ax.set_xticklabels(labels)
    ax.set_ylim(0.0, 1.0)

    ax.grid(axis="y", linestyle="-", linewidth=(0.2 if is_latex_style() else 0.25), alpha=0.35)

    lk = {"loc": "upper right", "ncol": 2, "frameon": True, "framealpha": 0.9, "edgecolor": "black"}
    lk.update(legend_inside_kwargs(default_ncol=2))
    ax.legend(**lk)

    fig.tight_layout(pad=0.35)
    fig.savefig(out_path)
    plt.close(fig)


def main() -> int:
    plot_category_breakdown(
        condition="algorithm_hidden",
        title="Fig. 2: Performance by Algorithm Category",
        out_name="figure_2_category_breakdown_combined_hidden.png",
    )

    plot_category_breakdown(
        condition="algorithm_informed",
        title="Fig. 2: Performance by Algorithm Category",
        out_name="figure_2_category_breakdown_combined_informed.png",
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# REFRESH_2026
