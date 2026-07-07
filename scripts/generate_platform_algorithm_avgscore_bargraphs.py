from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from scripts.latex_style import (
    ALGORITHM_COLORS,
    apply_latex_rcparams,
    fig_dpi,
    fig_size,
    legend_inside_kwargs,
    output_dir,
    is_latex_style,
)


# IEEE-ish plotting defaults
_BASE_RCPARAMS = {
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 9,
    "axes.titlesize": 9,
    "axes.labelsize": 9,
    "xtick.labelsize": 6,
    "ytick.labelsize": 8,
    "legend.fontsize": 6,
    "axes.linewidth": 0.6,
}
plt.rcParams.update(apply_latex_rcparams(base=_BASE_RCPARAMS))


PLATFORMS: List[Tuple[str, str]] = [
    ("deepseek", "DeepSeek\n(deepseek-chat)"),
    ("chatgpt", "ChatGPT\n(gpt-5-mini)"),
    ("gemini", "Gemini\n(gemini-3-flash-preview)"),
    ("grok", "Grok\n(grok-4.1-fast-reasoning)"),
]


def _pick_latest_raw_results(platform: str, condition: str) -> Path:
    raw_dir = Path("data") / "results" / platform / condition / "raw_results"
    if not raw_dir.exists():
        raise FileNotFoundError(f"Missing raw_results dir: {raw_dir}")

    candidates = sorted(raw_dir.glob("*.json"))
    candidates = [
        p
        for p in candidates
        if ".bak_" not in p.name and "partial" not in p.name and "CHECKPOINT" not in p.name
    ]
    if not candidates:
        raise FileNotFoundError(f"No raw_results JSON found in: {raw_dir}")

    candidates.sort(key=lambda p: (p.stat().st_mtime, p.name))
    return candidates[-1]


def _load_results(path: Path) -> List[Dict[str, Any]]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    results = payload.get("results") or []
    if not isinstance(results, list):
        return []
    return results


def _as_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    return str(v).strip().lower() in {"1", "true", "t", "yes", "y"}


def _safe_float(v: Any) -> float:
    try:
        if v is None:
            return 0.0
        return float(v)
    except Exception:
        return 0.0


def _mean(values: List[float]) -> float:
    if not values:
        return 0.0
    return float(sum(values) / len(values))


def _iter_success_evals(
    results: Iterable[Dict[str, Any]],
) -> Iterable[Tuple[Dict[str, Any], Dict[str, Any]]]:
    for r in results:
        ev = r.get("evaluation") or {}
        if not isinstance(ev, dict):
            continue
        if not _as_bool(ev.get("response_success", False)):
            continue
        yield r, ev


def _get_algorithm_name(row: Dict[str, Any]) -> str | None:
    ev = row.get("evaluation")
    if isinstance(ev, dict):
        alg = ev.get("algorithm")
        if isinstance(alg, str) and alg.strip():
            return alg.strip()

    # Hidden runs store ground-truth under original_info; informed runs commonly use test_case.
    oi = row.get("original_info")
    if isinstance(oi, dict):
        alg = oi.get("algorithm")
        if isinstance(alg, str) and alg.strip():
            return alg.strip()

    tc = row.get("test_case")
    if isinstance(tc, dict):
        alg = tc.get("algorithm")
        if isinstance(alg, str) and alg.strip():
            return alg.strip()

    return None


def _discover_algorithms() -> List[str]:
    # Discover the 15 ground-truth algorithms from any latest hidden raw_results.
    for platform, _label in PLATFORMS:
        try:
            path = _pick_latest_raw_results(platform, "algorithm_hidden")
        except Exception:
            continue
        results = _load_results(path)
        algs = sorted({a for a in (_get_algorithm_name(r) for r in results) if a})
        if algs:
            return algs
    raise FileNotFoundError("Could not discover algorithms from raw_results")


@dataclass(frozen=True)
class SeriesSpec:
    key: str
    label: str
    color: str


def compute_platform_algorithm_overall_means(condition: str, algorithms: List[str]) -> Dict[str, Dict[str, float]]:
    # Key by platform id (stable) so display labels can change.
    buckets: Dict[str, Dict[str, List[float]]] = {p: {a: [] for a in algorithms} for p, _label in PLATFORMS}

    for platform, _label in PLATFORMS:
        path = _pick_latest_raw_results(platform, condition)
        results = _load_results(path)
        for row, ev in _iter_success_evals(results):
            alg = _get_algorithm_name(row)
            if not alg or alg not in buckets[platform]:
                continue
            buckets[platform][alg].append(_safe_float(ev.get("overall_score", 0.0)))

    out: Dict[str, Dict[str, float]] = {}
    for platform, _label in PLATFORMS:
        out[platform] = {a: _mean(buckets[platform].get(a, [])) for a in algorithms}

    return out

def _plot_algorithm_grouped_bars(
    *,
    title: str,
    x_keys: List[str],
    x_tick_labels: List[str],
    data: Dict[str, Dict[str, float]],
    series: List[SeriesSpec],
    out_path: Path,
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    fig, ax = plt.subplots(figsize=fig_size(default=(4.8, 4.8)), dpi=fig_dpi(default=300))

    x = list(range(len(x_keys)))
    n = len(series)
    width = 0.82 / max(n, 1)

    for i, spec in enumerate(series):
        ys = [data.get(k, {}).get(spec.key, 0.0) for k in x_keys]
        xs = [xi - 0.41 + width / 2 + i * width for xi in x]
        ax.bar(
            xs,
            ys,
            width=width,
            label=spec.label,
            color=spec.color,
            edgecolor="black",
            linewidth=(0.2 if is_latex_style() else 0.25),
        )

    ax.set_xlabel("Platform")
    ax.set_ylabel("Average Score")

    ax.set_xticks(x)
    ax.set_xticklabels(x_tick_labels)
    ax.set_ylim(0, 1.0)
    ax.grid(axis="y", linestyle="-", linewidth=0.25, alpha=0.35)

    if is_latex_style():
        # Many-series legend: keep it inside but compact.
        lk = legend_inside_kwargs(default_ncol=3)
        ax.legend(**{**lk, **{"prop": {"size": 7.0}}})
        ax.tick_params(axis="x", pad=1)
        fig.tight_layout(pad=0.35)
    else:
        ax.legend(
            loc="upper center",
            bbox_to_anchor=(0.5, -0.24),
            ncol=2,
            frameon=True,
            framealpha=0.9,
            edgecolor="black",
            borderaxespad=0.0,
            handlelength=1.2,
            columnspacing=0.8,
            labelspacing=0.3,
        )
        ax.tick_params(axis="x", pad=2)
        fig.subplots_adjust(bottom=0.44, top=0.86)

    fig.savefig(out_path)
    plt.close(fig)


def main() -> int:
    out_dir = output_dir()
    algorithms = _discover_algorithms()
    x_keys = [p for p, _label in PLATFORMS]
    x_tick_labels = [
        (_label.split("\n", 1)[0] if is_latex_style() else _label)
        for _p, _label in PLATFORMS
    ]

    alg_series = [
        SeriesSpec(key=a, label=a, color=ALGORITHM_COLORS[i % len(ALGORITHM_COLORS)])
        for i, a in enumerate(algorithms)
    ]

    hidden_data = compute_platform_algorithm_overall_means("algorithm_hidden", algorithms)
    _plot_algorithm_grouped_bars(
        title="Hidden Algorithm Experiment: Average Score per Algorithm by Platform",
        x_keys=x_keys,
        x_tick_labels=x_tick_labels,
        data=hidden_data,
        series=alg_series,
        out_path=out_dir / "hidden_platform_algorithm_avg_score_bar.png",
    )

    informed_data = compute_platform_algorithm_overall_means("algorithm_informed", algorithms)
    _plot_algorithm_grouped_bars(
        title="Informed Algorithm Experiment: Average Score per Algorithm by Platform",
        x_keys=x_keys,
        x_tick_labels=x_tick_labels,
        data=informed_data,
        series=alg_series,
        out_path=out_dir / "informed_platform_algorithm_avg_score_bar.png",
    )

    return 0

if __name__ == "__main__":
    raise SystemExit(main())










# REFRESH_2026
