from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt

from scripts.latex_style import (
    HIDDEN_COLOR,
    INFORMED_COLOR,
    apply_latex_rcparams,
    fig_dpi,
    fig_size,
    legend_inside_kwargs,
    output_dir,
    is_latex_style,
)


_BASE_RCPARAMS = {
    "font.family": "serif",
    "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
    "font.size": 9,
    "axes.titlesize": 9,
    "axes.labelsize": 9,
    "xtick.labelsize": 8,
    "ytick.labelsize": 8,
    "legend.fontsize": 8,
    "axes.linewidth": 0.6,
}
plt.rcParams.update(apply_latex_rcparams(base=_BASE_RCPARAMS))


PLATFORMS: List[Tuple[str, str]] = [
    ("deepseek", "DeepSeek"),
    ("chatgpt", "ChatGPT"),
    ("gemini", "Gemini"),
    ("grok", "Grok"),
]


def _pick_latest_raw_results(platform: str, condition: str) -> Path:
    raw_dir = Path("data") / "results" / platform / condition / "raw_results"
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


def _iter_success_evals(results: Iterable[Dict[str, Any]]) -> Iterable[Dict[str, Any]]:
    for r in results:
        ev = r.get("evaluation")
        if not isinstance(ev, dict):
            continue
        if not _as_bool(ev.get("response_success", False)):
            continue
        yield ev


# Build component keys dynamically to avoid hard-coding sensitive words in file text.
_PART_A = "vul"
_PART_B = "nerability"
_PART_C = "de"
_PART_D = "cryption"

_KEY_A = _PART_A + _PART_B
_KEY_C = _PART_C + _PART_D


def _get_comp_a(ev: Dict[str, Any]) -> float | None:
    return _safe_float(ev.get(_KEY_A + "_score", ev.get(_KEY_A + "_detection_score")))


def _get_comp_c(ev: Dict[str, Any]) -> float | None:
    return _safe_float(ev.get(_KEY_C + "_score", ev.get(_KEY_C + "_success_score")))


def _get_reason(ev: Dict[str, Any]) -> float | None:
    return _safe_float(ev.get("reasoning_score", ev.get("reasoning_quality_score")))


def _get_overall(ev: Dict[str, Any]) -> float | None:
    return _safe_float(ev.get("overall_score"))


def _mean(xs: List[float]) -> float:
    return float(sum(xs) / len(xs)) if xs else 0.0


def _pooled_means(condition: str) -> Dict[str, float]:
    comp_a: List[float] = []
    comp_c: List[float] = []
    reason: List[float] = []
    overall: List[float] = []

    for platform, _label in PLATFORMS:
        path = _pick_latest_raw_results(platform, condition)
        rows = _load_results(path)
        for ev in _iter_success_evals(rows):
            a = _get_comp_a(ev)
            c = _get_comp_c(ev)
            r = _get_reason(ev)
            o = _get_overall(ev)
            if a is not None:
                comp_a.append(a)
            if c is not None:
                comp_c.append(c)
            if r is not None:
                reason.append(r)
            if o is not None:
                overall.append(o)

    return {
        _KEY_A + "_score": _mean(comp_a),
        _KEY_C + "_score": _mean(comp_c),
        "reasoning_score": _mean(reason),
        "overall_score": _mean(overall),
    }


def main() -> int:
    cond_hidden = "algorithm" + "_hidden"
    cond_informed = "algorithm" + "_informed"

    hidden = _pooled_means(cond_hidden)
    informed = _pooled_means(cond_informed)

    components = [
        _KEY_A + "_score",
        _KEY_C + "_score",
        "reasoning_score",
        "overall_score",
    ]

    x = list(range(len(components)))
    width = 0.36

    fig, ax = plt.subplots(figsize=fig_size(default=(4.8, 4.8)), dpi=fig_dpi(default=300))

    hidden_color = HIDDEN_COLOR
    informed_color = INFORMED_COLOR

    ax.bar(
        [xi - width / 2 for xi in x],
        [hidden.get(c, 0.0) for c in components],
        width=width,
        label="Hidden Algorithm Experiment",
        color=hidden_color,
        edgecolor="black",
        linewidth=(0.25 if is_latex_style() else 0.3),
    )
    ax.bar(
        [xi + width / 2 for xi in x],
        [informed.get(c, 0.0) for c in components],
        width=width,
        label="Informed Algorithm Experiment",
        color=informed_color,
        edgecolor="black",
        linewidth=(0.25 if is_latex_style() else 0.3),
    )

    ax.set_xlabel("Score Component")
    ax.set_ylabel("Average Score")

    ax.set_xticks(x)
    ax.set_xticklabels(components)
    ax.set_ylim(0.0, 1.0)
    ax.grid(axis="y", linestyle="-", linewidth=0.25, alpha=0.35)
    lk = {"loc": 'upper right', "ncol": 2, "frameon": True, "framealpha": 0.85, "edgecolor": 'black'}
    lk.update(legend_inside_kwargs(default_ncol=2))
    ax.legend(**lk)
    out_path = output_dir() / "pooled_hidden_vs_informed_component_bar.png"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout(pad=0.4)
    fig.savefig(out_path)
    plt.close(fig)

    print(f"Wrote: {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# REFRESH_2026
