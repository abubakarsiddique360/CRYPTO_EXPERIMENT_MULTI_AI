from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

import matplotlib
matplotlib.use('Agg')
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


# IEEE-ish figure defaults:
# - Serif font (Times New Roman if available)
# - Small font sizes (8–10pt typical for IEEE figures)
# - 300 DPI export
# - No oversized titles; left-aligned title for readability
_BASE_RCPARAMS = {
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'Times', 'DejaVu Serif'],
    'font.size': 9,
    'axes.titlesize': 9,
    'axes.labelsize': 9,
    'xtick.labelsize': 8,
    'ytick.labelsize': 8,
    'legend.fontsize': 8,
    'axes.linewidth': 0.6,
}
plt.rcParams.update(apply_latex_rcparams(base=_BASE_RCPARAMS))


PLATFORMS: List[Tuple[str, str]] = [
    ('deepseek', 'DeepSeek (deepseek-chat)'),
    ('chatgpt', 'ChatGPT (gpt-5-mini)'),
    ('gemini', 'Gemini (gemini-3-flash-preview)'),
    ('grok', 'Grok (grok-4.1-fast-reasoning)'),
]


def _pick_latest_raw_results(platform: str, condition: str) -> Path:
    raw_dir = Path('data') / 'results' / platform / condition / 'raw_results'
    if not raw_dir.exists():
        raise FileNotFoundError(f'Missing raw_results dir: {raw_dir}')

    candidates = sorted(raw_dir.glob('*.json'))
    candidates = [p for p in candidates if '.bak_' not in p.name and 'partial' not in p.name]
    if not candidates:
        raise FileNotFoundError(f'No raw_results JSON found in: {raw_dir}')

    candidates.sort(key=lambda p: (p.stat().st_mtime, p.name))
    return candidates[-1]


def _mean(values: List[float]) -> float:
    if not values:
        return 0.0
    return float(sum(values) / len(values))


def _safe_float(v: Any) -> float:
    try:
        if v is None:
            return 0.0
        return float(v)
    except Exception:
        return 0.0


def _safe_int(v: Any) -> int:
    try:
        if v is None:
            return 0
        return int(v)
    except Exception:
        return 0


def _as_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    return str(v).strip().lower() in {'1', 'true', 't', 'yes', 'y'}


@dataclass
class ComponentAverages:
    label: str
    values_by_component: Dict[str, float]


def _load_results(path: Path) -> List[Dict[str, Any]]:
    payload = json.loads(path.read_text(encoding='utf-8'))
    results = payload.get('results') or []
    if not isinstance(results, list):
        return []
    return results


def compute_hidden_component_averages(platform: str, label: str) -> ComponentAverages:
    path = _pick_latest_raw_results(platform, 'algorithm_hidden')
    results = _load_results(path)

    evals = [r.get('evaluation') or {} for r in results]
    evals = [e for e in evals if _as_bool(e.get('response_success', False))]

    # User-provided x-axis names are weight-names; plot the corresponding *average score components*.
    comps: List[Tuple[str, str]] = [
        ('identification_weight', 'identified_algorithm_score'),
        ('category_weight', 'identified_category_score'),
        ('decryption_weight', 'decryption_score'),
        ('vulnerability_weight', 'vulnerability_score'),
        ('reasoning_weight', 'reasoning_score'),
        ('overall_score', 'overall_score'),
    ]

    out: Dict[str, float] = {}
    for display_name, field in comps:
        out[display_name] = _mean([_safe_float(e.get(field, 0.0)) for e in evals])

    return ComponentAverages(label=label, values_by_component=out)


def compute_informed_component_averages(platform: str, label: str) -> ComponentAverages:
    path = _pick_latest_raw_results(platform, 'algorithm_informed')
    results = _load_results(path)

    evals = [r.get('evaluation') or {} for r in results]
    evals = [e for e in evals if _as_bool(e.get('response_success', False))]

    def get_vuln(e: Dict[str, Any]) -> float:
        return _safe_float(e.get('vulnerability_detection_score', e.get('vulnerability_score', 0.0)))

    def get_dec(e: Dict[str, Any]) -> float:
        return _safe_float(e.get('decryption_success_score', e.get('decryption_score', 0.0)))

    def get_reason(e: Dict[str, Any]) -> float:
        return _safe_float(e.get('reasoning_quality_score', e.get('reasoning_score', 0.0)))

    def get_conf(e: Dict[str, Any]) -> float:
        return _safe_float(e.get('confidence_score', e.get('confidence', 0.0)))

    out = {
        'vulnerability_score': _mean([get_vuln(e) for e in evals]),
        'decryption_score': _mean([get_dec(e) for e in evals]),
        'reasoning_score': _mean([get_reason(e) for e in evals]),
        'confidence_score': _mean([get_conf(e) for e in evals]),
        'overall_score': _mean([_safe_float(e.get('overall_score', 0.0)) for e in evals]),
    }

    return ComponentAverages(label=label, values_by_component=out)


def _plot_grouped_bar(
    *,
    title: str,
    x_components: List[str],
    series: List[ComponentAverages],
    out_path: Path,
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    # 7.16in is IEEE double-column width; 3.35in height adds room for long x-tick labels + legend.
    fig, ax = plt.subplots(figsize=fig_size(default=(4.8, 4.8)), dpi=fig_dpi(default=300))

    x = list(range(len(x_components)))
    n = len(series)
    width = 0.8 / max(n, 1)

    for i, s in enumerate(series):
        platform_key = PLATFORMS[i][0] if i < len(PLATFORMS) else ""
        bar_color = PLATFORM_COLORS.get(platform_key, None)
        ys = [s.values_by_component.get(c, 0.0) for c in x_components]
        xs = [xi - 0.4 + width / 2 + i * width for xi in x]
        ax.bar(
            xs,
            ys,
            width=width,
            label=s.label,
            color=bar_color,
            edgecolor='black',
            linewidth=(0.25 if is_latex_style() else 0.3),
        )

    ax.set_xlabel('Score Component')
    ax.set_ylabel('Average Score')

    ax.set_xticks(x)
    ax.set_xticklabels(x_components, rotation=30, ha='right', rotation_mode='anchor')
    ax.set_ylim(0, 1.20)

    ax.grid(axis='y', linestyle='-', linewidth=0.25, alpha=0.35)

    lk = {'loc': 'upper right', 'ncol': 2, 'frameon': True, 'framealpha': 0.85, 'edgecolor': 'black'}
    lk.update(legend_inside_kwargs(default_ncol=2))
    ax.legend(**lk)

    ax.tick_params(axis='x', pad=2)

    fig.tight_layout(pad=0.4)
    fig.savefig(out_path)
    plt.close(fig)


def main() -> int:
    out_dir = output_dir()

    hidden_series = [compute_hidden_component_averages(p, label) for p, label in PLATFORMS]
    hidden_components = [
        'identification_weight',
        'category_weight',
        'decryption_weight',
        'vulnerability_weight',
        'reasoning_weight',
        'overall_score',
    ]
    _plot_grouped_bar(
        title='Hidden Algorithm Experiment: Average Component Scores',
        x_components=hidden_components,
        series=hidden_series,
        out_path=out_dir / 'hidden_component_bar.png',
    )

    informed_series = [compute_informed_component_averages(p, label) for p, label in PLATFORMS]
    informed_components = [
        'vulnerability_score',
        'decryption_score',
        'reasoning_score',
        'confidence_score',
        'overall_score',
    ]
    _plot_grouped_bar(
        title='Informed Algorithm Experiment: Average Component Scores',
        x_components=informed_components,
        series=informed_series,
        out_path=out_dir / 'informed_component_bar.png',
    )

    print(f'Wrote: {out_dir / "hidden_component_bar.png"}')
    print(f'Wrote: {out_dir / "informed_component_bar.png"}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())


# REFRESH_2026
