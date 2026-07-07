"""
Shared IEEE-style LaTeX formatting utilities for matplotlib figures.
Provides consistent styling across all figure generation scripts.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional


# ── Consistent Cross-Figure Color Palette ──────────────────────────────────
# These colours are chosen for equal perceptual brightness & saturation so
# that no single bar / line dominates the visual – ideal for a unified
# multi-figure paper.

PLATFORM_COLORS: Dict[str, str] = {
    "deepseek": "#4C72B0",  # muted blue
    "chatgpt":  "#DD8452",  # warm amber / orange
    "gemini":   "#55A868",  # balanced teal-green
    "grok":     "#C44E52",  # soft crimson (not too dark, not too light)
}

# 15 distinguishable algorithm colours – all at similar luminosity (~50–70%)
# so that none visually overpowers another.
ALGORITHM_COLORS: tuple[str, ...] = (
    "#4C72B0",  # blue
    "#DD8452",  # orange
    "#55A868",  # green
    "#C44E52",  # red
    "#8172B3",  # purple
    "#937860",  # brown
    "#DA8BC3",  # pink
    "#8C8C8C",  # grey
    "#CCB974",  # olive
    "#64B5CD",  # sky blue
    "#C75B7A",  # rose
    "#6FA3CF",  # steel blue
    "#E8A838",  # golden
    "#A1C9A4",  # sage
    "#CD6E6E",  # brick
)

# ── Shared Experiment / Condition Colors ──────────────────────────────────
HIDDEN_COLOR   = "#8172B3"   # muted purple (blends with the blue-purple family of the palette)
INFORMED_COLOR = "#CCB974"   # warm olive-gold (blends with the amber-green family of the palette)


def apply_latex_rcparams(base: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    Return rcParams dict with IEEE-style LaTeX-friendly overrides.
    If *base* is given, the overrides are merged on top.
    """
    ieee_defaults: Dict[str, Any] = {
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "font.size": 8,
        "axes.titlesize": 9,
        "axes.labelsize": 8,
        "xtick.labelsize": 7,
        "ytick.labelsize": 7,
        "legend.fontsize": 7,
        "axes.linewidth": 0.8,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "figure.dpi": 300,
        "savefig.dpi": 300,
        "savefig.bbox": "tight",
        "savefig.pad_inches": 0.02,
    }
    if base is not None:
        ieee_defaults.update(base)
    return ieee_defaults


def fig_size(default: tuple[float, float] = (7.16, 4.8)) -> tuple[float, float]:
    """Return figure size in inches. 7.16in = IEEE double-column width."""
    return default


def fig_dpi(default: int = 300) -> int:
    """Return figure DPI."""
    return default


def legend_inside_kwargs(default_ncol: int = 2) -> Dict[str, Any]:
    """Return legend kwargs suitable for inside-the-axes placement."""
    return {
        "loc": "upper right",
        "ncol": default_ncol,
        "frameon": True,
        "framealpha": 0.85,
        "edgecolor": "black",
        "borderpad": 0.3,
        "handlelength": 1.5,
        "columnspacing": 0.8,
        "labelspacing": 0.2,
    }


def is_latex_style() -> bool:
    """Return True if LaTeX-style rendering is active (always True here)."""
    return True


def output_dir() -> Path:
    """Return the output directory for comparison figures."""
    return Path("data") / "comparisons"

# REFRESH_2026
