from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


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
        raise FileNotFoundError(f"No raw_results for {platform} {condition}")
    return cands[-1]


def as_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    return str(v).strip().lower() in {"1", "true", "t", "yes", "y"}


def sf(v: Any) -> float:
    try:
        if v is None:
            return 0.0
        return float(v)
    except Exception:
        return 0.0


def mean(xs: List[float]) -> float:
    return sum(xs) / len(xs) if xs else 0.0


def std(xs: List[float]) -> float:
    if not xs:
        return 0.0
    m = mean(xs)
    return (sum((x - m) ** 2 for x in xs) / len(xs)) ** 0.5


def load_results(p: Path) -> List[Dict[str, Any]]:
    d = json.loads(p.read_text(encoding="utf-8"))
    res = d.get("results") or []
    return res if isinstance(res, list) else []


def label_cell(label: str) -> str:
    # keep platform+model, but wrap to avoid truncation
    if " (" in label and label.endswith(")"):
        a, b = label.split(" (", 1)
        return a + "\n(" + b
    return label


def summarize_hidden(platform: str) -> Dict[str, float | int]:
    rows = load_results(pick_latest(platform, "algorithm_hidden"))
    evals = [(r.get("evaluation") or {}) for r in rows]
    evals = [e for e in evals if isinstance(e, dict)]

    ok = [e for e in evals if as_bool(e.get("response_success", False))]

    overall_vals = [sf(e.get("overall_score")) for e in ok]

    return {
        "success": len(ok),
        "overall_avg": mean(overall_vals),
        "overall_std": std(overall_vals),
        "id_avg": mean([sf(e.get("identified_algorithm_score")) for e in ok]),
        "cat_avg": mean([sf(e.get("identified_category_score")) for e in ok]),
        "vuln_avg": mean([sf(e.get("vulnerability_score")) for e in ok]),
        "dec_avg": mean([sf(e.get("decryption_score")) for e in ok]),
        "reason_avg": mean([sf(e.get("reasoning_score")) for e in ok]),
        "exact_match_rate": mean(
            [1.0 if as_bool(e.get("exact_match", False)) else 0.0 for e in ok]
        ),
        "category_match_rate": mean(
            [1.0 if as_bool(e.get("category_match", False)) else 0.0 for e in ok]
        ),
    }


def summarize_informed(platform: str) -> Dict[str, float | int]:
    rows = load_results(pick_latest(platform, "algorithm_informed"))
    evals = [(r.get("evaluation") or {}) for r in rows]
    evals = [e for e in evals if isinstance(e, dict)]

    total = len(evals)
    ok = [e for e in evals if as_bool(e.get("response_success", False))]

    overall_vals = [sf(e.get("overall_score")) for e in ok]

    def get_vuln(e: Dict[str, Any]) -> float:
        return sf(e.get("vulnerability_detection_score", e.get("vulnerability_score")))

    def get_dec(e: Dict[str, Any]) -> float:
        return sf(e.get("decryption_success_score", e.get("decryption_score")))

    def get_reason(e: Dict[str, Any]) -> float:
        return sf(e.get("reasoning_quality_score", e.get("reasoning_score")))

    def get_conf(e: Dict[str, Any]) -> float:
        return sf(e.get("confidence_score", e.get("confidence")))

    return {
        "total": total,
        "success": len(ok),
        "overall_avg": mean(overall_vals),
        "overall_std": std(overall_vals),
        "success_rate": (len(ok) / total) if total else 0.0,
        "vuln_avg": mean([get_vuln(e) for e in ok]),
        "dec_avg": mean([get_dec(e) for e in ok]),
        "reason_avg": mean([get_reason(e) for e in ok]),
        "conf_avg": mean([get_conf(e) for e in ok]),
    }


def render_table_png(
    title: str,
    columns: List[str],
    rows: List[List[str]],
    out_path: Path,
    col_widths: List[float],
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
            "font.size": 7,
        }
    )

    n_rows = len(rows) + 1
    fig_w = 7.16
    fig_h = max(1.8, 0.34 * n_rows)

    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=300)
    ax.axis("off")

    table_data = [columns] + rows
    tbl = ax.table(cellText=table_data, loc="center", cellLoc="center")

    for (ri, ci), cell in tbl.get_celld().items():
        cell.set_edgecolor("black")
        cell.set_linewidth(0.6)
        if ri == 0:
            cell.set_text_props(weight="bold")
            cell.set_facecolor("#f2f2f2")
        else:
            cell.set_facecolor("white")

    for ci, w in enumerate(col_widths):
        for ri in range(n_rows):
            tbl[(ri, ci)].set_width(w)

    tbl.auto_set_font_size(False)
    tbl.set_fontsize(7)
    tbl.scale(1.0, 1.35)

    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)


def main() -> int:
    out_dir = Path("data") / "comparisons"

    hidden_cols = [
        "Plateform",
        "Successful\nAnalyses",
        "Overall\nScore",
        "Score Std\nDev",
        "ID Score\nAvg",
        "Category\nScore Avg",
        "Vuln\nScore Avg",
        "Decrypt\nScore Avg",
        "Reason\nScore Avg",
        "Exact Match\nRate",
        "Category\nMatch Rate",
    ]

    hidden_rows: List[List[str]] = []
    for p, lbl in PLATFORMS:
        s = summarize_hidden(p)
        hidden_rows.append(
            [
                label_cell(lbl),
                str(int(s["success"])),
                f"{float(s['overall_avg']):.4f}",
                f"{float(s['overall_std']):.4f}",
                f"{float(s['id_avg']):.4f}",
                f"{float(s['cat_avg']):.4f}",
                f"{float(s['vuln_avg']):.4f}",
                f"{float(s['dec_avg']):.4f}",
                f"{float(s['reason_avg']):.4f}",
                f"{float(s['exact_match_rate']):.4f}",
                f"{float(s['category_match_rate']):.4f}",
            ]
        )

    h_first = 0.22
    h_rest = (1.0 - h_first) / (len(hidden_cols) - 1)
    render_table_png(
        "Hidden Algorithm Experiment: Platform-wise Overall Summary",
        hidden_cols,
        hidden_rows,
        out_dir / "hidden_platform_overall_summary.png",
        [h_first] + [h_rest] * (len(hidden_cols) - 1),
    )

    informed_cols = [
        "Plateform",
        "Total\nTests",
        "Successful\nAnalyses",
        "Overall\nScore",
        "Score Std\nAvg",
        "Success\nRate",
        "Vuln\nScore Avg",
        "Decrypt\nScore Avg",
        "Reason\nScore Avg",
        "Confidence\nScore Avg",
    ]

    informed_rows: List[List[str]] = []
    for p, lbl in PLATFORMS:
        s = summarize_informed(p)
        informed_rows.append(
            [
                label_cell(lbl),
                str(int(s["total"])),
                str(int(s["success"])),
                f"{float(s['overall_avg']):.4f}",
                f"{float(s['overall_std']):.4f}",
                f"{float(s['success_rate']):.4f}",
                f"{float(s['vuln_avg']):.4f}",
                f"{float(s['dec_avg']):.4f}",
                f"{float(s['reason_avg']):.4f}",
                f"{float(s['conf_avg']):.4f}",
            ]
        )

    i_first = 0.24
    i_rest = (1.0 - i_first) / (len(informed_cols) - 1)
    render_table_png(
        "Informed Algorithm Experiment: Platform-wise Overall Summary",
        informed_cols,
        informed_rows,
        out_dir / "informed_platform_overall_summary.png",
        [i_first] + [i_rest] * (len(informed_cols) - 1),
    )

    print(f"Wrote: {out_dir / 'hidden_platform_overall_summary.png'}")
    print(f"Wrote: {out_dir / 'informed_platform_overall_summary.png'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
