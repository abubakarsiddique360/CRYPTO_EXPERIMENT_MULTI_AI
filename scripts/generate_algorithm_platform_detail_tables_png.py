from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


# IEEE-ish defaults
plt.rcParams.update(
    {
        "font.family": "serif",
        "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
        "font.size": 8,
        "axes.titlesize": 9,
    }
)


PLATFORMS: List[Tuple[str, str]] = [
    ("deepseek", "DeepSeek"),
    ("chatgpt", "ChatGPT"),
    ("gemini", "Gemini"),
    ("grok", "Grok"),
]


CATEGORY_ORDER = {
    "classical": 0,
    "modern_symmetric": 1,
    "asymmetric": 2,
    "hash": 3,
}


PREFERRED_ALG_ORDER = [
    # classical
    "Caesar cipher",
    "Vigenère cipher",
    "Substitution cipher",
    # modern symmetric
    "AES-GCM",
    "AES-CBC",
    "AES-CTR",
    "AES-ECB",
    "ChaCha20-Poly1305",
    # asymmetric
    "RSA-2048",
    "RSA-4096",
    "ECDSA (P-256)",
    "Ed25519",
    # hash
    "SHA-256",
    "SHA-3-256",
    "BLAKE3",
]


def pick_latest(platform: str, condition: str) -> Path:
    raw_dir = Path("data") / "results" / platform / condition / "raw_results"
    candidates = [
        p
        for p in raw_dir.glob("*.json")
        if ".bak_" not in p.name and "partial" not in p.name and "CHECKPOINT" not in p.name
    ]
    candidates.sort(key=lambda p: (p.stat().st_mtime, p.name))
    if not candidates:
        raise FileNotFoundError(f"No raw_results for {platform} {condition}")
    return candidates[-1]


def load_results(p: Path) -> List[Dict[str, Any]]:
    payload = json.loads(p.read_text(encoding="utf-8"))
    res = payload.get("results") or []
    return res if isinstance(res, list) else []


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
    return float(sum(xs) / len(xs)) if xs else 0.0


def std(xs: List[float]) -> float:
    if not xs:
        return 0.0
    m = mean(xs)
    return float((sum((x - m) ** 2 for x in xs) / len(xs)) ** 0.5)


def iter_success_evals(results: Iterable[Dict[str, Any]]) -> Iterable[Tuple[Dict[str, Any], Dict[str, Any]]]:
    for r in results:
        ev = r.get("evaluation") or {}
        if not isinstance(ev, dict):
            continue
        if not as_bool(ev.get("response_success", False)):
            continue
        yield r, ev


def get_alg_and_cat(row: Dict[str, Any]) -> Tuple[str | None, str | None]:
    ev = row.get("evaluation")
    if isinstance(ev, dict):
        alg = ev.get("algorithm")
        cat = ev.get("category")
        a = alg.strip() if isinstance(alg, str) else None
        c = cat.strip() if isinstance(cat, str) else None
        return (a if a else None, c if c else None)
    return (None, None)


def order_algorithms(algs: List[str], alg_to_cat: Dict[str, str]) -> List[str]:
    pref = [a for a in PREFERRED_ALG_ORDER if a in set(algs)]
    rest = [a for a in algs if a not in set(pref)]

    def k(a: str) -> tuple[int, str]:
        c = alg_to_cat.get(a, "")
        return (CATEGORY_ORDER.get(c, 99), a)

    rest.sort(key=k)
    return pref + rest


@dataclass
class InformedMetrics:
    overall_avg: float
    overall_std: float
    count: int
    vuln_avg: float
    dec_avg: float
    reason_avg: float


@dataclass
class HiddenMetrics:
    overall_avg: float
    overall_std: float
    count: int
    id_avg: float
    cat_avg: float
    vuln_avg: float
    dec_avg: float
    reason_avg: float


def summarize_informed(results: List[Dict[str, Any]]) -> Dict[str, Dict[str, InformedMetrics]]:
    # stats[algorithm][platform_label]
    out: Dict[str, Dict[str, InformedMetrics]] = {}

    by_alg: Dict[str, List[Dict[str, Any]]] = {}
    alg_to_cat: Dict[str, str] = {}

    for _row, ev in iter_success_evals(results):
        alg = ev.get("algorithm")
        cat = ev.get("category")
        if not isinstance(alg, str) or not alg.strip():
            continue
        a = alg.strip()
        if isinstance(cat, str) and cat.strip():
            alg_to_cat[a] = cat.strip()
        by_alg.setdefault(a, []).append(ev)

    for a, evs in by_alg.items():
        overall = [sf(e.get("overall_score")) for e in evs]
        vuln = [sf(e.get("vulnerability_detection_score", e.get("vulnerability_score"))) for e in evs]
        dec = [sf(e.get("decryption_success_score", e.get("decryption_score"))) for e in evs]
        reason = [sf(e.get("reasoning_quality_score", e.get("reasoning_score"))) for e in evs]

        out[a] = {
            "__ALL__": InformedMetrics(
                overall_avg=mean(overall),
                overall_std=std(overall),
                count=len(evs),
                vuln_avg=mean(vuln),
                dec_avg=mean(dec),
                reason_avg=mean(reason),
            )
        }

    return out


def summarize_hidden(results: List[Dict[str, Any]]) -> Dict[str, Dict[str, HiddenMetrics]]:
    out: Dict[str, Dict[str, HiddenMetrics]] = {}

    by_alg: Dict[str, List[Dict[str, Any]]] = {}

    for _row, ev in iter_success_evals(results):
        alg = ev.get("algorithm")
        if not isinstance(alg, str) or not alg.strip():
            continue
        a = alg.strip()
        by_alg.setdefault(a, []).append(ev)

    for a, evs in by_alg.items():
        overall = [sf(e.get("overall_score")) for e in evs]
        id_s = [sf(e.get("identified_algorithm_score")) for e in evs]
        cat_s = [sf(e.get("identified_category_score")) for e in evs]
        vuln = [sf(e.get("vulnerability_score")) for e in evs]
        dec = [sf(e.get("decryption_score")) for e in evs]
        reason = [sf(e.get("reasoning_score")) for e in evs]

        out[a] = {
            "__ALL__": HiddenMetrics(
                overall_avg=mean(overall),
                overall_std=std(overall),
                count=len(evs),
                id_avg=mean(id_s),
                cat_avg=mean(cat_s),
                vuln_avg=mean(vuln),
                dec_avg=mean(dec),
                reason_avg=mean(reason),
            )
        }

    return out


def build_alg_category_map() -> Dict[str, str]:
    # Pull from any platform/condition; categories exist in evaluation
    alg_to_cat: Dict[str, str] = {}
    for cond in ["algorithm_hidden", "algorithm_informed"]:
        for platform, _lbl in PLATFORMS:
            try:
                rows = load_results(pick_latest(platform, cond))
            except Exception:
                continue
            for r in rows:
                a, c = get_alg_and_cat(r)
                if a and c:
                    alg_to_cat[a] = c
    return alg_to_cat


def render_table_png(
    title: str,
    columns: List[str],
    rows: List[List[str]],
    out_path: Path,
    col_widths: List[float],
    font_size: float = 6.0,
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)

    plt.rcParams.update(
        {
            "font.family": "serif",
            "font.serif": ["Times New Roman", "Times", "DejaVu Serif"],
            "font.size": font_size,
        }
    )

    n_rows = len(rows) + 1
    fig_w = 7.16
    # Compact but readable; keep row height small.
    fig_h = max(5.0, 0.15 * n_rows)

    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=300)
    ax.axis("off")

    table_data = [columns] + rows
    tbl = ax.table(cellText=table_data, cellLoc="center", bbox=[0.0, 0.0, 1.0, 0.94])

    for (ri, ci), cell in tbl.get_celld().items():
        cell.set_edgecolor("black")
        cell.set_linewidth(0.45)
        cell.PAD = 0.08
        cell.get_text().set_wrap(True)
        if ri == 0:
            cell.set_text_props(weight="bold")
            cell.set_facecolor("#f2f2f2")
        else:
            cell.set_facecolor("white")

    for ci, w in enumerate(col_widths):
        for ri in range(n_rows):
            tbl[(ri, ci)].set_width(w)

    tbl.auto_set_font_size(False)
    tbl.set_fontsize(font_size)
    tbl.scale(1.0, 1.05)

    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)


def fmt(x: float) -> str:
    return f"{x:.4f}"


def main() -> int:
    out_dir = Path("data") / "comparisons"

    alg_to_cat = build_alg_category_map()
    algorithms = order_algorithms(sorted(alg_to_cat.keys()), alg_to_cat)

    # Build platform×algorithm stats for each condition.
    informed_stats: Dict[str, Dict[str, InformedMetrics]] = {a: {} for a in algorithms}
    hidden_stats: Dict[str, Dict[str, HiddenMetrics]] = {a: {} for a in algorithms}

    for platform, plabel in PLATFORMS:
        # informed
        inf_rows = load_results(pick_latest(platform, "algorithm_informed"))
        inf_by_alg = {}
        for _row, ev in iter_success_evals(inf_rows):
            a = ev.get("algorithm")
            if isinstance(a, str) and a.strip():
                inf_by_alg.setdefault(a.strip(), []).append(ev)

        for a in algorithms:
            evs = inf_by_alg.get(a, [])
            overall = [sf(e.get("overall_score")) for e in evs]
            vuln = [sf(e.get("vulnerability_detection_score", e.get("vulnerability_score"))) for e in evs]
            dec = [sf(e.get("decryption_success_score", e.get("decryption_score"))) for e in evs]
            reason = [sf(e.get("reasoning_quality_score", e.get("reasoning_score"))) for e in evs]
            informed_stats[a][plabel] = InformedMetrics(
                overall_avg=mean(overall),
                overall_std=std(overall),
                count=len(evs),
                vuln_avg=mean(vuln),
                dec_avg=mean(dec),
                reason_avg=mean(reason),
            )

        # hidden
        hid_rows = load_results(pick_latest(platform, "algorithm_hidden"))
        hid_by_alg = {}
        for _row, ev in iter_success_evals(hid_rows):
            a = ev.get("algorithm")
            if isinstance(a, str) and a.strip():
                hid_by_alg.setdefault(a.strip(), []).append(ev)

        for a in algorithms:
            evs = hid_by_alg.get(a, [])
            overall = [sf(e.get("overall_score")) for e in evs]
            id_s = [sf(e.get("identified_algorithm_score")) for e in evs]
            cat_s = [sf(e.get("identified_category_score")) for e in evs]
            vuln = [sf(e.get("vulnerability_score")) for e in evs]
            dec = [sf(e.get("decryption_score")) for e in evs]
            reason = [sf(e.get("reasoning_score")) for e in evs]
            hidden_stats[a][plabel] = HiddenMetrics(
                overall_avg=mean(overall),
                overall_std=std(overall),
                count=len(evs),
                id_avg=mean(id_s),
                cat_avg=mean(cat_s),
                vuln_avg=mean(vuln),
                dec_avg=mean(dec),
                reason_avg=mean(reason),
            )

    # --- Informed table ---
    inf_cols = [
        "Algorithm",
        "Category",
        "Platform",
        "Avg Score",
        "Score Std",
        "Test Count",
        "Vuln Score",
        "Decrypt Score",
        "Reason Score",
    ]

    inf_rows_out: List[List[str]] = []
    for a in algorithms:
        cat = alg_to_cat.get(a, "")
        for i, (_p, plabel) in enumerate(PLATFORMS):
            m = informed_stats[a][plabel]
            inf_rows_out.append(
                [
                    a if i == 0 else "",
                    cat if i == 0 else "",
                    plabel,
                    fmt(m.overall_avg),
                    fmt(m.overall_std),
                    str(m.count),
                    fmt(m.vuln_avg),
                    fmt(m.dec_avg),
                    fmt(m.reason_avg),
                ]
            )

    # widths sum ~ 1.0
    render_table_png(
        "Informed Algorithm Experiment: Algorithm × Platform Detailed Scores",
        inf_cols,
        inf_rows_out,
        out_dir / "informed_algorithm_platform_detail_table.png",
        [0.18, 0.10, 0.11, 0.09, 0.08, 0.07, 0.09, 0.09, 0.09],
        font_size=6.0,
    )

    # --- Hidden table ---
    hid_cols = [
        "Algorithm",
        "Category",
        "Platform",
        "Avg Score",
        "Score Std",
        "Test Count",
        "ID Score",
        "Cat Score",
        "Vuln Score",
        "Decrypt Score",
        "Reason Score",
    ]

    hid_rows_out: List[List[str]] = []
    for a in algorithms:
        cat = alg_to_cat.get(a, "")
        for i, (_p, plabel) in enumerate(PLATFORMS):
            m = hidden_stats[a][plabel]
            hid_rows_out.append(
                [
                    a if i == 0 else "",
                    cat if i == 0 else "",
                    plabel,
                    fmt(m.overall_avg),
                    fmt(m.overall_std),
                    str(m.count),
                    fmt(m.id_avg),
                    fmt(m.cat_avg),
                    fmt(m.vuln_avg),
                    fmt(m.dec_avg),
                    fmt(m.reason_avg),
                ]
            )

    render_table_png(
        "Hidden Algorithm Experiment: Algorithm × Platform Detailed Scores",
        hid_cols,
        hid_rows_out,
        out_dir / "hidden_algorithm_platform_detail_table.png",
        [0.18, 0.10, 0.10, 0.08, 0.07, 0.06, 0.07, 0.07, 0.08, 0.08, 0.08],
        font_size=6.0,
    )

    print("Wrote:")
    print(out_dir / "informed_algorithm_platform_detail_table.png")
    print(out_dir / "hidden_algorithm_platform_detail_table.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

