from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import List

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


PLATFORMS = [
    ("deepseek", "DeepSeek"),
    ("chatgpt", "ChatGPT"),
    ("gemini", "Gemini"),
    ("grok", "Grok"),
]


def load_experiment_config() -> object:
    cfg_path = Path("config") / "experiment_config.py"
    spec = importlib.util.spec_from_file_location("experiment_config", cfg_path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Failed to load config from {cfg_path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module.ExperimentConfig()  # type: ignore[attr-defined]


def render_table_png(
    title: str,
    columns: List[str],
    rows: List[List[str]],
    out_path: Path,
    col_widths: List[float],
    font_size: int = 7,
    cell_loc: str = "left",
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
    fig_h = max(1.8, 0.36 * n_rows)

    fig, ax = plt.subplots(figsize=(fig_w, fig_h), dpi=300)
    ax.axis("off")

    table_data = [columns] + rows
    tbl = ax.table(cellText=table_data, loc="center", cellLoc=cell_loc)

    for (ri, ci), cell in tbl.get_celld().items():
        cell.set_edgecolor("black")
        cell.set_linewidth(0.6)
        if ri == 0:
            cell.set_text_props(weight="bold")
            cell.set_facecolor("#f2f2f2")
        else:
            cell.set_facecolor("white")

        cell.PAD = 0.16
        cell.get_text().set_wrap(True)

        # For instruction tables, left alignment is usually easiest to scan.
        cell.get_text().set_ha("left")

    for ci, w in enumerate(col_widths):
        for ri in range(n_rows):
            tbl[(ri, ci)].set_width(w)

    tbl.auto_set_font_size(False)
    tbl.set_fontsize(font_size)
    tbl.scale(1.0, 1.45)

    fig.tight_layout()
    fig.savefig(out_path, bbox_inches="tight", pad_inches=0.02)
    plt.close(fig)


def main() -> int:
    cfg = load_experiment_config()

    platforms_count = len(PLATFORMS)
    conditions_count = 2

    total_tests_per_condition = int(getattr(cfg, "total_tests"))

    alg_counts = [
        int(getattr(cfg, "caesar_count")),
        int(getattr(cfg, "vigenere_count")),
        int(getattr(cfg, "substitution_count")),
        int(getattr(cfg, "aes_gcm_count")),
        int(getattr(cfg, "aes_cbc_count")),
        int(getattr(cfg, "aes_ctr_count")),
        int(getattr(cfg, "aes_ecb_count")),
        int(getattr(cfg, "chacha20_count")),
        int(getattr(cfg, "rsa_2048_count")),
        int(getattr(cfg, "rsa_4096_count")),
        int(getattr(cfg, "ecdsa_count")),
        int(getattr(cfg, "ed25519_count")),
        int(getattr(cfg, "sha256_count")),
        int(getattr(cfg, "sha3_256_count")),
        int(getattr(cfg, "blake3_count")),
    ]
    algorithm_count = len(alg_counts)
    unique_counts = sorted(set(alg_counts))
    if len(unique_counts) == 1:
        tests_per_algorithm = str(unique_counts[0])
    else:
        tests_per_algorithm = f"{unique_counts[0]}–{unique_counts[-1]}"

    total_model_analyses_planned = total_tests_per_condition * platforms_count * conditions_count

    batch_size = int(getattr(cfg, "batch_size"))
    batch_delay = int(getattr(cfg, "batch_delay"))
    concurrent_requests = int(getattr(cfg, "concurrent_requests"))
    max_retries = int(getattr(cfg, "max_retries"))
    request_timeout = int(getattr(cfg, "request_timeout"))

    out_dir = Path("data") / "comparisons"

    cols1 = ["Item", "Value", "Notes"]

    platform_names = ", ".join([lbl for _, lbl in PLATFORMS])

    rows1: List[List[str]] = [
        [
            "Experiment conditions",
            "2",
            "Hidden Algorithm Experiment\nInformed Algorithm Experiment",
        ],
        [
            "AI platforms",
            f"{platforms_count}",
            platform_names,
        ],
        [
            "Algorithm count",
            f"{algorithm_count}",
            "3 classical; 5 symmetric\n4 asymmetric; 3 hash",
        ],
        [
            "Tests per algorithm",
            tests_per_algorithm,
            "Configured in experiment config",
        ],
        [
            "Total test cases (per condition)",
            f"{total_tests_per_condition}",
            "All algorithms pooled\n(one row per generated test)",
        ],
        [
            "Total model analyses\n(per platform × condition)",
            f"{total_tests_per_condition}",
            "One model response per test case",
        ],
        [
            "Total model analyses\n(all platforms × both conditions)",
            f"{total_model_analyses_planned}",
            "Planned: tests × platforms × conditions",
        ],
        [
            "Batching / concurrency",
            f"batch_size={batch_size}\nconcurrent={concurrent_requests}",
            f"batch_delay={batch_delay}s\nmax_retries={max_retries}\ntimeout={request_timeout}s",
        ],
        [
            "Saved artifacts",
            "JSON/CSV + figures",
            "Raw results under data/results/...\nPaper artifacts under data/comparisons/",
        ],
    ]

    render_table_png(
        "Instruction Summary Table 1: Experiment At-a-Glance",
        cols1,
        rows1,
        out_dir / "instruction_summary_table_1_overview.png",
        [0.32, 0.18, 0.50],
        font_size=7,
    )

    cols2 = ["Layer", "Inputs", "What it does", "Outputs"]

    rows2: List[List[str]] = [
        [
            "Test Generation",
            "Plaintext samples\n+ algorithm spec",
            "Generate per-algorithm test cases\n(15 × 60) and ground truth fields",
            "Generated encrypted/transform samples\n+ metadata",
        ],
        [
            "Prompt Engineering",
            "Generated samples\n+ condition",
            "Build prompts for Hidden vs Informed settings",
            "Model-ready requests\n(batched)",
        ],
        [
            "API Layer",
            "Batched requests",
            "Send requests to each platform; collect responses\nwith retries/timeouts",
            "Raw responses\n+ per-test status",
        ],
        [
            "Response Parsing",
            "Raw responses",
            "Normalize to per-test result fields\n(IDs/attempts/confidence)",
            "Per-test structured results",
        ],
        [
            "Evaluation Engine",
            "Per-test results\n+ ground truth",
            "Compute component scores and overall score",
            "Metrics: identification, detection, attempt,\nconfidence, overall",
        ],
        [
            "Persistence",
            "Structured results",
            "Write machine-readable outputs\nfor later aggregation",
            "data/results/<platform>/<condition>/\nraw_results/*.json (+ CSV)",
        ],
        [
            "Paper Artifacts",
            "Raw results JSON",
            "Aggregate and render final tables/figures",
            "data/comparisons/*.png\n(selected graphs/tables)",
        ],
    ]

    render_table_png(
        "Instruction Summary Table 2: Experiment Pipeline Layers",
        cols2,
        rows2,
        out_dir / "instruction_summary_table_2_pipeline.png",
        [0.18, 0.22, 0.32, 0.28],
        font_size=7,
    )

    print("Wrote:")
    print(out_dir / "instruction_summary_table_1_overview.png")
    print(out_dir / "instruction_summary_table_2_pipeline.png")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# REFRESH_2026
