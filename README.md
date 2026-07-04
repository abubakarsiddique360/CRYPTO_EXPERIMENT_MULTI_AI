# Multi-AI Cryptanalysis Experiment Suite

Framework for running controlled cryptanalysis experiments across multiple LLMs under two conditions:

- **Algorithm Hidden**: the model must infer the algorithm from ciphertext only
- **Algorithm Informed**: the model is told the algorithm and analyzes weaknesses

## Repository layout

- [src/](src/) — core experiment, evaluation, and client code
- [scripts/](scripts/) — paper figure/table generators (write outputs into `data/comparisons/`)
- [data/comparisons/](data/comparisons/) — publication-ready PNG/JPG assets used by the paper
- [paper_ieee_full/main.tex.txt](paper_ieee_full/main.tex.txt) — IEEE paper source (for Overleaf, upload/rename as `main.tex`)
- [docs/](docs/) — reproducibility notes and experiment documentation

## Prerequisites

- Windows
- Python 3.11+ recommended (project tested with Python 3.11)

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements_multi_ai.txt
```

(Optional) On Windows, you can use [run.cmd](run.cmd) to run commands using the repo's `.venv` Python:

```powershell
.\run.cmd -c "import sys; print(sys.executable)"
```

## API keys

Set these environment variables (either in your shell session, or via a local `.env` file).
A template is provided in [.env.example](.env.example).

- `DEEPSEEK_API_KEY`
- `OPENAI_API_KEY`
- `GEMINI_API_KEY`
- `GROK_API_KEY`

## Paper (Overleaf)

The paper source is maintained in [paper_ieee_full/main.tex.txt](paper_ieee_full/main.tex.txt).

For Overleaf, upload it as `main.tex` along with the required figure assets from `data/comparisons/`.

## Reproducing the paper figures (optional)

The generators in [scripts/](scripts/) read raw experiment outputs under `data/results/` and write publication-ready figures/tables into `data/comparisons/`.

Examples:

```powershell
python scripts\generate_platform_algorithm_avgscore_bargraphs.py
python scripts\generate_component_bargraphs.py
python scripts\generate_category_breakdown_bargraphs.py
python scripts\generate_performance_trend_over_test_sequence.py
```

## Citation

If you use this repository in academic work, please use [CITATION.cff](CITATION.cff) for the preferred citation metadata.

## Documentation

- [docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md)
- [docs/DATA_POLICY.md](docs/DATA_POLICY.md)
- [docs/PLAINTEXT_RECOVERY.md](docs/PLAINTEXT_RECOVERY.md)