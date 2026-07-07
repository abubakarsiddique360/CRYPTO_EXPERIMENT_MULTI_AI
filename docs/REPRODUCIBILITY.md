# Reproducibility

This repository runs controlled cryptanalysis experiments across multiple LLMs under two conditions:

- **algorithm_hidden**: model infers the algorithm from ciphertext only
- **algorithm_informed**: model is told the algorithm and analyzes weaknesses

## Environment

- Windows recommended (project currently tested on Windows)
- Python 3.11+ recommended

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements_multi_ai.txt
```

## API keys

- Do **not** commit real keys.
- Copy `.env.example` to `.env` and fill in keys locally.

```powershell
Copy-Item .env.example .env
```

Required env vars by platform:

- DeepSeek: `DEEPSEEK_API_KEY`
- OpenAI/ChatGPT: `OPENAI_API_KEY`
- Gemini: `GEMINI_API_KEY`
- Grok: `GROK_API_KEY`

## Run DeepSeek experiments

From repo root:

```powershell
python script\deepseek\run_deepseek_algorithm_hidden_experiment.py
python script\deepseek\run_deepseek_algorithm_informed_experiment.py
```

## Generate charts/tables (post-processing)

```powershell
python script\deepseek\run_deepseek_algorithm_hidden_charts.py
python script\deepseek\run_deepseek_algorithm_informed_charts.py
python script\deepseek\run_deepseek_algorithm_hidden_table_generator.py
python script\deepseek\run_deepseek_algorithm_informed_table.py
```

## Outputs

All outputs go under:

`data/results/{platform}/{condition}/{topic}/`

Examples:

- `data/results/deepseek/algorithm_hidden/raw_results/...json`
- `data/results/deepseek/algorithm_hidden/charts/...html`
- `data/results/deepseek/algorithm_hidden/tables/...html/.png`

By default, `data/results/` is gitignored. See `docs/DATA_POLICY.md`.

# REFRESH_2026
