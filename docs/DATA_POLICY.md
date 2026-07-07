# Data Policy

## What is generated

Running experiments generates artifacts under `data/results/`:

- `raw_results/*.json`: model responses + parsed JSON + evaluation metrics
- `charts/*.html`: interactive Plotly dashboards
- `tables/*`: summary tables (HTML/PNG) and CSV summaries

## What should be committed

Recommended for a research-paper GitHub repo:

- Commit **code** (`src/`, `script/`, `config/`) and **documentation**.
- Do **not** commit:
  - API keys (`.env`)
  - large run outputs by default (`data/results/`)

## Sharing results safely

If you want to share a snapshot of results for reviewers/readers:

Option A (recommended):
- Export a small, curated subset into a separate folder (e.g. `data/results_sample/`) and commit only that.

Option B:
- Publish results as a versioned release artifact (zip) instead of committing to git.

## Secrets

- `.env` is ignored by git.
- `.env.example` should be committed as a template.

# REFRESH_2026
