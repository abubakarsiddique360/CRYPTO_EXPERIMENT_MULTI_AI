# Plaintext Recovery Benchmark (Ciphertext-Only)

This repository includes a **plaintext recovery** benchmark designed to test whether LLMs can recover **plaintext from ciphertext-only** inputs **without any keys/secrets**.

## What this benchmark measures

- **Primary**: plaintext recovery quality from ciphertext-only (token-overlap scoring)
- **Secondary** (hidden condition): whether the model can infer the algorithm family/name (weighted less)

Modern crypto (AES/RSA) ciphertext-only recovery is computationally infeasible in general, so the plaintext-recovery benchmark focuses on **classical ciphers** where ciphertext-only recovery can be at least *plausible*.

## Conditions

- **algorithm_hidden**: model only sees ciphertext (must infer algorithm + guess plaintext)
- **algorithm_informed**: model is told the algorithm name (still no key), then must guess plaintext

If you want the strictest ciphertext-only, no hints benchmark, use **algorithm_hidden** only.

## How it works (pipeline)

1. **Test-case generation**
   - [src/experiment_design/plaintext_recovery_generator.py](../src/experiment_design/plaintext_recovery_generator.py)
   - Generates classical cipher cases (Caesar, Vigenère, optional substitution) with a fixed `seed` for reproducibility.

2. **(Hidden condition) anonymization/shuffling**
   - [src/experiment_design/ai_algorithm_hidden_shuffler.py](../src/experiment_design/ai_algorithm_hidden_shuffler.py)
   - Removes algorithm hints from `encrypted_data` and shuffles cases to reduce pattern leakage.

3. **Prompt creation + model calls**
   - Prompt family: [src/analysis_prompts/plaintext_recovery_prompts.py](../src/analysis_prompts/plaintext_recovery_prompts.py)
   - Clients: [src/ai_clients](../src/ai_clients)
   - The mission marker `mission="plaintext_recovery"` routes prompts to this strict JSON-only format.
   - Clients cap output tokens for `plaintext_recovery` to reduce cost and latency.

4. **Response parsing**
   - [src/ai_clients/base_client.py](../src/ai_clients/base_client.py)
   - Extracts the first valid JSON object, applies defaults, and sanitizes refusal-style outputs.

5. **Evaluation (scoring)**
   - Informed: [src/evaluators/plaintext_recovery_evaluator.py](../src/evaluators/plaintext_recovery_evaluator.py)
   - Hidden: [src/evaluators/algorithm_hidden_evaluator.py](../src/evaluators/algorithm_hidden_evaluator.py) with weights tuned so plaintext recovery dominates.

6. **Outputs (raw + artifacts)**
   - Runner: [src/experiments/plaintext_recovery_experiment.py](../src/experiments/plaintext_recovery_experiment.py)
   - Writes:
     - Raw JSON: `data/results/{platform}/{condition}/raw_results/{platform}_{condition}_raw_results_{timestamp}.json`
     - CSV summary: `data/results/{platform}/{condition}/{condition}_experiment_summary_{timestamp}.csv`
     - HTML tables + charts under `data/results/{platform}/{condition}/` (reusing the screenshot-matching generators)

## How to run

### 1) Setup

```powershell
cd C:\Users\ABU BAKAR SIDDIQUE\CRYPTO_EXPERIMENT_MULTI_AI
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements_multi_ai.txt
```

### 2) Set API keys

```powershell
$env:DEEPSEEK_API_KEY = "..."
$env:OPENAI_API_KEY = "..."
$env:GEMINI_API_KEY = "..."
$env:GROK_API_KEY = "..."
```

### 3) Run plaintext recovery

Single unified entrypoint:

```powershell
.\.venv\Scripts\python.exe script\run_plaintext_recovery.py --platform deepseek --condition algorithm_hidden --per-algorithm 60 --seed 42 --no-substitution
```

Per-platform wrappers:

```powershell
.\.venv\Scripts\python.exe script\deepseek\run_deepseek_plaintext_recovery_hidden.py
.\.venv\Scripts\python.exe script\chatgpt\run_chatgpt_plaintext_recovery_hidden.py
.\.venv\Scripts\python.exe script\gemini\run_gemini_plaintext_recovery_hidden.py
.\.venv\Scripts\python.exe script\grok\run_grok_plaintext_recovery_hidden.py
```

Notes:
- Use `--no-substitution` if you want a cleaner benchmark (substitution can be extremely hard ciphertext-only).
- Keep `--seed` fixed for reproducibility in a research setting.

# REFRESH_2026
