#!/usr/bin/env python3
"""repair_grok_hidden_raw_results.py

Rerun a small subset of Grok algorithm_hidden test cases (e.g., failed timeouts)
and patch an existing raw_results JSON in-place.

This script does NOT modify the experiment runners. It only:
- reads an existing `data/results/grok/algorithm_hidden/raw_results/*.json`
- reruns Grok for selected `test_id`s using the stored anonymized `test_case`
- re-evaluates using stored `original_info` (algorithm/category/plaintext)
- updates the JSON (with a timestamped backup)
- writes a JSONL rerun log under `data/results/grok/algorithm_hidden/logs/`

Typical usage:
  python repair_grok_hidden_raw_results.py --only-failed

Or explicitly:
  python repair_grok_hidden_raw_results.py --test-ids test_038 test_061

Notes:
- Requires `GROK_API_KEY` in environment or `.env`.
- Uses small concurrency (default 1) and limited rerun attempts (default 3).
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple


PROJECT_ROOT = Path(__file__).resolve().parent
SRC_DIR = PROJECT_ROOT / "src"
if not SRC_DIR.exists():
    # Support running from subfolders
    PROJECT_ROOT = Path(__file__).resolve()
    while PROJECT_ROOT != PROJECT_ROOT.parent and not (PROJECT_ROOT / "src").exists():
        PROJECT_ROOT = PROJECT_ROOT.parent
    SRC_DIR = PROJECT_ROOT / "src"

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def _load_dotenv_if_present() -> None:
    try:
        from dotenv import load_dotenv  # type: ignore
    except Exception:
        return

    for dotenv_path in (PROJECT_ROOT / ".env", PROJECT_ROOT / ".env.txt"):
        if dotenv_path.exists():
            load_dotenv(dotenv_path)
            return


def _find_latest_raw_results() -> Optional[Path]:
    base = PROJECT_ROOT / "data" / "results" / "grok" / "algorithm_hidden" / "raw_results"
    if not base.exists():
        return None
    candidates = sorted(base.glob("grok_algorithm_hidden_raw_results_*.json"))
    return candidates[-1] if candidates else None


def _parse_test_ids(values: Sequence[str]) -> List[str]:
    out: List[str] = []
    seen = set()
    for v in values:
        if not v:
            continue
        for part in str(v).replace(",", " ").split():
            tid = part.strip()
            if not tid:
                continue
            if tid not in seen:
                out.append(tid)
                seen.add(tid)
    return out


@dataclass
class PatchResult:
    test_id: str
    before_success: bool
    after_success: bool
    attempts: int
    last_error: str


async def _rerun_and_patch(
    *,
    results_path: Path,
    test_ids: List[str],
    concurrent_requests: int,
    rerun_attempts: int,
    log_path: Path,
    ignore_proxy: bool,
) -> Tuple[List[PatchResult], Dict[str, Any]]:
    from config.api_config import AIConfig
    from config.output_paths import results_dir
    from ai_clients.grok_client import GrokCryptanalyst
    from analysis_prompts.algorithm_hidden_analysis_prompts import AlgorithmHiddenAnalysisPrompts
    from evaluators.algorithm_hidden_evaluator import AlgorithmHiddenEvaluator

    cfg = AIConfig()
    if not (cfg.GROK_API_KEY or "").strip():
        raise SystemExit("Missing GROK_API_KEY (set it in .env or your environment).")

    raw = json.loads(results_path.read_text(encoding="utf-8"))
    results = raw.get("results")
    if not isinstance(results, list):
        raise SystemExit(f"{results_path} is missing a top-level 'results' list")

    index_by_test_id: Dict[str, int] = {}
    for i, r in enumerate(results):
        tc = r.get("test_case") if isinstance(r, dict) else None
        tid = (tc or {}).get("test_id") if isinstance(tc, dict) else None
        if isinstance(tid, str):
            index_by_test_id[tid] = i

    missing = [tid for tid in test_ids if tid not in index_by_test_id]
    if missing:
        raise SystemExit(f"Requested test_id(s) not found in results: {missing}")

    prompts = AlgorithmHiddenAnalysisPrompts()
    evaluator = AlgorithmHiddenEvaluator()

    # Pre-compute "before" aggregate counts
    def _resp_success(entry: dict) -> bool:
        ev = entry.get("evaluation") or {}
        return bool((ev.get("response_success") if isinstance(ev, dict) else False))

    before_successes = sum(1 for r in results if isinstance(r, dict) and _resp_success(r))

    log_path.parent.mkdir(parents=True, exist_ok=True)

    patched: List[PatchResult] = []

    analyst_client = GrokCryptanalyst(cfg.GROK_API_KEY)
    if ignore_proxy:
        analyst_client.proxy = ""
        analyst_client.trust_env = False

    async with analyst_client as analyst:
        semaphore = asyncio.Semaphore(max(1, int(concurrent_requests)))

        async def process_one(tid: str) -> PatchResult:
            async with semaphore:
                idx = index_by_test_id[tid]
                entry = results[idx]
                if not isinstance(entry, dict):
                    raise RuntimeError(f"Unexpected non-dict entry for {tid}")

                before_ok = _resp_success(entry)

                test_case = copy.deepcopy(entry.get("test_case") or {})
                if not isinstance(test_case, dict):
                    test_case = {}
                test_case["test_id"] = tid
                test_case["algorithm_hidden"] = True

                enc = test_case.get("encrypted_data")
                if isinstance(enc, dict):
                    test_case["encrypted_data"] = prompts.sanitize_encrypted_data_for_prompt(enc)

                best_response = None
                last_err = ""

                for attempt in range(1, max(1, int(rerun_attempts)) + 1):
                    response = (await analyst.batch_analyze([test_case], concurrent_requests=1))[0]
                    best_response = response
                    last_err = str(response.error or "")

                    # Append attempt record (JSONL)
                    rec = {
                        "timestamp": datetime.now().isoformat(timespec="seconds"),
                        "results_file": str(results_path),
                        "test_id": tid,
                        "attempt": attempt,
                        "success": bool(response.success),
                        "error": response.error,
                        "input_tokens": getattr(response, "input_tokens", None),
                        "output_tokens": getattr(response, "output_tokens", None),
                    }
                    log_path.write_text("", encoding="utf-8") if not log_path.exists() else None
                    with log_path.open("a", encoding="utf-8") as f:
                        f.write(json.dumps(rec, ensure_ascii=False) + "\n")

                    if response.success:
                        break

                if best_response is None:
                    raise RuntimeError(f"No response produced for {tid}")

                original_info = entry.get("original_info") or {}
                if not isinstance(original_info, dict):
                    original_info = {}

                plaintext = (
                    (original_info.get("plaintext") if isinstance(original_info.get("plaintext"), str) else "")
                    or (entry.get("plaintext") if isinstance(entry.get("plaintext"), str) else "")
                )

                original_case = copy.deepcopy(original_info.get("original_case") or {})
                if not isinstance(original_case, dict):
                    original_case = {}
                if plaintext:
                    original_case["plaintext"] = plaintext

                eval_case = {
                    "test_id": tid,
                    "algorithm": original_info.get("algorithm", "unknown"),
                    "category": original_info.get("category", "unknown"),
                    "original_test_case": original_case,
                }

                evaluation = evaluator.evaluate_cryptanalysis(best_response, eval_case)

                entry["grok_response"] = {
                    "success": bool(best_response.success),
                    "error": best_response.error,
                    "parsed_data": getattr(best_response, "parsed_data", None),
                    "input_tokens": getattr(best_response, "input_tokens", 0),
                    "output_tokens": getattr(best_response, "output_tokens", 0),
                }
                entry["evaluation"] = evaluation

                # Keep convenience fields aligned if present
                if plaintext and isinstance(entry.get("plaintext"), str):
                    entry["plaintext"] = plaintext
                if "encrypted_data" in entry and isinstance(test_case.get("encrypted_data"), dict):
                    entry["encrypted_data"] = test_case.get("encrypted_data")

                after_ok = bool(evaluation.get("response_success"))
                return PatchResult(
                    test_id=tid,
                    before_success=bool(before_ok),
                    after_success=bool(after_ok),
                    attempts=min(max(1, int(rerun_attempts)), attempt),
                    last_error=last_err,
                )

        # Execute (bounded) tasks
        tasks = [process_one(tid) for tid in test_ids]
        patched = await asyncio.gather(*tasks)

    # Refresh top-level metrics
    evaluations: List[dict] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        ev = r.get("evaluation")
        if isinstance(ev, dict):
            evaluations.append(ev)

    metrics = evaluator.calculate_aggregate_metrics(evaluations)
    metrics["timestamp"] = datetime.now().isoformat(timespec="seconds")

    raw["metrics"] = metrics
    meta = raw.get("metadata")
    if not isinstance(meta, dict):
        meta = {}
        raw["metadata"] = meta
    meta["repaired_at"] = datetime.now().isoformat(timespec="seconds")
    meta["repaired_test_ids"] = list(test_ids)

    after_successes = sum(1 for r in results if isinstance(r, dict) and _resp_success(r))

    summary = {
        "results_file": str(results_path),
        "log_file": str(log_path),
        "tests_targeted": len(test_ids),
        "successes_before": int(before_successes),
        "successes_after": int(after_successes),
        "success_delta": int(after_successes - before_successes),
        "metrics": metrics,
    }

    return patched, {"raw": raw, "summary": summary}


def main() -> int:
    _load_dotenv_if_present()

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--results-file",
        type=str,
        default="",
        help="Path to an existing grok_algorithm_hidden_raw_results_*.json (defaults to latest)",
    )
    parser.add_argument(
        "--test-ids",
        nargs="*",
        default=[],
        help="One or more anonymized test IDs (e.g., test_038). You can also pass a comma-separated list.",
    )
    parser.add_argument(
        "--only-failed",
        action="store_true",
        help="If set, rerun all tests in the file where evaluation.response_success is false.",
    )
    parser.add_argument(
        "--concurrent",
        type=int,
        default=1,
        help="Max concurrent in-flight reruns (default: 1).",
    )
    parser.add_argument(
        "--rerun-attempts",
        type=int,
        default=3,
        help="How many times to attempt a rerun per test_id until success (default: 3).",
    )
    parser.add_argument(
        "--grok-timeout",
        type=int,
        default=0,
        help="Override GROK_TIMEOUT for this run (seconds).",
    )
    parser.add_argument(
        "--use-proxy",
        action="store_true",
        help="Use GROK_PROXY from .env (default: ignore proxy for direct API calls).",
    )
    parser.add_argument(
        "--grok-max-retries",
        type=int,
        default=-1,
        help="Override GROK_MAX_RETRIES for this run (client internal retries per attempt).",
    )

    args = parser.parse_args()

    results_path = Path(args.results_file) if args.results_file else (_find_latest_raw_results() or Path())
    if not results_path or not results_path.exists():
        raise SystemExit("Could not locate results file. Pass --results-file explicitly.")

    # Optional per-run overrides
    if int(args.grok_timeout or 0) > 0:
        os.environ["GROK_TIMEOUT"] = str(int(args.grok_timeout))
    if int(args.grok_max_retries) >= 0:
        os.environ["GROK_MAX_RETRIES"] = str(int(args.grok_max_retries))

    raw = json.loads(results_path.read_text(encoding="utf-8"))
    results = raw.get("results")
    if not isinstance(results, list):
        raise SystemExit(f"{results_path} does not contain a top-level 'results' list")

    requested_test_ids = _parse_test_ids(args.test_ids)

    if args.only_failed or not requested_test_ids:
        # Default to rerunning failures if nothing explicit was provided.
        inferred_failed: List[str] = []
        for r in results:
            if not isinstance(r, dict):
                continue
            tc = r.get("test_case") or {}
            ev = r.get("evaluation") or {}
            tid = (tc.get("test_id") if isinstance(tc, dict) else None)
            ok = (ev.get("response_success") if isinstance(ev, dict) else False)
            if isinstance(tid, str) and not ok:
                inferred_failed.append(tid)
        test_ids = requested_test_ids or inferred_failed
    else:
        test_ids = requested_test_ids

    if not test_ids:
        print("No test_ids selected for repair (nothing to do).")
        return 0

    from config.output_paths import results_dir

    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    logs_dir = results_dir("grok", "algorithm_hidden", "logs")
    log_path = logs_dir / f"repair_reruns_{stamp}.jsonl"

    # Backup first
    backup_path = results_path.with_suffix("")
    backup_path = backup_path.parent / f"{backup_path.name}.bak_{stamp}.json"
    backup_path.write_text(results_path.read_text(encoding="utf-8"), encoding="utf-8")

    print(f"Repair targets: {len(test_ids)} test(s): {', '.join(test_ids)}")
    print(f"Backup written: {backup_path}")
    print(f"Rerun log: {log_path}")

    patched, out = asyncio.run(
        _rerun_and_patch(
            results_path=results_path,
            test_ids=test_ids,
            concurrent_requests=int(args.concurrent),
            rerun_attempts=int(args.rerun_attempts),
            log_path=log_path,
            ignore_proxy=not bool(args.use_proxy),
        )
    )

    # Write updated JSON back to the same file
    results_path.write_text(json.dumps(out["raw"], indent=2, ensure_ascii=False), encoding="utf-8")

    summary = out["summary"]
    print("\nDone.")
    print(f"Successes before: {summary['successes_before']} / {out['raw']['metrics'].get('total_tests', '?')}")
    print(f"Successes after:  {summary['successes_after']} / {out['raw']['metrics'].get('total_tests', '?')}")

    still_failed = [p.test_id for p in patched if not p.after_success]
    if still_failed:
        print("\nStill failed after reruns:")
        for tid in still_failed:
            pr = next((x for x in patched if x.test_id == tid), None)
            print(f"  - {tid}: {getattr(pr, 'last_error', '')}")
        return 2

    return 0


if __name__ == "__main__":
    raise SystemExit(main())


# REFRESH_2026
