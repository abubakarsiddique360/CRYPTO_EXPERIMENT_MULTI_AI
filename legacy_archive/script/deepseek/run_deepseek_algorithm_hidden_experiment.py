#!/usr/bin/env python3
"""Run DeepSeek Algorithm Hidden Experiment.

AI cannot see algorithm information; must identify algorithms from ciphertext.

Outputs (standardized):
  data/results/deepseek/algorithm_hidden/raw_results/

Artifacts (flat, under platform root):
  data/results/deepseek/algorithm_hidden_*_{timestamp}.*
"""

import argparse
import asyncio
import copy
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import pandas as pd

PROJECT_ROOT = Path(__file__).resolve()
while PROJECT_ROOT != PROJECT_ROOT.parent and not (PROJECT_ROOT / "src").exists():
    PROJECT_ROOT = PROJECT_ROOT.parent

SRC_DIR = PROJECT_ROOT / "src"
if not SRC_DIR.exists():
    raise RuntimeError("Could not locate project root (missing 'src' directory)")

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None

if load_dotenv:
    for dotenv_path in (PROJECT_ROOT / ".env", PROJECT_ROOT / ".env.txt"):
        if dotenv_path.exists():
            load_dotenv(dotenv_path)
            break

from ai_clients.deepseek_client import DeepSeekCryptanalyst
from analysis_prompts.algorithm_hidden_analysis_prompts import AlgorithmHiddenAnalysisPrompts
from config.experiment_config import ExperimentConfig
from config.output_paths import results_dir
from crypto_systems.asymmetric_crypto import AsymmetricCrypto
from crypto_systems.classical_ciphers import ClassicalCiphers
from crypto_systems.symmetric_modern import ModernSymmetricCrypto
from evaluators.algorithm_hidden_evaluator import AlgorithmHiddenEvaluator
from experiment_design.ai_algorithm_hidden_shuffler import AIAlgorithmHiddenShuffler


class DeepSeekAlgorithmHiddenExperiment:
    def __init__(
        self,
        api_key: str,
        samples_per_algorithm: int | None = None,
        audit: bool = False,
        include_plaintext_in_raw_results: bool = False,
    ):
        self.api_key = api_key
        self.config = ExperimentConfig()
        self.results: List[Dict] = []
        self.metrics: Dict = {}
        self.experiment_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        self.samples_per_algorithm = samples_per_algorithm
        self.audit = bool(audit)
        self.include_plaintext_in_raw_results = bool(include_plaintext_in_raw_results)

        self.platform = "deepseek"
        self.condition = "algorithm_hidden"

        self.results_base_dir = results_dir(self.platform, self.condition)
        self.summary_dir = results_dir(self.platform, self.condition, "experiment_summary")
        self.raw_dir = results_dir(self.platform, self.condition, "raw_results")
        self.tables_dir = results_dir(self.platform, self.condition, "tables")
        self.charts_dir = results_dir(self.platform, self.condition, "charts")

        self.platform_out_dir = results_dir(self.platform, self.condition)

        self.audit_dir = PROJECT_ROOT / 'data' / 'audit' / self.platform / self.condition
        if self.audit:
            self.audit_dir.mkdir(parents=True, exist_ok=True)

        self.setup_components()

    def setup_components(self):
        self.classical_ciphers = ClassicalCiphers()
        self.symmetric_crypto = ModernSymmetricCrypto()
        self.asymmetric_crypto = AsymmetricCrypto()

        self.deepseek_analyst = DeepSeekCryptanalyst(self.api_key)
        self.algorithm_hidden_prompts = AlgorithmHiddenAnalysisPrompts()
        self.algorithm_hidden_evaluator = AlgorithmHiddenEvaluator()

        from visualization.algorithm_hidden_performance_charts import AlgorithmHiddenPerformanceCharts

        self.algorithm_hidden_charts = AlgorithmHiddenPerformanceCharts()

    @staticmethod
    def _redact_original_case(original_case: dict, *, include_plaintext: bool) -> dict:
        """Redact sensitive fields from an original test case before writing artifacts.

        Always removes key material; plaintext is included only when explicitly requested.
        """

        oc2 = copy.deepcopy(original_case)

        # Never persist key material in artifacts
        for k in (
            'key',
            'private_key',
            'secret_key',
            'shared_secret',
            'raw_key',
            'key_bytes',
        ):
            oc2.pop(k, None)

        if not include_plaintext:
            oc2.pop('plaintext', None)

        return oc2

    def generate_test_cases(self) -> List[Dict]:
        test_cases: List[Dict] = []

        print("Generating classical cipher test cases...")
        test_cases.extend(self.classical_ciphers.generate_test_cases(max_per_algorithm=self.samples_per_algorithm))

        print("Generating modern symmetric and hash test cases...")
        test_cases.extend(self.symmetric_crypto.generate_test_cases(max_per_algorithm=self.samples_per_algorithm))

        print("Generating asymmetric test cases...")
        test_cases.extend(self.asymmetric_crypto.generate_test_cases(max_per_algorithm=self.samples_per_algorithm))

        print(f"Generated {len(test_cases)} total test cases")
        return test_cases



    def _select_subset_by_algorithm(self, shuffled_cases: List[Dict], shuffler: AIAlgorithmHiddenShuffler, samples_per_algorithm: int) -> List[Dict]:
        from collections import defaultdict

        counts = defaultdict(int)
        selected: List[Dict] = []
        for c in shuffled_cases:
            info = shuffler.get_original_info(c["test_id"]) or {}
            algo = info.get("algorithm", "unknown")
            if counts[algo] >= samples_per_algorithm:
                continue
            counts[algo] += 1
            selected.append(c)

        # Keep stable order but make sure we didn't accidentally select 0 for any algorithm.
        missing = [a for a in self.algorithm_hidden_evaluator.algorithm_list if counts.get(a, 0) < samples_per_algorithm]
        if missing:
            print(f"WARNING: subset selection missing some algorithms: {missing}")

        print(f"Selected subset: {len(selected)} cases ({samples_per_algorithm} per algorithm)")
        return selected
    async def run_experiment(self):
        print("\n" + "=" * 70)
        print("DEEPSEEK ALGORITHM HIDDEN CRYPTANALYSIS EXPERIMENT")
        print("AI cannot see algorithm information")
        print("=" * 70)

        print("Test Configuration:")
        print(f"  Total Tests: {self.config.total_tests}")
        print(f"  Batch Size: {self.config.batch_size}")
        print(f"  Concurrent Requests: {self.config.concurrent_requests}")
        print("=" * 70)

        test_cases = self.generate_test_cases()
        shuffler = AIAlgorithmHiddenShuffler(test_cases)
        shuffled_cases = shuffler.shuffle_with_stratification(seed=42)
        for case in shuffled_cases:
            case["algorithm_hidden"] = True
            if isinstance(case.get("encrypted_data"), dict):
                case["encrypted_data"] = self.algorithm_hidden_prompts.sanitize_encrypted_data_for_prompt(case["encrypted_data"])

        if self.samples_per_algorithm is not None:
            shuffled_cases = self._select_subset_by_algorithm(shuffled_cases, shuffler, int(self.samples_per_algorithm))

        print("\nTest cases shuffled and anonymized")
        print("AI will only see test IDs (test_001, test_002, ...)")

        mapping_file = str(self.summary_dir / f"test_mapping_{self.experiment_timestamp}.json")
        shuffler.save_mapping(mapping_file)
        print(f"Test mapping saved: {mapping_file}")

        if self.audit:
            audit_file = str(self.audit_dir / f"audit_mapping_{self.experiment_timestamp}.json")
            shuffler.save_audit_mapping(audit_file)
            print(f"Audit mapping saved: {audit_file}")

        start_time = datetime.now()
        successful_analyses = 0

        async with self.deepseek_analyst as analyst:
            batch_size = self.config.batch_size
            total_batches = (len(shuffled_cases) + batch_size - 1) // batch_size

            for batch_num in range(total_batches):
                start_idx = batch_num * batch_size
                end_idx = min(start_idx + batch_size, len(shuffled_cases))
                batch = shuffled_cases[start_idx:end_idx]

                print(f"\nProcessing batch {batch_num + 1}/{total_batches} (cases {start_idx + 1}-{end_idx})")

                batch_results = await analyst.batch_analyze(
                    batch,
                    concurrent_requests=self.config.concurrent_requests,
                )

                for test_case, deepseek_response in zip(batch, batch_results):
                    original_info_raw = shuffler.get_original_info(test_case["test_id"]) or {}
                    plaintext = ''
                    oc_raw = original_info_raw.get("original_case")
                    if isinstance(oc_raw, dict):
                        plaintext = oc_raw.get("plaintext", '') or ''

                    original_info = copy.deepcopy(original_info_raw)
                    oc = original_info.get("original_case")
                    if isinstance(oc, dict):
                        original_info["original_case"] = self._redact_original_case(
                            oc,
                            include_plaintext=self.include_plaintext_in_raw_results,
                        )

                    if self.include_plaintext_in_raw_results:
                        # For manual review only (never sent to the model)
                        original_info["plaintext"] = plaintext

                    eval_original_case = {}
                    if isinstance(oc_raw, dict):
                        eval_original_case = self._redact_original_case(
                            oc_raw,
                            include_plaintext=True,
                        )
                        eval_original_case["plaintext"] = plaintext

                    eval_case = {
                        "test_id": test_case["test_id"],
                        "algorithm": original_info.get("algorithm", "unknown"),
                        "category": original_info.get("category", "unknown"),
                        "original_test_case": eval_original_case if isinstance(eval_original_case, dict) else {},
                    }

                    evaluation = self.algorithm_hidden_evaluator.evaluate_cryptanalysis(
                        deepseek_response,
                        eval_case,
                    )

                    result_entry = {
                        "test_case": test_case,
                        "original_info": original_info,
                        "deepseek_response": {
                            "success": deepseek_response.success,
                            "response_time": deepseek_response.response_time,
                            "error": deepseek_response.error,
                            "parsed_data": deepseek_response.parsed_data,
                            "input_tokens": deepseek_response.input_tokens,
                            "output_tokens": deepseek_response.output_tokens,
                        },
                        "evaluation": evaluation,
                    }

                    if self.include_plaintext_in_raw_results:
                        # Convenience fields for manual inspection (never sent to the model)
                        result_entry["plaintext"] = plaintext
                        result_entry["encrypted_data"] = test_case.get("encrypted_data")

                    self.results.append(result_entry)

                    if deepseek_response.success:
                        successful_analyses += 1

                print(f"  Successful: {sum(1 for r in batch_results if r.success)}/{len(batch)}")

                self._save_progress(batch_num + 1)

                if batch_num < total_batches - 1:
                    await asyncio.sleep(self.config.batch_delay)

        duration = datetime.now() - start_time

        self._calculate_metrics()
        self._generate_reports()
        self._print_experiment_summary(successful_analyses, duration)

        return self.results, self.metrics

    def _save_progress(self, batch_num: int):
        progress_data = {
            "batch": batch_num,
            "timestamp": datetime.now().isoformat(),
            "results_so_far": len(self.results),
        }

        progress_file = str(self.summary_dir / f"progress_batch_{batch_num}_{self.experiment_timestamp}.json")
        with open(progress_file, "w", encoding="utf-8") as f:
            json.dump(progress_data, f, indent=2)

    def _calculate_metrics(self):
        if not self.results:
            self.metrics = {"error": "No results"}
            return

        evaluations = [result["evaluation"] for result in self.results]
        self.metrics = self.algorithm_hidden_evaluator.calculate_aggregate_metrics(evaluations)
        self.metrics["timestamp"] = datetime.now().isoformat()

        total_input_tokens = 0
        total_output_tokens = 0
        for result in self.results:
            response = result["deepseek_response"]
            total_input_tokens += response.get("input_tokens", 0)
            total_output_tokens += response.get("output_tokens", 0)

        self.metrics["total_input_tokens"] = total_input_tokens
        self.metrics["total_output_tokens"] = total_output_tokens

        from config.api_config import AIConfig

        config = AIConfig()
        cost_info = config.get_model_cost("deepseek")

        input_cost = (total_input_tokens / 1000) * cost_info["input"]
        output_cost = (total_output_tokens / 1000) * cost_info["output"]
        total_cost = input_cost + output_cost

        self.metrics["estimated_cost"] = total_cost
        self.metrics["cost_per_test"] = total_cost / len(self.results) if self.results else 0

    def _generate_reports(self):
        print("\n" + "=" * 70)
        print("GENERATING REPORTS AND CHARTS")
        print("=" * 70)

        results_file = str(self.raw_dir / f"{self.platform}_{self.condition}_raw_results_{self.experiment_timestamp}.json")
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "metadata": {
                        "experiment": "DeepSeek Algorithm Hidden Cryptanalysis",
                        "timestamp": self.experiment_timestamp,
                        "test_count": len(self.results),
                        "model": "DeepSeek",
                        "condition": "algorithm_hidden",
                        "model_version": "deepseek-chat",
                    },
                    "metrics": self.metrics,
                    "results": self.results,
                },
                f,
                indent=2,
                ensure_ascii=False,
            )

        print(f" Raw results saved: {results_file}")

        self._generate_csv_report()

        print("\nGenerating 3 performance charts...")
        try:
            self._generate_charts()
            print(" Charts generated successfully!")
        except Exception as e:
            print(f" Error generating charts: {e}")

        print("\nGenerating summary table...")
        try:
            from visualization.algorithm_hidden_table_generator import AlgorithmHiddenTableGenerator

            AlgorithmHiddenTableGenerator(platform=self.platform).run(results_file=results_file)
        except Exception as e:
            print(f" Error generating summary table: {e}")

        print("\n" + "=" * 70)
        print("REPORT GENERATION COMPLETE")
        print("=" * 70)

    def _generate_charts(self):
        self.algorithm_hidden_charts.create_three_charts(
            self.results,
            self.experiment_timestamp,
            output_dir=self.platform_out_dir,
            file_prefix="",
        )

    def _generate_csv_report(self):
        csv_data = []

        for result in self.results:
            evaluation = result["evaluation"]
            csv_data.append(
                {
                    "test_id": evaluation["test_id"],
                    "algorithm": evaluation["algorithm"],
                    "original_category": evaluation.get("category", "unknown"),
                    "identified_category_by_AI": evaluation.get("identified_category", "unknown"),
                    "identified_category_score": evaluation.get("identified_category_score", 0.0),
                    "identified_algorithm_by_AI": evaluation["identified_algorithm"],
                    "identified_algorithm_score": evaluation["identified_algorithm_score"],
                    "response_success": evaluation["response_success"],
                    "overall_score": evaluation["overall_score"],
                    "vulnerability_score": evaluation["vulnerability_score"],
                    "decryption_score": evaluation["decryption_score"],
                    "reasoning_score": evaluation["reasoning_score"],
                    "confidence": evaluation["confidence"],
                    "suggested_attacks_count": evaluation["suggested_attacks_count"],
                    "vulnerabilities_count": evaluation["vulnerabilities_count"],
                    "exact_match": evaluation["exact_match"],
                    "category_match": evaluation["category_match"],
                }
            )

        df = pd.DataFrame(
            csv_data,
            columns=[
                "test_id",
                "algorithm",
                "original_category",
                "identified_category_by_AI",
                "identified_category_score",
                "identified_algorithm_by_AI",
                "identified_algorithm_score",
                "response_success",
                "overall_score",
                "vulnerability_score",
                "decryption_score",
                "reasoning_score",
                "confidence",
                "suggested_attacks_count",
                "vulnerabilities_count",
                "exact_match",
                "category_match",
            ],
        )

        csv_file = str(results_dir(self.platform, self.condition) / (f"{self.condition}_experiment_summary_{self.experiment_timestamp}.csv"))
        df.to_csv(csv_file, index=False)
        print(f" CSV report saved: {csv_file}")

    def _print_experiment_summary(self, successful_analyses: int, duration):
        metrics = self.metrics

        print("\n" + "=" * 70)
        print("DEEPSEEK ALGORITHM HIDDEN EXPERIMENT SUMMARY")
        print("=" * 70)

        print("\nOverall Statistics:")
        print(f"  Total Tests: {metrics.get('total_tests', 0)}")
        print(f"  Successful Analyses: {successful_analyses}")
        print(f"  Success Rate: {metrics.get('success_rate', 0):.1%}")
        print(f"  Overall Score: {metrics.get('avg_overall_score', 0):.3f}")
        print(f"  Duration: {duration}")

        print("\nAlgorithm Identification:")
        print(f"  Exact Match Rate: {metrics.get('exact_match_rate', 0):.1%}")
        print(f"  Category Match Rate: {metrics.get('category_match_rate', 0):.1%}")
        print(f"  Avg Identified_Algo_Score: {metrics.get('avg_identification_score', metrics.get('avg_identified_algorithm_score', 0)):.3f}")

        print("\nToken Usage:")
        print(f"  Total Input Tokens: {metrics.get('total_input_tokens', 0):,}")
        print(f"  Total Output Tokens: {metrics.get('total_output_tokens', 0):,}")
        print(f"  Total Tokens: {metrics.get('total_input_tokens', 0) + metrics.get('total_output_tokens', 0):,}")
        print(f"  Estimated Cost: ${metrics.get('estimated_cost', 0):.4f}")
        print(f"  Cost per Test: ${metrics.get('cost_per_test', 0):.6f}")

        print("\nOutput Files:")
        print(f"  Raw Results: {self.platform}_{self.condition}_raw_results_{self.experiment_timestamp}.json")
        print(f"  CSV Report: {self.condition}_experiment_summary_{self.experiment_timestamp}.csv")
        print("\n3 Chart Files:")
        print(f"  1. algorithm_hidden_algorithm_identification_{self.experiment_timestamp}.html")
        print(f"  2. algorithm_hidden_performance_by_algorithm_{self.experiment_timestamp}.html")
        print(f"  3. algorithm_hidden_performance_trend_{self.experiment_timestamp}.html")


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--samples-per-algo", type=int, default=None, help="Run a mini subset: N samples per algorithm (15 algorithms total).")
    parser.add_argument("--audit", action="store_true", help="Write an audit mapping under data/audit/... (includes plaintext; keys are still removed).")
    parser.add_argument("--include-plaintext-in-raw-results", action="store_true", help="DANGEROUS: Persist plaintext alongside ciphertext in the raw results JSON for manual review. Plaintext is never sent to the model.")
    args = parser.parse_args()

    print("DEEPSEEK ALGORITHM HIDDEN CRYPTANALYSIS EXPERIMENT")
    print("=" * 60)

    api_key = os.getenv("DEEPSEEK_API_KEY")

    if not api_key:
        print("Error: DEEPSEEK_API_KEY environment variable not set")
        sys.exit(1)

    analyst = DeepSeekCryptanalyst(api_key)
    if not analyst.validate_api_key():
        print("API key validation failed")
        sys.exit(1)

    print("API key validated successfully")
    print("Starting DeepSeek algorithm hidden experiment...")

    if getattr(args, 'include_plaintext_in_raw_results', False):
        print('WARNING: --include-plaintext-in-raw-results is enabled; raw results will contain plaintext. Do not share these artifacts.')
    else:
        print('NOTE: plaintext will NOT be saved in raw results. For manual eyeballing, rerun with --include-plaintext-in-raw-results (do not share those artifacts).')

    try:
        experiment = DeepSeekAlgorithmHiddenExperiment(
            api_key,
            samples_per_algorithm=getattr(args, 'samples_per_algo', None),
            audit=getattr(args, 'audit', False),
            include_plaintext_in_raw_results=getattr(args, 'include_plaintext_in_raw_results', False),
        )
        results, _metrics = await experiment.run_experiment()

        print("\nExperiment completed successfully!")
        print(f"DeepSeek analyzed {len(results)} ciphertexts without algorithm information.")

    except Exception as e:
        print(f"Experiment failed: {e}")
        import traceback

        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

# REFRESH_2026
