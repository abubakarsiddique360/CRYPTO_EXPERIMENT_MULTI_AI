#!/usr/bin/env python3
"""
Run Gemini AlgorithmHidden Experiment
AI cannot see algorithm information; must identify algorithms from ciphertext.
"""

import argparse
import asyncio
import copy
import json
import os
import sys
from datetime import datetime
from typing import Dict, List
import pandas as pd

from pathlib import Path

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
    for dotenv_path in (PROJECT_ROOT / '.env', PROJECT_ROOT / '.env.txt'):
        if dotenv_path.exists():
            load_dotenv(dotenv_path)
            break


class TeeIO:
    def __init__(self, *streams):
        self._streams = [s for s in streams if s is not None]

    def write(self, data):
        for s in self._streams:
            try:
                s.write(data)
                s.flush()
            except Exception:
                pass
        return len(data)

    def flush(self):
        for s in self._streams:
            try:
                s.flush()
            except Exception:
                pass



import os
USE_GENAI = str(os.getenv("GEMINI_USE_GENAI", "")).strip().lower() in ("1", "true", "yes", "on")
if USE_GENAI:
    from ai_clients.gemini_genai_sdk_client import GeminiGenAISDKCryptanalyst as GeminiCryptanalyst
else:
    from ai_clients.gemini_client import GeminiCryptanalyst
from crypto_systems.classical_ciphers import ClassicalCiphers
from crypto_systems.symmetric_modern import ModernSymmetricCrypto
from crypto_systems.asymmetric_crypto import AsymmetricCrypto
from analysis_prompts.algorithm_hidden_analysis_prompts import AlgorithmHiddenAnalysisPrompts
from evaluators.algorithm_hidden_evaluator import AlgorithmHiddenEvaluator
from experiment_design.ai_algorithm_hidden_shuffler import AIAlgorithmHiddenShuffler
from config.experiment_config import ExperimentConfig

from config.output_paths import results_dir
class GeminiAlgorithmHiddenExperiment:
    def __init__(self, api_key: str, audit: bool = False, include_plaintext_in_raw_results: bool = False, max_per_algorithm: int | None = None, *, run_id: str | None = None):
        self.api_key = api_key
        self.max_per_algorithm = max_per_algorithm
        self.audit = bool(audit)
        self.include_plaintext_in_raw_results = bool(include_plaintext_in_raw_results)
        self.config = ExperimentConfig()
        self.setup_components()
        self.results = []
        self.metrics = {}
        self.run_id = run_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.experiment_timestamp = self.run_id
        self.platform = 'gemini'
        self.condition = 'algorithm_hidden'
        self.results_base_dir = results_dir(self.platform, self.condition)
        self.summary_dir = results_dir(self.platform, self.condition, 'experiment_summary')
        self.raw_dir = results_dir(self.platform, self.condition, 'raw_results')
        self.tables_dir = results_dir(self.platform, self.condition, 'tables')
        self.charts_dir = results_dir(self.platform, self.condition, 'charts')

        
        
        self.audit_dir = PROJECT_ROOT / 'data' / 'audit' / self.platform / self.condition
        if self.audit:
            self.audit_dir.mkdir(parents=True, exist_ok=True)
# Create directories
    def setup_components(self):
        """Initialize components"""
        self.classical_ciphers = ClassicalCiphers()
        self.symmetric_crypto = ModernSymmetricCrypto()
        self.asymmetric_crypto = AsymmetricCrypto()
        self.gemini_analyst = GeminiCryptanalyst(self.api_key)
        self.algorithm_hidden_prompts = AlgorithmHiddenAnalysisPrompts()
        self.algorithm_hidden_evaluator = AlgorithmHiddenEvaluator()
        
        # Import charts
        from visualization.algorithm_hidden_performance_charts import AlgorithmHiddenPerformanceCharts
        self.algorithm_hidden_charts = AlgorithmHiddenPerformanceCharts()

    @staticmethod
    def _redact_original_case(original_case: dict, *, include_plaintext: bool) -> dict:
        # Redact sensitive fields from an original test case before writing artifacts.
        # Always removes key material; plaintext is included only when explicitly requested.

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
        """Generate 900 test cases"""
        test_cases = []
        
        print("Generating classical cipher test cases...")
        classical_cases = self.classical_ciphers.generate_test_cases(max_per_algorithm=self.max_per_algorithm)
        test_cases.extend(classical_cases)
        
        print("Generating modern symmetric and hash test cases...")
        symmetric_hash_cases = self.symmetric_crypto.generate_test_cases(max_per_algorithm=self.max_per_algorithm)
        test_cases.extend(symmetric_hash_cases)
        
        print("Generating asymmetric test cases...")
        asymmetric_cases = self.asymmetric_crypto.generate_test_cases(max_per_algorithm=self.max_per_algorithm)
        test_cases.extend(asymmetric_cases)
        
        print(f"Generated {len(test_cases)} total test cases")
        return test_cases
    
    async def run_experiment(self):
        """Run the algorithm hidden experiment with Gemini"""
        print("\n" + "=" * 70)
        print("GEMINI ALGORITHM HIDDEN CRYPTANALYSIS EXPERIMENT")
        print("AI cannot see algorithm information")
        print("=" * 70)
        
        print(f"Test Configuration:")
        display_total_tests = (
            self.config.total_tests
            if self.max_per_algorithm is None
            else int(self.max_per_algorithm) * 15
        )
        print(f"  Total Tests: {display_total_tests}")
        print(f"  Batch Size: {self.config.batch_size}")
        print(f"  Concurrent Requests: {self.config.concurrent_requests}")
        print("=" * 70)
        
        # Generate and shuffle test cases
        test_cases = self.generate_test_cases()
        shuffler = AIAlgorithmHiddenShuffler(test_cases)
        shuffled_cases = shuffler.shuffle_with_stratification(seed=42)
        for case in shuffled_cases:
            case['algorithm_hidden'] = True
            if isinstance(case.get('encrypted_data'), dict):
                case['encrypted_data'] = self.algorithm_hidden_prompts.sanitize_encrypted_data_for_prompt(case['encrypted_data'])
        
        print(f"\nTest cases shuffled and anonymized")
        print(f"AI will only see test IDs (test_001, test_002, ...)")
        
        # Save mapping
        mapping_file = str(self.summary_dir / f"test_mapping_{self.experiment_timestamp}.json")
        shuffler.save_mapping(mapping_file)
        print(f"Test mapping saved: {mapping_file}")

        if self.audit:
            audit_file = str(self.audit_dir / f"audit_mapping_{self.experiment_timestamp}.json")
            shuffler.save_audit_mapping(audit_file)
            print(f"Audit mapping saved: {audit_file}")
        
        # Run analysis
        start_time = datetime.now()
        successful_analyses = 0
        
        async with self.gemini_analyst as analyst:
            batch_size = self.config.batch_size
            total_batches = (len(shuffled_cases) + batch_size - 1) // batch_size
            
            for batch_num in range(total_batches):
                start_idx = batch_num * batch_size
                end_idx = min(start_idx + batch_size, len(shuffled_cases))
                batch = shuffled_cases[start_idx:end_idx]
                
                print(f"\nProcessing batch {batch_num + 1}/{total_batches} (cases {start_idx + 1}-{end_idx})")
                
                batch_results = await analyst.batch_analyze(
                    batch, 
                    concurrent_requests=self.config.concurrent_requests
                )
                
                # Evaluate batch
                for i, (test_case, gemini_response) in enumerate(zip(batch, batch_results)):
                    original_info_raw = shuffler.get_original_info(test_case['test_id']) or {}
                    plaintext = ''
                    oc_raw = original_info_raw.get('original_case')
                    if isinstance(oc_raw, dict):
                        plaintext = oc_raw.get('plaintext', '') or ''

                    original_info = copy.deepcopy(original_info_raw)
                    oc = original_info.get('original_case')
                    if isinstance(oc, dict):
                        original_info['original_case'] = self._redact_original_case(
                            oc,
                            include_plaintext=self.include_plaintext_in_raw_results,
                        )

                    if self.include_plaintext_in_raw_results:
                        # For manual review only (never sent to the model)
                        original_info['plaintext'] = plaintext

                    eval_original_case = {}
                    if isinstance(oc_raw, dict):
                        eval_original_case = self._redact_original_case(
                            oc_raw,
                            include_plaintext=True,
                        )
                        eval_original_case['plaintext'] = plaintext

                    eval_case = {
                        'test_id': test_case['test_id'],
                        'algorithm': original_info.get('algorithm', 'unknown'),
                        'category': original_info.get('category', 'unknown'),
                        'original_test_case': eval_original_case if isinstance(eval_original_case, dict) else {}
                    }

                    evaluation = self.algorithm_hidden_evaluator.evaluate_cryptanalysis(
                        gemini_response, eval_case
                    )

                    result_entry = {
                        'test_case': test_case,
                        'gemini_response': {
                            'success': gemini_response.success,
                            'error': gemini_response.error,
                            'parsed_data': gemini_response.parsed_data,
                        },
                        'evaluation': evaluation
                    }

                    if self.include_plaintext_in_raw_results:
                        # Convenience fields for manual inspection (never sent to the model)
                        result_entry['plaintext'] = plaintext
                        result_entry['encrypted_data'] = test_case.get('encrypted_data')

                    self.results.append(result_entry)
                    if gemini_response.success:
                        successful_analyses += 1
                
                print(f"  Successful: {sum(1 for r in batch_results if r.success)}/{len(batch)}")
                
                # Save progress
                self._save_progress(batch_num + 1)
                
                # Rate limiting
                if batch_num < total_batches - 1:
                    await asyncio.sleep(self.config.batch_delay)
        
        # Calculate duration
        end_time = datetime.now()
        duration = end_time - start_time
        
        # Calculate metrics
        self._calculate_metrics()
        
        # Generate reports
        self._generate_reports()
        
        # Print summary
        self._print_experiment_summary(successful_analyses, duration)
        
        return self.results, self.metrics
    def _save_progress(self, batch_num: int):
        """Save progress with consistent timestamp"""
        progress_data = {
            'batch': batch_num,
            'timestamp': datetime.now().isoformat(),
            'results_so_far': len(self.results)
        }

        progress_file = str(self.summary_dir / f"progress_batch_{batch_num}_{self.experiment_timestamp}.json")
        with open(progress_file, 'w', encoding='utf-8') as f:
            json.dump(progress_data, f, indent=2)

    def _calculate_metrics(self):
        """Calculate metrics"""
        if not self.results:
            self.metrics = {'error': 'No results'}
            return
        
        evaluations = [result['evaluation'] for result in self.results]
        self.metrics = self.algorithm_hidden_evaluator.calculate_aggregate_metrics(evaluations)
        self.metrics['timestamp'] = datetime.now().isoformat()
        
        # Calculate total tokens and cost
        total_input_tokens = 0
        total_output_tokens = 0
        for result in self.results:
            response = result['gemini_response']
            total_input_tokens += response.get('input_tokens', 0)
            total_output_tokens += response.get('output_tokens', 0)
        
        self.metrics['total_input_tokens'] = total_input_tokens
        self.metrics['total_output_tokens'] = total_output_tokens
        
        # Calculate estimated cost
        from config.api_config import AIConfig
        config = AIConfig()
        cost_info = config.get_model_cost('gemini')
        
        input_cost = (total_input_tokens / 1000) * cost_info['input']
        output_cost = (total_output_tokens / 1000) * cost_info['output']
        total_cost = input_cost + output_cost
        
        self.metrics['estimated_cost'] = total_cost
        self.metrics['cost_per_test'] = total_cost / len(self.results) if self.results else 0
    
    def _generate_reports(self):
        """Generate reports and charts"""
        print("\n" + "=" * 70)
        print("GENERATING REPORTS AND CHARTS")
        print("=" * 70)
        
        # Save raw results
        results_file = str(self.raw_dir / f"{self.platform}_{self.condition}_raw_results_{self.experiment_timestamp}.json")
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'experiment': 'Gemini Algorithm Hidden Cryptanalysis',
                    'timestamp': self.experiment_timestamp,
                    'test_count': len(self.results),
                    'model': 'Gemini',
                    'condition': 'algorithm_hidden',
                    'model_version': 'gemini-pro'
                },
                'metrics': self.metrics,
                'results': self.results
            }, f, indent=2, ensure_ascii=False)
        
        print(f"âœ“ Raw results saved: {results_file}")
        
        # Generate CSV report
        self._generate_csv_report()
        
        # Generate charts
        print("\nGenerating 3 performance charts...")
        try:
            # Update chart output directory
            self._generate_charts_with_custom_path()
            print("âœ“ Charts generated successfully!")

            # Generate summary table (flat under platform results dir)
            try:
                from visualization.algorithm_hidden_table_generator import AlgorithmHiddenTableGenerator
                AlgorithmHiddenTableGenerator(platform=self.platform).run(results_file=results_file)
            except Exception as e:
                print(f"Error generating summary table: {e}")
        except Exception as e:
            print(f"âœ— Error generating charts: {e}")
        
        print("\n" + "=" * 70)
        print("REPORT GENERATION COMPLETE")
        print("=" * 70)
    
    def _generate_charts_with_custom_path(self):
        """Generate charts directly into the platform charts directory"""
        self.algorithm_hidden_charts.create_three_charts(
            self.results,
            self.experiment_timestamp,
            output_dir=results_dir(self.platform, self.condition),
            file_prefix="",
        )

    def _generate_csv_report(self):
        """Generate CSV report with consistent timestamp"""
        csv_data = []

        for result in self.results:
            evaluation = result['evaluation']

            csv_data.append({
                'test_id': evaluation.get('test_id'),
                'algorithm': evaluation.get('algorithm'),
                'original_category': evaluation.get('category', 'unknown'),
                'identified_category_by_AI': evaluation.get('identified_category', 'unknown'),
                'identified_category_score': evaluation.get('identified_category_score', 0.0),
                'identified_algorithm_by_AI': evaluation.get('identified_algorithm', 'unknown'),
                'identified_algorithm_score': evaluation.get('identified_algorithm_score', 0.0),
                'response_success': evaluation.get('response_success', False),
                'overall_score': evaluation.get('overall_score', 0.0),
                'vulnerability_score': evaluation.get('vulnerability_score', 0.0),
                'decryption_score': evaluation.get('decryption_score', 0.0),
                'decryption_applicable': evaluation.get('decryption_applicable', False),
                'decryption_kind': evaluation.get('decryption_kind', 'not_applicable'),
                'decryption_acknowledged_infeasible': evaluation.get('decryption_acknowledged_infeasible', False),
                'decryption_plaintext_similarity': evaluation.get('decryption_plaintext_similarity', 0.0),
                'decryption_plaintext_exact_match': evaluation.get('decryption_plaintext_exact_match', False),
                'reasoning_score': evaluation.get('reasoning_score', 0.0),
                'confidence': evaluation.get('confidence', 0.0),
                'suggested_attacks_count': evaluation.get('suggested_attacks_count', 0),
                'vulnerabilities_count': evaluation.get('vulnerabilities_count', 0),
                'exact_match': evaluation.get('exact_match', False),
                'category_match': evaluation.get('category_match', False),
            })

        df = pd.DataFrame(
            csv_data,
            columns=[
                'test_id',
                'algorithm',
                'original_category',
                'identified_category_by_AI',
                'identified_category_score',
                'identified_algorithm_by_AI',
                'identified_algorithm_score',
                'response_success',
                'overall_score',
                'vulnerability_score',
                'decryption_score',
                'decryption_applicable',
                'decryption_kind',
                'decryption_acknowledged_infeasible',
                'decryption_plaintext_similarity',
                'decryption_plaintext_exact_match',
                'reasoning_score',
                'confidence',
                'suggested_attacks_count',
                'vulnerabilities_count',
                'exact_match',
                'category_match',
            ],
        )

        csv_file = str(results_dir(self.platform, self.condition) / (f"{self.condition}_experiment_summary_{self.experiment_timestamp}.csv"))
        df.to_csv(csv_file, index=False)
        print(f" CSV report saved: {csv_file}")

    def _print_experiment_summary(self, successful_analyses: int, duration):
        """Print experiment summary"""
        metrics = self.metrics
        
        print("\n" + "=" * 70)
        print("GEMINI ALGORITHM HIDDEN EXPERIMENT SUMMARY")
        print("=" * 70)
        
        print(f"\nOverall Statistics:")
        print(f"  Total Tests: {metrics.get('total_tests', 0)}")
        print(f"  Successful Analyses: {successful_analyses}")
        print(f"  Success Rate: {metrics.get('success_rate', 0):.1%}")
        print(f"  Overall Score: {metrics.get('avg_overall_score', 0):.3f}")
        print(f"  Duration: {duration}")
        
        print(f"\nAlgorithm Identification:")
        print(f"  Exact Match Rate: {metrics.get('exact_match_rate', 0):.1%}")
        print(f"  Category Match Rate: {metrics.get('category_match_rate', 0):.1%}")
        print(f"  Avg Identified_Algo_Score: {metrics.get('avg_identification_score', metrics.get('avg_identified_algorithm_score', 0)):.3f}")
        
        print(f"\nToken Usage:")
        print(f"  Total Input Tokens: {metrics.get('total_input_tokens', 0):,}")
        print(f"  Total Output Tokens: {metrics.get('total_output_tokens', 0):,}")
        print(f"  Total Tokens: {metrics.get('total_input_tokens', 0) + metrics.get('total_output_tokens', 0):,}")
        print(f"  Estimated Cost: ${metrics.get('estimated_cost', 0):.4f}")
        print(f"  Cost per Test: ${metrics.get('cost_per_test', 0):.6f}")
        
        print(f"\nOutput Files:")
        print(f"  Raw Results: {self.platform}_{self.condition}_raw_results_{self.experiment_timestamp}.json")
        print(f"  CSV Report: {self.condition}_experiment_summary_{self.experiment_timestamp}.csv")
        print(f"\n3 Chart Files:")
        print(f"  1. algorithm_hidden_algorithm_identification_{self.experiment_timestamp}.html")
        print(f"  2. algorithm_hidden_performance_by_algorithm_{self.experiment_timestamp}.html")
        print(f"  3. algorithm_hidden_performance_trend_{self.experiment_timestamp}.html")

async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit", action="store_true", help="Write an audit mapping under data/audit/... (includes plaintext; keys are still removed).")
    parser.add_argument("--include-plaintext-in-raw-results", action="store_true", help="DANGEROUS: Persist plaintext in each result's original_info for manual review. Plaintext is never sent to the model.")
    parser.add_argument("--quick-15", action="store_true", help="Quick smoke run: 1 test per algorithm (15 total). Avoids generating all 900 cases.")
    parser.add_argument('--run-id', type=str, default='', help='Stable run id for this run (default: timestamp)')
    parser.add_argument('--log-file', type=str, default='', help='Write a combined stdout/stderr log to this file')
    args = parser.parse_args()

    print("GEMINI ALGORITHM HIDDEN CRYPTANALYSIS EXPERIMENT")
    print("=" * 60)

    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key:
        print("Error: GEMINI_API_KEY environment variable not set")
        sys.exit(1)

    analyst = GeminiCryptanalyst(api_key)
    if not analyst.validate_api_key():
        print("API key validation failed")
        sys.exit(1)

    run_id = (args.run_id or '').strip() or datetime.now().strftime('%Y%m%d_%H%M%S')

    log_path = (args.log_file or '').strip()
    if not log_path:
        log_dir = results_dir('gemini', 'algorithm_hidden', 'logs')
        log_path = str(log_dir / f'gemini_hidden_{run_id}.log')

    log_file = open(log_path, 'a', encoding='utf-8')
    sys.stdout = TeeIO(sys.stdout, log_file)
    sys.stderr = TeeIO(sys.stderr, log_file)

    print(f'Run ID: {run_id}')
    print(f'Log file: {log_path}')

    print("API key validated successfully")

    # Network preflight (fast fail if proxy/network is down)
    try:
        async with GeminiCryptanalyst(api_key) as preflight:
            ok, msg = await preflight.ping()
        if not ok:
            print("ERROR: Gemini API preflight failed:")
            print(f"  {msg}")
            print("If you require a proxy, ensure it is running and OPENAI_PROXY/GEMINI_PROXY is correct (e.g., http://127.0.0.1:7897).")
            sys.exit(1)
        print("Gemini API preflight OK")
    except Exception as e:
        print("ERROR: Gemini API preflight threw an exception:")
        print(f"  {e}")
        sys.exit(1)

    print("Starting Gemini algorithm hidden experiment...")

    if getattr(args, 'quick_15', False):
        print("NOTE: --quick-15 enabled; will run 15 total tests (1 per algorithm).")

    if getattr(args, "include_plaintext_in_raw_results", False):
        print("WARNING: --include-plaintext-in-raw-results is enabled; raw results will contain plaintext. Do not share these artifacts.")
    else:
        print("NOTE: plaintext will NOT be saved in raw results. For manual eyeballing, rerun with --include-plaintext-in-raw-results (do not share those artifacts).")

    try:
        experiment = GeminiAlgorithmHiddenExperiment(
            api_key,
            audit=getattr(args, 'audit', False),
            include_plaintext_in_raw_results=getattr(args, 'include_plaintext_in_raw_results', False),
            max_per_algorithm=(1 if getattr(args, 'quick_15', False) else None),
            run_id=run_id,
        )
        results, _metrics = await experiment.run_experiment()

        print("\nExperiment completed successfully!")
        print(f"Gemini analyzed {len(results)} ciphertexts without algorithm information.")

    except Exception as e:
        print(f"Experiment failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        try:
            log_file.flush()
            log_file.close()
        except Exception:
            pass


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user (Ctrl+C). You may have partial artifacts under data/results/gemini/algorithm_hidden.")
        raise
