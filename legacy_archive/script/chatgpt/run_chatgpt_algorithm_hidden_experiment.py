#!/usr/bin/env python3
"""
Run ChatGPT AlgorithmHidden Experiment
Uses the ChatGPT API for algorithm-hidden runs
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

from ai_clients.chatgpt_client import ChatGPTCryptanalyst
from crypto_systems.classical_ciphers import ClassicalCiphers
from crypto_systems.symmetric_modern import ModernSymmetricCrypto
from crypto_systems.asymmetric_crypto import AsymmetricCrypto
from analysis_prompts.algorithm_hidden_analysis_prompts import AlgorithmHiddenAnalysisPrompts
from evaluators.algorithm_hidden_evaluator import AlgorithmHiddenEvaluator
from experiment_design.ai_algorithm_hidden_shuffler import AIAlgorithmHiddenShuffler
from config.experiment_config import ExperimentConfig

from config.output_paths import results_dir
class ChatGPTAlgorithmHiddenExperiment:
    def __init__(self, api_key: str, audit: bool = False, include_plaintext_in_raw_results: bool = False, max_per_algorithm: int | None = None, resume_timestamp: str | None = None):
        self.api_key = api_key
        self.audit = bool(audit)
        self.include_plaintext_in_raw_results = bool(include_plaintext_in_raw_results)
        self.max_per_algorithm = max_per_algorithm
        self.config = ExperimentConfig()
        self.setup_components()
        self.results = []
        self.metrics = {}
        self.experiment_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.resume_timestamp = (str(resume_timestamp) if resume_timestamp else None)

        self.platform = 'chatgpt'
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
        self.chatgpt_analyst = ChatGPTCryptanalyst(self.api_key)
        self.algorithm_hidden_prompts = AlgorithmHiddenAnalysisPrompts()
        self.algorithm_hidden_evaluator = AlgorithmHiddenEvaluator()
        
        # We'll reuse the same charts from visualization
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

    
    class _LoadedMappingShuffler:
        def __init__(self, mapping: dict):
            self.mapping = mapping or {}

        def get_original_info(self, anonymized_id: str) -> dict:
            return self.mapping.get(anonymized_id, {})

    def _load_resume_state(self) -> tuple[list[dict], '_LoadedMappingShuffler', int]:
        """Load shuffled cases + checkpoint results and return (cases, shuffler, start_batch).

        Note: For correct decryption scoring on resumptions, we prefer a resume_mapping_{ts}.json
        containing plaintext. If absent, plaintext will be unavailable for remaining cases and
        decryption_score will be 0.0 for applicable algorithms.
        """

        if not self.resume_timestamp:
            raise RuntimeError('resume_timestamp not set')

        ts = self.resume_timestamp

        shuffled_cases_file = self.summary_dir / f"shuffled_test_cases_{ts}.json"
        if not shuffled_cases_file.exists():
            raise FileNotFoundError(f"Missing shuffled cases file: {shuffled_cases_file}")

        checkpoint_file = self.raw_dir / f"{self.platform}_{self.condition}_raw_results_{ts}_CHECKPOINT.json"
        if not checkpoint_file.exists():
            raise FileNotFoundError(f"Missing checkpoint file: {checkpoint_file}")

        # Mapping with plaintext (preferred)
        resume_map_file = self.summary_dir / f"resume_mapping_{ts}.json"
        mapping_file = self.summary_dir / f"test_mapping_{ts}.json"

        mapping: dict = {}
        if resume_map_file.exists():
            mapping = json.load(open(resume_map_file, 'r', encoding='utf-8'))
        elif mapping_file.exists():
            mapping = json.load(open(mapping_file, 'r', encoding='utf-8'))
            print('WARNING: resume_mapping file not found; plaintext unavailable for remaining cases; decryption_score will be 0.0 for decryptable algorithms.')
        else:
            print('WARNING: no mapping file found; original_info for remaining cases will be empty.')

        shuffled_cases = json.load(open(shuffled_cases_file, 'r', encoding='utf-8'))
        ckpt = json.load(open(checkpoint_file, 'r', encoding='utf-8'))

        self.results = ckpt.get('results', []) or []

        last_batch = int((ckpt.get('metadata') or {}).get('batch_num') or 0)
        start_batch = last_batch + 1

        return shuffled_cases, self._LoadedMappingShuffler(mapping), start_batch

    def generate_test_cases(self) -> List[Dict]:
        """Generate 900 test cases (same as DeepSeek)"""
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
        """Run the algorithm hidden experiment with ChatGPT"""
        print("\n" + "=" * 70)
        print("CHATGPT ALGORITHM HIDDEN CRYPTANALYSIS EXPERIMENT")
        print("AI cannot see algorithm information")
        print("=" * 70)
        
        print(f"Test Configuration:")
        display_total_tests = (self.config.total_tests if self.max_per_algorithm is None else int(self.max_per_algorithm) * 15)
        print(f"  Total Tests: {display_total_tests}")
        print(f"  Batch Size: {self.config.batch_size}")
        print(f"  Concurrent Requests: {self.config.concurrent_requests}")
        print("=" * 70)
        
        # Generate and shuffle test cases (or resume from checkpoint)
        start_batch_num = 1

        if self.resume_timestamp:
            # Resume uses existing shuffled cases + checkpoint results
            self.experiment_timestamp = self.resume_timestamp
            shuffled_cases, shuffler, start_batch_num = self._load_resume_state()
            print(f"Resuming run timestamp={self.resume_timestamp} from batch {start_batch_num}")
        else:
            test_cases = self.generate_test_cases()
            shuffler = AIAlgorithmHiddenShuffler(test_cases)
            shuffled_cases = shuffler.shuffle_with_stratification(seed=42)
            for case in shuffled_cases:
                case['algorithm_hidden'] = True
                if isinstance(case.get('encrypted_data'), dict):
                    case['encrypted_data'] = self.algorithm_hidden_prompts.sanitize_encrypted_data_for_prompt(case['encrypted_data'])
            print("\nTest cases shuffled and anonymized")
            print("AI will only see test IDs (test_001, test_002, ...)")

            # Save mapping
            mapping_file = str(self.summary_dir / f"test_mapping_{self.experiment_timestamp}.json")
            shuffler.save_mapping(mapping_file)
            print(f"Test mapping saved: {mapping_file}")

            if self.audit:
                audit_file = str(self.audit_dir / f"audit_mapping_{self.experiment_timestamp}.json")
                shuffler.save_audit_mapping(audit_file)
                print(f"Audit mapping saved: {audit_file}")

            # Persist shuffled cases for resumability
            try:
                shuffled_cases_file = str(self.summary_dir / f"shuffled_test_cases_{self.experiment_timestamp}.json")
                with open(shuffled_cases_file, 'w', encoding='utf-8') as f:
                    json.dump(shuffled_cases, f, indent=2, ensure_ascii=False)
                print(f"Shuffled cases saved: {shuffled_cases_file}")
            except Exception as e:
                print(f"Warning: failed to save shuffled cases: {e}")

            # Persist mapping with plaintext when explicitly allowed (needed for correct resume scoring)
            if self.include_plaintext_in_raw_results:
                try:
                    resume_map_file = str(self.summary_dir / f"resume_mapping_{self.experiment_timestamp}.json")
                    resume_map = {}
                    for tid, info in (shuffler.mapping or {}).items():
                        entry = dict(info)
                        oc = entry.get('original_case')
                        if isinstance(oc, dict):
                            oc2 = dict(oc)
                            for k in ('key','private_key','secret_key','shared_secret','raw_key','key_bytes'):
                                oc2.pop(k, None)
                            entry['original_case'] = oc2
                        resume_map[tid] = entry
                    with open(resume_map_file, 'w', encoding='utf-8') as f:
                        json.dump(resume_map, f, indent=2, ensure_ascii=False)
                    print(f"Resume mapping saved: {resume_map_file}")
                except Exception as e:
                    print(f"Warning: failed to save resume mapping: {e}")

        # Run analysis
        start_time = datetime.now()
        successful_analyses = 0
        
        async with self.chatgpt_analyst as analyst:
            # ChatGPT preflight: fail fast on network/proxy/region issues
            ok, msg = await analyst.ping()
            if not ok:
                raise RuntimeError(f"ChatGPT preflight failed: {msg}")
            batch_size = self.config.batch_size
            total_batches = (len(shuffled_cases) + batch_size - 1) // batch_size

            current_batch = 0
            try:
                # start_batch_num is 1-based
                for batch_num in range(int(start_batch_num) - 1, total_batches):
                    current_batch = batch_num + 1
                    start_idx = batch_num * batch_size
                    end_idx = min(start_idx + batch_size, len(shuffled_cases))
                    batch = shuffled_cases[start_idx:end_idx]
                
                    print(f"\nProcessing batch {batch_num + 1}/{total_batches} (cases {start_idx + 1}-{end_idx})")
                
                    batch_results = await analyst.batch_analyze(
                        batch, 
                        concurrent_requests=self.config.concurrent_requests
                    )

                    # Fail fast if OpenAI blocks this VPN/region mid-run
                    for _r in batch_results:
                        _err = str(getattr(_r, 'error', '') or '')
                        if 'unsupported_country_region_territory' in _err.lower():
                            raise RuntimeError('OpenAI rejected this network location: unsupported_country_region_territory. Switch VPN region or disable VPN and retry.')
                
                    # Evaluate batch
                    for i, (test_case, chatgpt_response) in enumerate(zip(batch, batch_results)):
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
                            chatgpt_response, eval_case
                        )

                        result_entry = {
                            'test_case': test_case,
                            'original_info': original_info,
                            'chatgpt_response': {
                                'success': chatgpt_response.success,
                                'response_time': chatgpt_response.response_time,
                                'error': chatgpt_response.error,
                                'parsed_data': chatgpt_response.parsed_data,
                                'input_tokens': chatgpt_response.input_tokens,
                                'output_tokens': chatgpt_response.output_tokens
                            },
                            'evaluation': evaluation
                        }

                        if self.include_plaintext_in_raw_results:
                            # Convenience fields for manual inspection (never sent to the model)
                            result_entry['plaintext'] = plaintext
                            result_entry['encrypted_data'] = test_case.get('encrypted_data')

                        self.results.append(result_entry)
                        if chatgpt_response.success:
                            successful_analyses += 1
                
                    print(f"  Successful: {sum(1 for r in batch_results if r.success)}/{len(batch)}")
                
                    # Save progress
                    self._save_progress(batch_num + 1)
                
                    # Rate limiting
                    if batch_num < total_batches - 1:
                        await asyncio.sleep(self.config.batch_delay)
            except asyncio.CancelledError:
                print("\nInterrupted (async cancellation); saving progress...")
                if current_batch > 0:
                    self._save_progress(current_batch, cancelled=True, cancelled_reason="cancelled")
                self._try_write_partial_raw_results(reason="cancelled", batch_num=current_batch)
                raise
            except Exception as e:
                print(f"\nRun failed: {e!r}; saving progress...")
                if current_batch > 0:
                    self._save_progress(current_batch, cancelled=True, cancelled_reason=f"error: {type(e).__name__}")
                self._try_write_partial_raw_results(reason=f"error_{type(e).__name__}", batch_num=current_batch)
                raise
        
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
    def _save_progress(
        self,
        batch_num: int,
        *,
        cancelled: bool = False,
        cancelled_reason: str | None = None,
    ):
        """Save progress with consistent timestamp"""
        progress_data = {
            'batch': batch_num,
            'timestamp': datetime.now().isoformat(),
            'results_so_far': len(self.results),
            'cancelled': bool(cancelled),
            'cancelled_reason': cancelled_reason,
        }

        progress_file = str(self.summary_dir / f"progress_batch_{batch_num}_{self.experiment_timestamp}.json")
        with open(progress_file, 'w', encoding='utf-8') as f:
            json.dump(progress_data, f, indent=2)

        try:
            self._write_checkpoint_raw_results(batch_num=batch_num)
        except Exception as e:
            print(f"Warning: failed to write checkpoint raw results: {type(e).__name__}: {e}")

    def _write_checkpoint_raw_results(self, *, batch_num: int):
        """Write an always-overwritten checkpoint raw_results file for safe resume after interruption."""

        checkpoint_file = str(self.raw_dir / f"{self.platform}_{self.condition}_raw_results_{self.experiment_timestamp}_CHECKPOINT.json")

        payload = {
            'metadata': {
                'experiment': 'ChatGPT Algorithm Hidden Cryptanalysis',
                'timestamp': self.experiment_timestamp,
                'test_count': len(self.results),
                'model': 'ChatGPT',
                'condition': 'algorithm_hidden',
                'model_version': str(self.chatgpt_analyst.model or ''),
                'partial': True,
                'checkpoint': True,
                'batch_num': int(batch_num),
            },
            'metrics': self.metrics,
            'results': self.results,
        }

        with open(checkpoint_file, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

    def _try_write_partial_raw_results(self, *, reason: str, batch_num: int | None):
        """Best-effort partial raw_results dump when a run is interrupted."""

        if not self.results:
            return

        try:
            self._calculate_metrics()
        except Exception as e:  # best-effort only
            from datetime import datetime
            self.metrics = {
                'error': f'metrics_failed: {type(e).__name__}: {e}',
                'timestamp': datetime.now().isoformat(),
            }

        import re

        reason_slug = re.sub(r"[^a-zA-Z0-9._-]+", "_", (reason or "partial")).strip("_")
        reason_slug = reason_slug[:64] or "partial"

        suffix = f"PARTIAL_{reason_slug}"
        if batch_num:
            suffix = f"{suffix}_batch{int(batch_num)}"

        results_file = str(self.raw_dir / f"{self.platform}_{self.condition}_raw_results_{self.experiment_timestamp}_{suffix}.json")

        payload = {
            'metadata': {
                'experiment': 'ChatGPT Algorithm Hidden Cryptanalysis',
                'timestamp': self.experiment_timestamp,
                'test_count': len(self.results),
                'model': 'ChatGPT',
                'condition': 'algorithm_hidden',
                'model_version': str(self.chatgpt_analyst.model or ''),
                'partial': True,
                'partial_reason': reason,
                'batch_num': batch_num,
            },
            'metrics': self.metrics,
            'results': self.results,
        }

        try:
            import json
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            print(f"OK Partial raw results saved: {results_file}")
        except Exception as e:  # last resort
            print(f"Warning: failed to write partial raw results: {type(e).__name__}: {e}")

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
            response = result['chatgpt_response']
            total_input_tokens += response.get('input_tokens', 0)
            total_output_tokens += response.get('output_tokens', 0)
        
        self.metrics['total_input_tokens'] = total_input_tokens
        self.metrics['total_output_tokens'] = total_output_tokens
        
        # Calculate estimated cost
        from config.api_config import AIConfig
        config = AIConfig()
        cost_info = config.get_model_cost('chatgpt')
        
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
                    'experiment': 'ChatGPT Algorithm Hidden Cryptanalysis',
                    'timestamp': self.experiment_timestamp,
                    'test_count': len(self.results),
                    'model': 'ChatGPT',
                    'condition': 'algorithm_hidden',
                    'model_version': str(self.chatgpt_analyst.model or '')
                },
                'metrics': self.metrics,
                'results': self.results
            }, f, indent=2, ensure_ascii=False)
        
        print(f"OK Raw results saved: {results_file}")
        
        # Generate CSV report
        self._generate_csv_report()
        
        # Generate charts
        print("\nGenerating 3 performance charts...")
        try:
            # Update chart output directory
            original_results_dir = 'data/results'
            # We need to ensure charts go to chatgpt directory
            self._generate_charts_with_custom_path()
            print("OK Charts generated successfully!")

            # Generate summary table (flat under platform results dir)
            try:
                from visualization.algorithm_hidden_table_generator import AlgorithmHiddenTableGenerator
                AlgorithmHiddenTableGenerator(platform=self.platform).run(results_file=results_file)
            except Exception as e:
                print(f"Error generating summary table: {e}")

        except Exception as e:
            print(f"Error generating charts: {e}")

        print("\n" + "=" * 70)
        print("REPORT GENERATION COMPLETE")
        print("=" * 70)
    
    def _generate_charts_with_custom_path(self):
        """Generate charts directly into the chatgpt results directory."""
        self.algorithm_hidden_charts.create_three_charts(
            self.results,
            self.experiment_timestamp,
            output_dir=str(results_dir(self.platform, self.condition)),
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
        print("CHATGPT ALGORITHM HIDDEN EXPERIMENT SUMMARY")
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
    """Main function"""
    parser = argparse.ArgumentParser()
    parser.add_argument("--audit", action="store_true", help="Write an audit mapping under data/audit/... (includes plaintext; keys are still removed).")
    parser.add_argument("--quick-15", action="store_true", help="Quick smoke run: 1 test per algorithm (15 total). Avoids generating all 900 cases.")
    parser.add_argument("--include-plaintext-in-raw-results", action="store_true", help="DANGEROUS: Persist plaintext in each result's original_info for manual review. Plaintext is never sent to the model.")
    parser.add_argument("--resume-timestamp", type=str, default=None, help="Resume an interrupted run from its CHECKPOINT + shuffled_test_cases. Provide the experiment timestamp like 20260128_133800.")
    args = parser.parse_args()
    print("CHATGPT ALGORITHM HIDDEN CRYPTANALYSIS EXPERIMENT")
    print("=" * 60)
    
    # Load API key
    api_key = os.getenv('OPENAI_API_KEY')
    
    if not api_key:
        print("Error: OPENAI_API_KEY environment variable not set")
        print("Set it with: export OPENAI_API_KEY='your_key_here'")
        sys.exit(1)
    
    # Validate API key
    analyst = ChatGPTCryptanalyst(api_key)
    if not analyst.validate_api_key():
        print("API key validation failed")
        sys.exit(1)
    
    print("API key validated successfully")
    print("Starting ChatGPT algorithm hidden experiment...")
    if getattr(args, 'quick_15', False):
        print("NOTE: --quick-15 enabled; will run 15 total tests (1 per algorithm).")
    if getattr(args, "include_plaintext_in_raw_results", False):
        print("WARNING: --include-plaintext-in-raw-results is enabled; raw results will contain plaintext. Do not share these artifacts.")
    else:
        print("NOTE: plaintext will NOT be saved in raw results. For manual eyeballing, rerun with --include-plaintext-in-raw-results (do not share those artifacts).")
    
    try:
        experiment = ChatGPTAlgorithmHiddenExperiment(
            api_key,
            audit=getattr(args, "audit", False),
            include_plaintext_in_raw_results=getattr(args, 'include_plaintext_in_raw_results', False),
            max_per_algorithm=(1 if getattr(args, 'quick_15', False) else None),
            resume_timestamp=getattr(args, 'resume_timestamp', None),
        )
        results, metrics = await experiment.run_experiment()
        
        print(f"\nExperiment completed successfully!")
        print(f"ChatGPT analyzed {len(results)} ciphertexts without algorithm information.")
        
    except (asyncio.CancelledError, KeyboardInterrupt):
        print("Interrupted; exiting. Partial progress (if any) is saved under experiment_summary.")
        sys.exit(130)

    except Exception as e:
        print(f"Experiment failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())

