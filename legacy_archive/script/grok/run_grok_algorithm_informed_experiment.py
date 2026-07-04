#!/usr/bin/env python3
"""
Run Grok Informed Algorithm Experiment
AI can see algorithm information (normal cryptanalysis)
"""

import argparse
import asyncio
import json
import os
import sys
import re
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


def _parse_run_id_from_partial_filename(filename: str) -> str | None:
    m = re.search(r'_raw_results_(.+?)_partial\.json$', filename)
    return m.group(1) if m else None


def _find_latest_partial_file(raw_dir: Path) -> Path | None:
    candidates = sorted(raw_dir.glob('*_raw_results_*_partial.json'), key=lambda p: p.stat().st_mtime, reverse=True)
    return candidates[0] if candidates else None

from ai_clients.grok_client import GrokCryptanalyst
from crypto_systems.classical_ciphers import ClassicalCiphers
from crypto_systems.symmetric_modern import ModernSymmetricCrypto
from crypto_systems.asymmetric_crypto import AsymmetricCrypto
from evaluators.response_evaluator import ResponseEvaluator
from config.experiment_config import ExperimentConfig



from config.output_paths import results_dir
class GrokInformedAlgorithmExperiment:
    def __init__(self, api_key: str, max_tests: int | None = None, *, run_id: str | None = None, resume_from: str | None = None):
        self.api_key = api_key
        self.max_tests = max_tests
        self.config = ExperimentConfig()
        self.setup_components()
        self.results = []
        self.metrics = {}
        self.run_id = run_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.experiment_timestamp = self.run_id
        self.resume_from = resume_from

        self.platform = 'grok'
        self.condition = 'algorithm_informed'
        self.results_base_dir = results_dir(self.platform, self.condition)
        self.summary_dir = results_dir(self.platform, self.condition, 'experiment_summary')
        self.raw_dir = results_dir(self.platform, self.condition, 'raw_results')
        self.partial_results_file = self.raw_dir / f"{self.platform}_{self.condition}_raw_results_{self.run_id}_partial.json"
        self.final_results_file = self.raw_dir / f"{self.platform}_{self.condition}_raw_results_{self.run_id}.json"
        self.tables_dir = results_dir(self.platform, self.condition, 'tables')
        self.charts_dir = results_dir(self.platform, self.condition, 'charts')

        
        # Create directories
    def setup_components(self):
        """Initialize components"""
        self.classical_ciphers = ClassicalCiphers()
        self.symmetric_crypto = ModernSymmetricCrypto()
        self.asymmetric_crypto = AsymmetricCrypto()
        self.grok_analyst = GrokCryptanalyst(self.api_key)
        self.evaluator = ResponseEvaluator()
        
        # Import charts
        from visualization.performance_charts import PerformanceCharts
        self.performance_charts = PerformanceCharts()
    
    def generate_test_cases(self) -> List[Dict]:
        """Generate 900 test cases"""
        test_cases = []
        
        

        max_per_algorithm = None
        if self.max_tests is not None and int(self.max_tests) > 0:
            max_per_algorithm = 1
        print("Generating classical cipher test cases...")
        classical_cases = self.classical_ciphers.generate_test_cases(max_per_algorithm=max_per_algorithm)
        test_cases.extend(classical_cases)
        
        print("Generating modern symmetric and hash test cases...")
        symmetric_hash_cases = self.symmetric_crypto.generate_test_cases(max_per_algorithm=max_per_algorithm)
        test_cases.extend(symmetric_hash_cases)
        
        print("Generating asymmetric test cases...")
        asymmetric_cases = self.asymmetric_crypto.generate_test_cases(max_per_algorithm=max_per_algorithm)
        test_cases.extend(asymmetric_cases)
        
        print(f"Generated {len(test_cases)} total test cases")

        if self.max_tests is not None and int(self.max_tests) > 0:
            test_cases = test_cases[: int(self.max_tests)]
            print(f"Preflight enabled: using first {len(test_cases)} test cases")

        # Keep printed config aligned with the actual run.
        try:
            self.config.total_tests = len(test_cases)
        except Exception:
            pass

        return test_cases
    
    async def run_experiment(self):
        """Run the informed algorithm experiment with Grok"""
        print("\n" + "=" * 70)
        print("GROK INFORMED ALGORITHM CRYPTANALYSIS EXPERIMENT")
        print("AI can see algorithm information")
        print("=" * 70)
        
        print(f"Test Configuration:")
        print(f"  Total Tests: {self.config.total_tests}")
        print(f"  Batch Size: {self.config.batch_size}")
        print(f"  Concurrent Requests: {self.config.concurrent_requests}")
        print("=" * 70)
        
        # Generate test cases
        test_cases = self.generate_test_cases()

        # Resume support: if a partial raw results file is provided, skip completed tests
        completed_ids = set()
        if self.resume_from:
            completed_ids = self._load_partial_raw_results(self.resume_from)
            if completed_ids:
                before_count = len(test_cases)
                test_cases = [tc for tc in test_cases if tc.get('test_id') not in completed_ids]
                print(f"Resuming run_id={self.run_id}: remaining {len(test_cases)}/{before_count} test cases")

        
        print(f"\nStarting analysis of {len(test_cases)} test cases...")
        
        # Run analysis
        start_time = datetime.now()
        successful_analyses = 0
        
        async with self.grok_analyst as analyst:
            batch_size = self.config.batch_size
            total_batches = (len(test_cases) + batch_size - 1) // batch_size
            
            for batch_num in range(total_batches):
                start_idx = batch_num * batch_size
                end_idx = min(start_idx + batch_size, len(test_cases))
                batch = test_cases[start_idx:end_idx]
                
                print(f"\nProcessing batch {batch_num + 1}/{total_batches} (cases {start_idx + 1}-{end_idx})")
                
                batch_results = await analyst.batch_analyze(
                    batch, 
                    concurrent_requests=self.config.concurrent_requests
                )
                
                # Evaluate batch
                for i, (test_case, grok_response) in enumerate(zip(batch, batch_results)):
                    evaluation = self.evaluator.evaluate_cryptanalysis(grok_response, test_case)

                    self.results.append({
                        'test_case': test_case,
                        'grok_response': {
                            'success': grok_response.success,
                            'response_time': grok_response.response_time,
                            'error': grok_response.error,
                            'parsed_data': grok_response.parsed_data,
                            'input_tokens': grok_response.input_tokens,
                            'output_tokens': grok_response.output_tokens
                        },
                        'evaluation': evaluation
                    })

                    if grok_response.success:
                        successful_analyses += 1
                
                print(f"  Successful: {sum(1 for r in batch_results if r.success)}/{len(batch)}")
                api_calls = getattr(analyst, 'api_call_count', None)
                api_retries = getattr(analyst, 'api_retry_count', None)
                if api_calls is not None:
                    print(f"  API calls so far: {api_calls} (retries: {api_retries or 0})")
                
                # Save progress
                self._save_progress(batch_num + 1)
                self._save_partial_raw_results(batch_num=batch_num + 1, analyst=analyst)
                
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
        self._print_experiment_summary()
        
        return self.results, self.metrics
    def _save_progress(self, batch_num: int):
        """Save intermediate progress (lightweight; avoids duplicating raw results each batch)."""
        progress_data = {
            'batch': batch_num,
            'timestamp': datetime.now().isoformat(),
            'results_so_far': len(self.results),
        }

        progress_file = str(self.summary_dir / f"experiment_progress_batch_{batch_num}_{self.experiment_timestamp}.json")
        with open(progress_file, 'w', encoding='utf-8') as f:
            json.dump(progress_data, f, indent=2, ensure_ascii=False)

        print(f"Progress saved: {progress_file}")

    def _save_partial_raw_results(self, *, batch_num: int, analyst=None) -> None:
        """Write a resumable partial raw-results snapshot after each batch."""
        meta = {
            'experiment': 'Grok Cryptanalysis',
            'timestamp': self.run_id,
            'is_partial': True,
            'batch': batch_num,
            'test_cases_count_so_far': len(self.results),
        }
        if analyst is not None:
            meta['api_call_count'] = getattr(analyst, 'api_call_count', None)
            meta['api_retry_count'] = getattr(analyst, 'api_retry_count', None)
            meta['api_error_count'] = getattr(analyst, 'api_error_count', None)

        completed_ids = []
        for r in self.results:
            tc = (r or {}).get('test_case') or {}
            tid = tc.get('test_id')
            if tid is not None:
                completed_ids.append(tid)

        payload = {
            'metadata': meta,
            'completed_test_ids': completed_ids,
            'results': self.results,
        }

        try:
            with open(self.partial_results_file, 'w', encoding='utf-8') as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            print(f"Partial raw results saved: {self.partial_results_file}")
        except Exception as e:
            print(f"Warning: failed to write partial raw results: {e}")


    def _load_partial_raw_results(self, resume_path: str | Path) -> set:
        """Load partial results and return completed test_ids set."""
        p = Path(resume_path)
        data = json.loads(p.read_text(encoding='utf-8'))
        prior_results = data.get('results') or []
        if not isinstance(prior_results, list):
            prior_results = []
        self.results = prior_results

        completed = set(data.get('completed_test_ids') or [])
        if not completed:
            # Derive from results if needed
            for r in self.results:
                tc = (r or {}).get('test_case') or {}
                tid = tc.get('test_id')
                if tid is not None:
                    completed.add(tid)
        print(f"Resume loaded: {len(self.results)} prior results; {len(completed)} completed test_ids")
        return completed


    def _calculate_metrics(self):
        """Calculate metrics"""
        if not self.results:
            self.metrics = {'error': 'No results'}
            return
        
        # Basic statistics
        total_tests = len(self.results)
        successful_responses = sum(1 for r in self.results if r['grok_response']['success'])
        
        # Scores by category
        categories = {}
        algorithms = {}
        difficulties = {}
        
        for result in self.results:
            evaluation = result['evaluation']
            test_case = result['test_case']
            category = test_case['category']
            algorithm = test_case['algorithm']
            difficulty = test_case['difficulty']
            
            if category not in categories:
                categories[category] = {'scores': [], 'count': 0}
            if algorithm not in algorithms:
                algorithms[algorithm] = {'scores': [], 'count': 0}
            if difficulty not in difficulties:
                difficulties[difficulty] = {'scores': [], 'count': 0}
            
            score = evaluation['overall_score']
            categories[category]['scores'].append(score)
            categories[category]['count'] += 1
            
            algorithms[algorithm]['scores'].append(score)
            algorithms[algorithm]['count'] += 1
            
            difficulties[difficulty]['scores'].append(score)
            difficulties[difficulty]['count'] += 1
        
        # Calculate averages
        category_metrics = {}
        for category, data in categories.items():
            if data['scores']:
                category_metrics[category] = {
                    'average_score': sum(data['scores']) / len(data['scores']),
                    'test_count': data['count']
                }
        
        algorithm_metrics = {}
        for algorithm, data in algorithms.items():
            if data['scores']:
                algorithm_metrics[algorithm] = {
                    'average_score': sum(data['scores']) / len(data['scores']),
                    'test_count': data['count']
                }
        
        difficulty_metrics = {}
        for difficulty, data in difficulties.items():
            if data['scores']:
                difficulty_metrics[difficulty] = {
                    'average_score': sum(data['scores']) / len(data['scores']),
                    'test_count': data['count']
                }
        
        # Overall score
        overall_score = sum(r['evaluation']['overall_score'] for r in self.results) / total_tests if total_tests > 0 else 0
        
        # Token usage and cost
        total_input_tokens = 0
        total_output_tokens = 0
        for result in self.results:
            response = result['grok_response']
            total_input_tokens += response.get('input_tokens', 0)
            total_output_tokens += response.get('output_tokens', 0)
        
        from config.api_config import AIConfig
        config = AIConfig()
        cost_info = config.get_model_cost('grok')
        
        input_cost = (total_input_tokens / 1000) * cost_info['input']
        output_cost = (total_output_tokens / 1000) * cost_info['output']
        total_cost = input_cost + output_cost
        
        self.metrics = {
            'timestamp': datetime.now().isoformat(),
            'total_tests': total_tests,
            'successful_responses': successful_responses,
            'success_rate': successful_responses / total_tests if total_tests > 0 else 0,
            'overall_score': overall_score,
            'category_metrics': category_metrics,
            'algorithm_metrics': algorithm_metrics,
            'difficulty_metrics': difficulty_metrics,
            'total_input_tokens': total_input_tokens,
            'total_output_tokens': total_output_tokens,
            'estimated_cost': total_cost,
            'cost_per_test': total_cost / total_tests if total_tests > 0 else 0
        }
    def _generate_reports(self):
        """Generate comprehensive reports and visualizations"""
        results_file = str(self.final_results_file)
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'experiment': 'Grok Cryptanalysis',
                    'timestamp': self.experiment_timestamp,
                    'test_cases_count': len(self.results),
                    'configuration': {
                        'classical_ciphers': self.config.classical_cipher_count,
                        'modern_symmetric': self.config.modern_symmetric_count,
                        'asymmetric': self.config.asymmetric_count,
                        'hash_functions': self.config.hash_count,
                        'total_tests': self.config.total_tests,
                    },
                },
                'metrics': self.metrics,
                'results': self.results,
            }, f, indent=2, ensure_ascii=False)

        self._generate_csv_report()

        print("\nGenerating comprehensive visualizations...")
        try:
            self.performance_charts.create_comprehensive_dashboard(
                self.results,
                self.metrics,
                self.experiment_timestamp,
                output_dir=str(results_dir(self.platform, self.condition)),
                file_prefix="",
            )
            print("Performance charts generated successfully!")

            # Generate summary table (flat under platform results dir)
            try:
                from visualization.algorithm_informed_table_generator import AlgorithmInformedTableGenerator
                AlgorithmInformedTableGenerator(platform=self.platform).run(results_file=results_file)
            except Exception as e:
                print(f"Error generating summary table: {e}")
        except Exception as e:
            print(f"Error generating visualizations: {e}")

        self._print_experiment_summary()

        print(f"\nALL OUTPUT FILES:")
        print(f"  Raw results: {results_file}")
        print(f"  CSV report: {self.condition}_experiment_summary_{self.experiment_timestamp}.csv")
        print(f"  Performance charts: 5 interactive HTML files")
        print(f"     1. algorithm_informed_confidence_vs_actual_{self.experiment_timestamp}.html")
        print(f"     2. algorithm_informed_time_series_analysis_{self.experiment_timestamp}.html")
        print(f"     3. algorithm_informed_component_score_breakdown_{self.experiment_timestamp}.html")
        print(f"     4. algorithm_informed_performance_by_category_{self.experiment_timestamp}.html")
        print(f"     5. algorithm_informed_performance_by_algorithm_{self.experiment_timestamp}.html")
    def _generate_csv_report(self):
        """Generate CSV report for detailed analysis"""
        csv_data = []

        for result in self.results:
            test_case = result['test_case']
            evaluation = result['evaluation']
            response = result.get('grok_response', {})

            row = {
                'test_id': test_case.get('test_id'),
                'algorithm': test_case.get('algorithm'),
                'category': test_case.get('category'),
                'difficulty': test_case.get('difficulty'),
                'response_success': bool(response.get('success')),
                'overall_score': evaluation.get('overall_score', 0),
                'vulnerability_score': evaluation.get('vulnerability_detection_score', evaluation.get('vulnerability_score', 0)),
                'decryption_score': evaluation.get('decryption_success_score', evaluation.get('decryption_score', 0)),
                'reasoning_score': evaluation.get('reasoning_quality_score', evaluation.get('reasoning_score', 0)),
                'confidence': evaluation.get('confidence_score', evaluation.get('confidence', 0)),
                'suggested_attacks_count': len(evaluation.get('suggested_attacks', [])),
                'vulnerabilities_count': len(evaluation.get('vulnerabilities_found', [])),
            }
            csv_data.append(row)

        df = pd.DataFrame(csv_data, columns=['test_id', 'algorithm', 'category', 'difficulty', 'response_success', 'overall_score', 'vulnerability_score', 'decryption_score', 'reasoning_score', 'confidence', 'suggested_attacks_count', 'vulnerabilities_count'])
        csv_file = str(results_dir(self.platform, self.condition) / (f"{self.condition}_experiment_summary_{self.experiment_timestamp}.csv"))
        df.to_csv(csv_file, index=False)
        print(f"CSV report saved: {csv_file}")
    def _print_experiment_summary(self):
        """Print comprehensive experiment summary"""
        metrics = self.metrics

        print("\n" + "=" * 60)
        print("GROK CRYPTANALYSIS EXPERIMENT SUMMARY")
        print("=" * 60)

        print(f"Overall Statistics:")
        print(f"  Total Tests: {metrics.get('total_tests', 0)}")
        print(f"  Successful Responses: {metrics.get('successful_responses', 0)} ({metrics.get('success_rate', 0):.1%})")
        print(f"  Overall Score: {metrics.get('overall_score', 0):.3f}")

        print(f"\nPerformance by Category:")
        for category, data in metrics.get('category_metrics', {}).items():
            print(f"  {category:20} Score: {data.get('average_score', 0):.3f} ({data.get('test_count', 0)} tests)")

        print(f"\nPerformance by Algorithm:")
        for algorithm, data in metrics.get('algorithm_metrics', {}).items():
            print(f"  {algorithm:20} Score: {data.get('average_score', 0):.3f} ({data.get('test_count', 0)} tests)")

        print(f"\nPerformance by Difficulty:")
        for difficulty, data in metrics.get('difficulty_metrics', {}).items():
            print(f"  {difficulty:20} Score: {data.get('average_score', 0):.3f} ({data.get('test_count', 0)} tests)")


async def main():
    """Main function"""
    parser = argparse.ArgumentParser(description='Run Grok algorithm_informed experiment')
    parser.add_argument('--max-tests', type=int, default=0, help='Run only the first N test cases (preflight). 0=all')
    parser.add_argument('--run-id', type=str, default='', help='Stable run id for resumable runs (default: timestamp)')
    parser.add_argument('--log-file', type=str, default='', help='Write a combined stdout/stderr log to this file')
    parser.add_argument('--resume', action='store_true', help='Resume from the latest partial raw results snapshot (if present)')
    parser.add_argument('--resume-from', type=str, default='', help='Resume from a specific partial raw results JSON file')
    args = parser.parse_args()

    print('GROK INFORMED ALGORITHM CRYPTANALYSIS EXPERIMENT')
    print('=' * 60)

    api_key = os.getenv('GROK_API_KEY')
    if not api_key:
        print('Error: GROK_API_KEY environment variable not set')
        sys.exit(1)

    analyst = GrokCryptanalyst(api_key)
    if not analyst.validate_api_key():
        print('API key validation failed')
        sys.exit(1)

    # Determine resume file/run id
    raw_dir = results_dir('grok', 'algorithm_informed', 'raw_results')
    resume_from = (args.resume_from or '').strip()
    if args.resume and not resume_from:
        latest = _find_latest_partial_file(raw_dir)
        if latest:
            resume_from = str(latest)

    run_id = (args.run_id or '').strip()
    if not run_id and resume_from:
        run_id = _parse_run_id_from_partial_filename(Path(resume_from).name) or ''
    if not run_id:
        run_id = datetime.now().strftime('%Y%m%d_%H%M%S')

    # Set up log tee (prints still go to terminal, but also into file)
    log_path = (args.log_file or '').strip()
    if not log_path:
        log_dir = results_dir('grok', 'algorithm_informed', 'logs')
        log_path = str(log_dir / f'grok_informed_{run_id}.log')

    log_file = open(log_path, 'a', encoding='utf-8')
    sys.stdout = TeeIO(sys.stdout, log_file)
    sys.stderr = TeeIO(sys.stderr, log_file)

    print(f'Run ID: {run_id}')
    print(f'Log file: {log_path}')
    if resume_from:
        print(f'Resume from: {resume_from}')

    print('API key validated successfully')
    print('Starting Grok informed algorithm experiment...')

    try:
        experiment = GrokInformedAlgorithmExperiment(
            api_key,
            max_tests=(args.max_tests or None),
            run_id=run_id,
            resume_from=(resume_from or None),
        )
        results, _metrics = await experiment.run_experiment()
        print('\nExperiment completed successfully!')
        print(f'Grok analyzed {len(results)} ciphertexts with algorithm information.')
        print(f'Final raw results: {experiment.final_results_file}')
        print(f'Partial raw results: {experiment.partial_results_file}')

    except Exception as e:
        print(f'Experiment failed: {e}')
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        try:
            log_file.flush()
            log_file.close()
        except Exception:
            pass


if __name__ == '__main__':
    asyncio.run(main())










