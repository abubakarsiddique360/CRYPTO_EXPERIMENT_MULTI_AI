#!/usr/bin/env python3
"""
Run Gemini Informed Algorithm Experiment
AI can see algorithm information (normal cryptanalysis)
"""

import argparse
import asyncio
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
from evaluators.response_evaluator import ResponseEvaluator
from config.experiment_config import ExperimentConfig



from config.output_paths import results_dir
class GeminiInformedAlgorithmExperiment:
    def __init__(self, api_key: str, max_tests: int | None = None, max_per_algorithm: int | None = None, *, run_id: str | None = None):
        self.api_key = api_key
        self.max_tests = max_tests
        self.max_per_algorithm = max_per_algorithm
        self.config = ExperimentConfig()
        self.setup_components()
        self.results = []
        self.metrics = {}
        self.run_id = run_id or datetime.now().strftime("%Y%m%d_%H%M%S")
        self.experiment_timestamp = self.run_id
        self.platform = 'gemini'
        self.condition = 'algorithm_informed'
        self.results_base_dir = results_dir(self.platform, self.condition)
        self.summary_dir = results_dir(self.platform, self.condition, 'experiment_summary')
        self.raw_dir = results_dir(self.platform, self.condition, 'raw_results')
        self.tables_dir = results_dir(self.platform, self.condition, 'tables')
        self.charts_dir = results_dir(self.platform, self.condition, 'charts')

        
        # Create directories
    def setup_components(self):
        """Initialize components"""
        self.classical_ciphers = ClassicalCiphers()
        self.symmetric_crypto = ModernSymmetricCrypto()
        self.asymmetric_crypto = AsymmetricCrypto()
        self.gemini_analyst = GeminiCryptanalyst(self.api_key)
        self.evaluator = ResponseEvaluator()
        
        # Import charts
        from visualization.performance_charts import PerformanceCharts
        self.performance_charts = PerformanceCharts()
    
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
    

    def _select_sample_cases(self, test_cases: List[Dict], max_tests: int) -> List[Dict]:
        """Select a small but diverse sample.

        Strategy: take first occurrence of each algorithm (up to max_tests),
        then fill remaining slots in original order.

        Used by --quick-15.
        """
        if not test_cases or max_tests <= 0:
            return []

        selected: List[Dict] = []
        seen_algorithms: set[str] = set()
        remainder: List[Dict] = []

        for tc in test_cases:
            algo = tc.get('algorithm')
            if algo and algo not in seen_algorithms and len(selected) < max_tests:
                selected.append(tc)
                seen_algorithms.add(algo)
            else:
                remainder.append(tc)

        for tc in remainder:
            if len(selected) >= max_tests:
                break
            selected.append(tc)

        return selected
    async def run_experiment(self):
        """Run the informed algorithm experiment with Gemini"""
        print("\n" + "=" * 70)
        print("GEMINI INFORMED ALGORITHM CRYPTANALYSIS EXPERIMENT")
        print("AI can see algorithm information")
        print("=" * 70)
        
        print(f"Test Configuration:")
        print(f"  Total Tests: {self.config.total_tests}")
        print(f"  Batch Size: {self.config.batch_size}")
        print(f"  Concurrent Requests: {self.config.concurrent_requests}")
        print("=" * 70)
        
        # Generate test cases
        test_cases = self.generate_test_cases()
        if self.max_tests is not None and int(self.max_tests) > 0:
            if self.max_per_algorithm == 1:
                test_cases = self._select_sample_cases(test_cases, int(self.max_tests))
                print(f"\nSample run enabled: {len(test_cases)} test cases selected (max_tests={self.max_tests})")
            else:
                test_cases = test_cases[: int(self.max_tests)]
                print(f"Preflight enabled: using first {len(test_cases)} test cases")
            self.config.total_tests = len(test_cases)
        
        print(f"\nStarting analysis of {len(test_cases)} test cases...")
        
        # Run analysis
        start_time = datetime.now()
        successful_analyses = 0
        
        async with self.gemini_analyst as analyst:
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
                for i, (test_case, gemini_response) in enumerate(zip(batch, batch_results)):
                    evaluation = self.evaluator.evaluate_cryptanalysis(gemini_response, test_case)

                    self.results.append({
                        'test_case': test_case,
                        'gemini_response': {
                            'success': gemini_response.success,
                            'error': gemini_response.error,
                            'parsed_data': gemini_response.parsed_data,
                        },
                        'evaluation': evaluation
                    })

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

    def _calculate_metrics(self):
        """Calculate metrics"""
        if not self.results:
            self.metrics = {'error': 'No results'}
            return
        
        # Basic statistics
        total_tests = len(self.results)
        successful_responses = sum(1 for r in self.results if r['gemini_response']['success'])
        
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
        
        self.metrics = {
            'timestamp': datetime.now().isoformat(),
            'total_tests': total_tests,
            'successful_responses': successful_responses,
            'success_rate': successful_responses / total_tests if total_tests > 0 else 0,
            'overall_score': overall_score,
            'category_metrics': category_metrics,
            'algorithm_metrics': algorithm_metrics,
            'difficulty_metrics': difficulty_metrics,
        }
    def _generate_reports(self):
        """Generate comprehensive reports and visualizations"""
        results_file = str(self.raw_dir / f"{self.platform}_{self.condition}_raw_results_{self.experiment_timestamp}.json")
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'experiment': 'Gemini Cryptanalysis',
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
            response = result.get('gemini_response', {})

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
        print("GEMINI CRYPTANALYSIS EXPERIMENT SUMMARY")
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
    parser = argparse.ArgumentParser(description='Run Gemini algorithm_informed experiment')
    parser.add_argument('--max-tests', type=int, default=0, help='Run only the first N test cases (preflight). 0=all')
    parser.add_argument('--quick-15', action='store_true', help='Quick smoke run: 1 test per algorithm (15 total). Avoids generating all 900 cases.')
    parser.add_argument('--run-id', type=str, default='', help='Stable run id for this run (default: timestamp)')
    parser.add_argument('--log-file', type=str, default='', help='Write a combined stdout/stderr log to this file')
    args = parser.parse_args()

    print('GEMINI INFORMED ALGORITHM CRYPTANALYSIS EXPERIMENT')
    print('=' * 60)

    api_key = os.getenv('GEMINI_API_KEY')
    if not api_key:
        print('Error: GEMINI_API_KEY environment variable not set')
        sys.exit(1)

    analyst = GeminiCryptanalyst(api_key)
    if not analyst.validate_api_key():
        print('API key validation failed')
        sys.exit(1)

    run_id = (args.run_id or '').strip() or datetime.now().strftime('%Y%m%d_%H%M%S')

    log_path = (args.log_file or '').strip()
    if not log_path:
        log_dir = results_dir('gemini', 'algorithm_informed', 'logs')
        log_path = str(log_dir / f'gemini_informed_{run_id}.log')

    log_file = open(log_path, 'a', encoding='utf-8')
    sys.stdout = TeeIO(sys.stdout, log_file)
    sys.stderr = TeeIO(sys.stderr, log_file)

    print(f'Run ID: {run_id}')
    print(f'Log file: {log_path}')

    print('API key validated successfully')

    # Network preflight (fast fail if proxy/network is down)
    try:
        async with GeminiCryptanalyst(api_key) as preflight:
            ok, msg = await preflight.ping()
        if not ok:
            print('ERROR: Gemini API preflight failed:')
            print(f'  {msg}')
            print('If you require a proxy, ensure it is running and OPENAI_PROXY/GEMINI_PROXY is correct (e.g., http://127.0.0.1:7897).')
            sys.exit(1)
        print('Gemini API preflight OK')
    except Exception as e:
        print('ERROR: Gemini API preflight threw an exception:')
        print(f'  {e}')
        sys.exit(1)

    print('Starting Gemini informed algorithm experiment...')
    if getattr(args, 'quick_15', False):
        if not getattr(args, 'max_tests', 0):
            args.max_tests = 15
        print('NOTE: --quick-15 enabled; will run 15 total tests (1 per algorithm).')

    try:
        experiment = GeminiInformedAlgorithmExperiment(
            api_key,
            max_tests=(args.max_tests or None),
            max_per_algorithm=(1 if getattr(args, 'quick_15', False) else None),
            run_id=run_id,
        )
        results, _metrics = await experiment.run_experiment()

        print('\nExperiment completed successfully!')
        print(f'Gemini analyzed {len(results)} ciphertexts with algorithm information.')

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


