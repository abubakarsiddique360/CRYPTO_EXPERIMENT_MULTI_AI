#!/usr/bin/env python3
import asyncio
import argparse
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
import pandas as pd

# Ensure project root + src are on sys.path (so `config` and `visualization` import reliably)
PROJECT_ROOT = Path(__file__).resolve()
while PROJECT_ROOT != PROJECT_ROOT.parent and not (PROJECT_ROOT / 'src').exists():
    PROJECT_ROOT = PROJECT_ROOT.parent

SRC_DIR = PROJECT_ROOT / 'src'
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from crypto_systems.classical_ciphers import ClassicalCiphers
from crypto_systems.symmetric_modern import ModernSymmetricCrypto
from crypto_systems.asymmetric_crypto import AsymmetricCrypto
from visualization.performance_charts import PerformanceCharts
from visualization.table_generator import TableGenerator
from config.experiment_config import ExperimentConfig
from config.output_paths import results_dir
from ai_clients.deepseek_client import DeepSeekCryptanalyst
from evaluators.response_evaluator import ResponseEvaluator

class DeepSeekCryptanalysisExperiment:
    def __init__(self, api_key: str):
        self.api_key = api_key
        self.config = ExperimentConfig()
        self.setup_components()
        self.results = []
        self.metrics = {}
        self.platform = 'deepseek'
        self.condition = 'algorithm_informed'
        self.experiment_timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        self.summary_dir = results_dir(self.platform, self.condition, 'experiment_summary')
        self.raw_dir = results_dir(self.platform, self.condition, 'raw_results')
        self.platform_out_dir = results_dir(self.platform, self.condition)

    def setup_components(self):
        """Initialize all experiment components"""
        self.classical_ciphers = ClassicalCiphers()
        self.symmetric_crypto = ModernSymmetricCrypto()
        self.asymmetric_crypto = AsymmetricCrypto()
        self.deepseek_analyst = DeepSeekCryptanalyst(self.api_key)
        self.evaluator = ResponseEvaluator()
        self.performance_charts = PerformanceCharts()
        self.table_generator = TableGenerator

    def generate_test_cases(self, max_per_algorithm: int | None = None) -> List[Dict]:
        """Generate test cases for the experiment."""
        test_cases = []

        # Classical cipher test cases - 180 tests
        print("Generating classical cipher test cases...")
        classical_cases = self.classical_ciphers.generate_test_cases(max_per_algorithm=max_per_algorithm)
        test_cases.extend(classical_cases)

        # Modern symmetric and hash test cases - 420 tests
        print("Generating modern symmetric and hash test cases...")
        symmetric_hash_cases = self.symmetric_crypto.generate_test_cases(max_per_algorithm=max_per_algorithm)
        test_cases.extend(symmetric_hash_cases)

        # Asymmetric test cases - 300 tests
        print("Generating asymmetric test cases...")
        asymmetric_cases = self.asymmetric_crypto.generate_test_cases(max_per_algorithm=max_per_algorithm)
        test_cases.extend(asymmetric_cases)

        print(f"Generated {len(test_cases)} total test cases")
        
        # Verify counts by category
        category_counts = {}
        algorithm_counts = {}
        
        for test_case in test_cases:
            category = test_case['category']
            algorithm = test_case['algorithm']
            
            category_counts[category] = category_counts.get(category, 0) + 1
            algorithm_counts[algorithm] = algorithm_counts.get(algorithm, 0) + 1
        
        print(f"Category distribution:")
        for category, count in category_counts.items():
            print(f"  {category}: {count} tests")
            
        print(f"Algorithm distribution:")
        for algorithm, count in algorithm_counts.items():
            print(f"  {algorithm}: {count} tests")
        
        return test_cases

    def _select_sample_cases(self, test_cases: List[Dict], max_tests: int) -> List[Dict]:
        """Select a small but diverse sample.

        Strategy: take first occurrence of each algorithm (up to max_tests),
        then fill remaining slots in original order.
        """
        if not test_cases:
            return []
        if max_tests <= 0:
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

    async def run_experiment(self, max_tests: int | None = None):
        """Run the complete cryptanalysis experiment"""
        print("Starting DeepSeek Cryptanalysis Experiment")
        print("=" * 60)
        print(f"Test Configuration:")
        print(f"  Classical Ciphers: {self.config.classical_cipher_count} tests")
        print(f"  Modern Symmetric: {self.config.modern_symmetric_count} tests")
        print(f"  Asymmetric: {self.config.asymmetric_count} tests")
        print(f"  Hash Functions: {self.config.hash_count} tests")
        print(f"  TOTAL: {self.config.total_tests} tests")
        print("=" * 60)

        # Generate test cases
        test_cases = self.generate_test_cases(max_per_algorithm=(1 if max_tests is not None else None))

        if max_tests is not None:
            test_cases = self._select_sample_cases(test_cases, int(max_tests))
            print(f"\nSample run enabled: {len(test_cases)} test cases selected (max_tests={max_tests})")

        # Run DeepSeek analysis
        print(f"Analyzing {len(test_cases)} test cases with DeepSeek...")
        print(f"  Batch size: {self.config.batch_size}")
        print(f"  Concurrent requests: {self.config.concurrent_requests}")
        print(f"  Batch delay: {self.config.batch_delay}s")

        start_time = datetime.now()
        successful_analyses = 0
        failed_analyses = 0

        async with self.deepseek_analyst as analyst:
            # Run in batches to manage API limits
            batch_size = self.config.batch_size
            total_batches = (len(test_cases) + batch_size - 1) // batch_size

            for batch_num in range(total_batches):
                start_idx = batch_num * batch_size
                end_idx = min(start_idx + batch_size, len(test_cases))
                batch = test_cases[start_idx:end_idx]

                print(f"\nProcessing batch {batch_num + 1}/{total_batches} (cases {start_idx + 1}-{end_idx})")

                # Analyze batch
                batch_results = await analyst.batch_analyze(batch, concurrent_requests=self.config.concurrent_requests)

                # Evaluate results
                batch_success = 0
                batch_failed = 0
                
                for i, (test_case, deepseek_response) in enumerate(zip(batch, batch_results)):
                    evaluation = self.evaluator.evaluate_cryptanalysis(deepseek_response, test_case)

                    self.results.append({
                        'test_case': test_case,
                        'deepseek_response': {
                            'success': deepseek_response.success,
                            'response_time': 0,  # Set to 0 as per requirement
                            'error': deepseek_response.error,
                            'parsed_data': deepseek_response.parsed_data
                        },
                        'evaluation': evaluation
                    })

                    if deepseek_response.success:
                        batch_success += 1
                        successful_analyses += 1
                    else:
                        batch_failed += 1
                        failed_analyses += 1

                print(f"  Successful: {batch_success}/{len(batch)}")
                if batch_failed > 0:
                    print(f"  Failed: {batch_failed}/{len(batch)}")

                # Save progress after each batch
                self._save_progress(batch_num + 1)

                # Rate limiting between batches
                if batch_num < total_batches - 1:
                    print(f"Waiting {self.config.batch_delay} seconds before next batch...")
                    await asyncio.sleep(self.config.batch_delay)

        # Calculate experiment duration
        end_time = datetime.now()
        duration = end_time - start_time

        # Calculate overall metrics
        self._calculate_metrics()

        # Generate reports and visualizations
        self._generate_reports()

        print("\n" + "=" * 60)
        print("EXPERIMENT COMPLETED SUCCESSFULLY!")
        print("=" * 60)
        print(f"Total tests: {len(self.results)}")
        print(f"Successful analyses: {successful_analyses}")
        print(f"Failed analyses: {failed_analyses}")
        print(f"Success rate: {(successful_analyses/len(self.results))*100:.1f}%")
        print(f"Overall score: {self.metrics['overall_score']:.3f}")

        return self.results, self.metrics

    def _save_progress(self, batch_num: int):
        """Save intermediate progress (lightweight; avoids duplicating raw results each batch)."""
        progress_data = {
            "batch": batch_num,
            "timestamp": datetime.now().isoformat(),
            "results_so_far": len(self.results),
        }

        progress_file = str(self.summary_dir / f"experiment_progress_batch_{batch_num}_{self.experiment_timestamp}.json")
        with open(progress_file, "w", encoding="utf-8") as f:
            json.dump(progress_data, f, indent=2, ensure_ascii=False)

        print(f"Progress saved: {progress_file}")

    def _calculate_metrics(self):
        """Calculate comprehensive experiment metrics"""
        if not self.results:
            self.metrics = {'error': 'No results to analyze'}
            return

        # Basic statistics
        total_tests = len(self.results)
        successful_responses = sum(1 for r in self.results if r['deepseek_response']['success'])

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
            
            # Initialize category tracking
            if category not in categories:
                categories[category] = {'scores': [], 'count': 0}
            if algorithm not in algorithms:
                algorithms[algorithm] = {'scores': [], 'count': 0}
            if difficulty not in difficulties:
                difficulties[difficulty] = {'scores': [], 'count': 0}

            # Add scores
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

        # Overall metrics
        overall_score = sum(r['evaluation']['overall_score'] for r in self.results) / total_tests if total_tests > 0 else 0

        self.metrics = {
            'timestamp': datetime.now().isoformat(),
            'total_tests': total_tests,
            'successful_responses': successful_responses,
            'success_rate': successful_responses / total_tests if total_tests > 0 else 0,
            'overall_score': overall_score,
            'category_metrics': category_metrics,
            'algorithm_metrics': algorithm_metrics,
            'difficulty_metrics': difficulty_metrics
        }

    def _generate_reports(self):
        """Generate comprehensive reports and visualizations"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Save raw results
        results_file = str(self.raw_dir / f"{self.platform}_{self.condition}_raw_results_{timestamp}.json")
        with open(results_file, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'experiment': 'DeepSeek Cryptanalysis',
                    'timestamp': timestamp,
                    'test_cases_count': len(self.results),
                    'configuration': {
                        'classical_ciphers': self.config.classical_cipher_count,
                        'modern_symmetric': self.config.modern_symmetric_count,
                        'asymmetric': self.config.asymmetric_count,
                        'hash_functions': self.config.hash_count,
                        'total_tests': self.config.total_tests
                    }
                },
                'metrics': self.metrics,
                'results': self.results
            }, f, indent=2, ensure_ascii=False)

        # Generate CSV for analysis
        self._generate_csv_report(timestamp)

        # Create visualizations
        print("\nGenerating comprehensive visualizations...")
        try:
            self.performance_charts.create_comprehensive_dashboard(self.results, self.metrics, timestamp, output_dir=self.platform_out_dir, file_prefix="")
            print("Performance charts generated successfully!")
            
            # Generate comprehensive table
            print("\nGenerating comprehensive table...")
            table_gen = TableGenerator(platform=self.platform)
            table_gen.run(results_file=results_file)
            print("Comprehensive table generated successfully!")
        except Exception as e:
            print(f"Error generating visualizations: {e}")

        # Print summary
        self._print_experiment_summary()

        print(f"\nALL OUTPUT FILES:")
        print(f"  Raw results: {results_file}")
        print(f"  CSV report: {self.condition}_experiment_summary_{timestamp}.csv (in {self.platform_out_dir})")
        print(f"  Performance charts: 5 interactive HTML files")
        print(f"  Summary table: {self.condition}_summary_table_{timestamp}.html (in {self.platform_out_dir})")

    def _generate_csv_report(self, timestamp: str):
        """Generate CSV report for detailed analysis"""
        csv_data = []

        for result in self.results:
            test_case = result['test_case']
            evaluation = result['evaluation']
            response = result['deepseek_response']

            row = {
                'test_id': test_case['test_id'],
                'algorithm': test_case['algorithm'],
                'category': test_case['category'],
                'difficulty': test_case['difficulty'],
                'response_success': response['success'],
                'overall_score': evaluation['overall_score'],
                'vulnerability_score': evaluation['vulnerability_detection_score'],
                'decryption_score': evaluation['decryption_success_score'],
                'reasoning_score': evaluation['reasoning_quality_score'],
                'confidence': evaluation.get('confidence_score', 0),
                'suggested_attacks_count': len(evaluation.get('suggested_attacks', [])),
                'vulnerabilities_count': len(evaluation.get('vulnerabilities_found', []))
            }
            csv_data.append(row)

        df = pd.DataFrame(csv_data)
        csv_file = str(results_dir(self.platform, self.condition) / (f"{self.condition}_experiment_summary_{timestamp}.csv"))
        df.to_csv(csv_file, index=False)
        print(f"CSV report saved: {csv_file}")

    def _print_experiment_summary(self):
        """Print comprehensive experiment summary"""
        metrics = self.metrics

        print("\n" + "=" * 60)
        print("DEEPSEEK CRYPTANALYSIS EXPERIMENT SUMMARY")
        print("=" * 60)

        print(f"Overall Statistics:")
        print(f"  Total Tests: {metrics['total_tests']}")
        print(f"  Successful Responses: {metrics['successful_responses']} ({metrics['success_rate']:.1%})")
        print(f"  Overall Score: {metrics['overall_score']:.3f}")

        print(f"\nPerformance by Category:")
        for category, data in metrics['category_metrics'].items():
            print(f"  {category:20} Score: {data['average_score']:.3f} ({data['test_count']} tests)")

        print(f"\nPerformance by Algorithm:")
        for algorithm, data in metrics['algorithm_metrics'].items():
            print(f"  {algorithm:20} Score: {data['average_score']:.3f} ({data['test_count']} tests)")

        print(f"\nPerformance by Difficulty:")
        for difficulty, data in metrics['difficulty_metrics'].items():
            print(f"  {difficulty:20} Score: {data['average_score']:.3f} ({data['test_count']} tests)")

async def main():
    parser = argparse.ArgumentParser(description='DeepSeek algorithm_informed cryptanalysis experiment')
    parser.add_argument('--max-tests', type=int, default=None, help='Run only a small sample (e.g., 15)')
    args = parser.parse_args()

    """Main execution function"""
    print("DEEPSEEK CRYPTANALYSIS EXPERIMENT")
    print("===========================================")
    
    # Load DeepSeek API key
    api_key = os.getenv('DEEPSEEK_API_KEY')

    if not api_key:
        print("Error: DEEPSEEK_API_KEY environment variable not set")
        print("\nPlease set your DeepSeek API key:")
        print("  For Linux/Mac:")
        print("    export DEEPSEEK_API_KEY='your_api_key_here'")
        print("  For Windows:")
        print("    set DEEPSEEK_API_KEY=your_api_key_here")
        print("\nGet your API key from: https://platform.deepseek.com/api_keys")
        sys.exit(1)
        
    # Create analyst to validate API key
    analyst = DeepSeekCryptanalyst(api_key)
    if not analyst.validate_api_key():
        print("API key validation failed")
        sys.exit(1)

    print("DeepSeek API key validated successfully")

    # Verify API key format
    if len(api_key) < 20:
        print("Error: API key appears to be invalid (too short)")
        print("  Please check your DEEPSEEK_API_KEY environment variable")
        sys.exit(1)

    print("DeepSeek API key loaded successfully")
    print("Starting experiment...")

    try:
        # Run experiment
        experiment = DeepSeekCryptanalysisExperiment(api_key)
        results, metrics = await experiment.run_experiment(max_tests=args.max_tests)

        print(f"\nExperiment completed successfully!")
        print(f"Check 'data/results/deepseek/' for output files")
        
    except Exception as e:
        print(f"Experiment failed with error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # Check if running in appropriate environment
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExperiment interrupted by user")
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        sys.exit(1)





# REFRESH_2026
