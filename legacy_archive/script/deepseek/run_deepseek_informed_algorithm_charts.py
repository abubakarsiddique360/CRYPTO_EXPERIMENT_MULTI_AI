#!/usr/bin/env python3
"""DeepSeek Algorithm Informed Charts Runner.

Reads the latest raw results from:
  data/results/deepseek/algorithm_informed/raw_results/

Writes chart files flat under:
  data/results/deepseek/

Example:
  data/results/deepseek/algorithm_informed_performance_by_algorithm_{timestamp}.html
"""

import argparse
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve()
while PROJECT_ROOT != PROJECT_ROOT.parent and not (PROJECT_ROOT / 'src').exists():
    PROJECT_ROOT = PROJECT_ROOT.parent

SRC_DIR = PROJECT_ROOT / 'src'
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from config.output_paths import results_dir
from visualization.algorithm_informed_performance_charts import PerformanceCharts


def _find_latest_raw_results(platform: str, condition: str) -> Path:
    raw_dir = results_dir(platform, condition, 'raw_results')
    pattern = f"{platform}_{condition}_raw_results_*.json"
    files = sorted(raw_dir.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No raw results files found: {raw_dir} / {pattern}")
    return files[-1]


def main() -> None:
    parser = argparse.ArgumentParser(description='Generate DeepSeek algorithm-informed charts')
    parser.add_argument('--results-file', type=str, help='Optional explicit raw results JSON file')
    args = parser.parse_args()

    platform = 'deepseek'
    condition = 'algorithm_informed'

    results_file = Path(args.results_file) if args.results_file else _find_latest_raw_results(platform, condition)
    data = json.loads(results_file.read_text(encoding='utf-8'))
    results = data.get('results', [])
    metrics = data.get('metrics', {})
    if not results:
        raise ValueError(f'No results found in {results_file}')

    timestamp = results_file.name.replace(f"{platform}_{condition}_raw_results_", '').replace('.json', '')

    out_dir = results_dir(platform, condition)
    charts = PerformanceCharts()
    charts.create_comprehensive_dashboard(results, metrics, timestamp, output_dir=out_dir, file_prefix='')

    print('\nDone.')
    print(f'Input: {results_file}')
    print(f'Output dir: {out_dir}')


if __name__ == '__main__':
    main()
