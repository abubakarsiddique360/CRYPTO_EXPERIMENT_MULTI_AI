#!/usr/bin/env python3
"""DeepSeek Algorithm Informed Table Runner.

Reads latest raw results from:
  data/results/deepseek/algorithm_informed/raw_results/

Writes table files flat under:
  data/results/deepseek/

Example:
  data/results/deepseek/algorithm_informed_summary_table_{timestamp}.html
"""

import argparse
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

from visualization.algorithm_informed_table_generator import AlgorithmInformedTableGenerator


def main() -> None:
    parser = argparse.ArgumentParser(description='Generate DeepSeek algorithm-informed summary table')
    parser.add_argument('--results-file', type=str, help='Optional explicit raw results JSON file path')
    args = parser.parse_args()

    generator = AlgorithmInformedTableGenerator(platform='deepseek')
    generator.run(results_file=args.results_file)


if __name__ == '__main__':
    main()
