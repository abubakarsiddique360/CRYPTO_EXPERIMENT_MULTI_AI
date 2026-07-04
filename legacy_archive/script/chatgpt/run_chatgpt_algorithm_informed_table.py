#!/usr/bin/env python3
"""CHATGPT Algorithm Informed Table Runner

Reads the latest raw results from:
  data/results/chatgpt/algorithm_informed/raw_results/

Writes tables to:
  data/results/chatgpt/algorithm_informed/tables/
"""

import argparse
import sys
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

from visualization.table_generator import TableGenerator


def main():
    parser = argparse.ArgumentParser(description='Generate algorithm-informed comprehensive table')
    parser.add_argument('--results-file', type=str, help='Optional explicit raw results JSON file path')
    args = parser.parse_args()

    generator = TableGenerator(platform='chatgpt', condition='algorithm_informed')
    generator.run(results_file=args.results_file)


if __name__ == '__main__':
    main()
