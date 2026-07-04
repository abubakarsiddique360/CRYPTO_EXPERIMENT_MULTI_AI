#!/usr/bin/env python3
"""GEMINI Algorithm Hidden Table Runner

Reads the latest raw results from:
  data/results/gemini/algorithm_hidden/raw_results/

Writes tables to:
  data/results/gemini/algorithm_hidden/tables/
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

from visualization.algorithm_hidden_table_generator import AlgorithmHiddenTableGenerator


def main():
    parser = argparse.ArgumentParser(description="Generate algorithm-hidden summary table")
    parser.add_argument(
        "--results-file",
        type=str,
        help="Optional explicit raw results JSON file path",
    )
    args = parser.parse_args()

    generator = AlgorithmHiddenTableGenerator(platform="gemini")
    generator.run(results_file=args.results_file)


if __name__ == "__main__":
    main()
