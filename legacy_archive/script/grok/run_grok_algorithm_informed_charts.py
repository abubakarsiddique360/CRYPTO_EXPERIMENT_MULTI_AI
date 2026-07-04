#!/usr/bin/env python3
"""GROK Algorithm Informed Charts Runner

Loads the latest raw results from:
  data/results/grok/algorithm_informed/raw_results/

Writes charts to:
  data/results/<platform>/
"""

import argparse
import json
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

from config.output_paths import results_dir
from visualization.performance_charts import PerformanceCharts


def _find_latest_raw_results_file(raw_dir: Path, platform: str, condition: str) -> Path:
    pattern = f"{platform}_{condition}_raw_results_*.json"
    files = sorted(raw_dir.glob(pattern))
    if not files:
        raise FileNotFoundError(f"No raw results files found: {raw_dir} / {pattern}")
    return files[-1]


def _load_raw_results(results_file: Path):
    data = json.loads(results_file.read_text(encoding="utf-8"))
    results = data.get("results", [])
    metrics = data.get("metrics", {})
    metadata = data.get("metadata", {})
    if not results:
        raise ValueError("No results found in raw results JSON")
    return results, metrics, metadata


def _extract_timestamp_from_filename(results_file: Path, platform: str, condition: str) -> str:
    prefix = f"{platform}_{condition}_raw_results_"
    name = results_file.name
    if name.startswith(prefix) and name.endswith(".json"):
        return name[len(prefix):-5]
    return "latest"


def generate_all_charts(platform: str, condition: str):
    raw_dir = results_dir(platform, condition, "raw_results")
    charts_dir = results_dir(platform, condition)
    file_prefix = ""
    results_file = _find_latest_raw_results_file(raw_dir, platform, condition)
    print(f"Loading raw results from: {results_file}")
    results, metrics, _metadata = _load_raw_results(results_file)

    timestamp = _extract_timestamp_from_filename(results_file, platform, condition)
    print(f"Using timestamp: {timestamp}")

    charts = PerformanceCharts()
    charts.create_comprehensive_dashboard(results, metrics, timestamp, output_dir=charts_dir, file_prefix=file_prefix)

    summary_file = charts_dir / f"{condition}_charts_summary_{timestamp}.txt"
    summary_file.write_text(
        "\n".join([
            f"{platform.upper()} CRYPTANALYSIS - CHARTS GENERATED",
            "=" * 50,
            "",
            f"Source data: {results_file.name}",
            f"Total tests: {len(results)}",
            f"Timestamp: {timestamp}",
            "",
            "Generated HTML files:",
            f"  1. algorithm_informed_confidence_vs_actual_{timestamp}.html",
            f"  2. algorithm_informed_time_series_analysis_{timestamp}.html",
            f"  3. algorithm_informed_component_score_breakdown_{timestamp}.html",
            f"  4. algorithm_informed_performance_by_category_{timestamp}.html",
            f"  5. algorithm_informed_performance_by_algorithm_{timestamp}.html",
            "",
        ]) + "\n",
        encoding="utf-8",
    )

    print(f"Charts written to: {charts_dir}")
    print(f"Summary saved to: {summary_file}")


def generate_specific_chart(platform: str, condition: str, chart_type: str):
    raw_dir = results_dir(platform, condition, "raw_results")
    charts_dir = results_dir(platform, condition)
    file_prefix = ""
    results_file = _find_latest_raw_results_file(raw_dir, platform, condition)
    results, _metrics, _metadata = _load_raw_results(results_file)
    timestamp = _extract_timestamp_from_filename(results_file, platform, condition)

    charts = PerformanceCharts()

    if chart_type == "time_series":
        charts.create_time_series_analysis(results, timestamp, output_dir=charts_dir, file_prefix=file_prefix)
        print(f"Generated: algorithm_informed_time_series_analysis_{timestamp}.html")
    elif chart_type == "confidence":
        charts.create_confidence_vs_actual_chart(results, timestamp, output_dir=charts_dir, file_prefix=file_prefix)
        print(f"Generated: algorithm_informed_confidence_vs_actual_{timestamp}.html")
    elif chart_type == "component":
        charts.create_component_score_breakdown(results, timestamp, output_dir=charts_dir, file_prefix=file_prefix)
        print(f"Generated: algorithm_informed_component_score_breakdown_{timestamp}.html")
    elif chart_type == "category":
        charts.create_performance_by_category(results, timestamp, output_dir=charts_dir, file_prefix=file_prefix)
        print(f"Generated: algorithm_informed_performance_by_category_{timestamp}.html")
    elif chart_type == "algorithm":
        charts.create_performance_by_algorithm(results, timestamp, output_dir=charts_dir, file_prefix=file_prefix)
        print(f"Generated: algorithm_informed_performance_by_algorithm_{timestamp}.html")
    else:
        raise ValueError("Unknown chart type. Use: time_series, confidence, component, category, algorithm")


def main():
    parser = argparse.ArgumentParser(description="Generate informed-performance charts")
    parser.add_argument("--chart", type=str, help="Generate a specific chart (time_series, confidence, component, category, algorithm)")
    args = parser.parse_args()

    platform = "grok"
    condition = "algorithm_informed"

    if args.chart:
        generate_specific_chart(platform, condition, args.chart)
    else:
        generate_all_charts(platform, condition)


if __name__ == "__main__":
    main()
