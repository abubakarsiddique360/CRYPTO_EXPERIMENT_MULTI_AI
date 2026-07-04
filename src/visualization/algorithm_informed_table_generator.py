#!/usr/bin/env python3
"""Algorithm Informed Summary Table Generator.

Format: MUST match the user's screenshot for the algorithm_informed experiment.
- Single table
- Main algorithm rows
- "CATEGORY SUMMARY" block embedded in the same table
- "OVERALL SUMMARY" block embedded in the same table (two rows: labels + values)

Reads latest raw results from:
  data/results/{platform}/algorithm_informed/raw_results/

Writes artifacts under:
  data/results/{platform}/{condition}/
"""

from __future__ import annotations

import sys
import html
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# --- sys.path bootstrap (auto-added) ---
PROJECT_ROOT = Path(__file__).resolve()
while PROJECT_ROOT != PROJECT_ROOT.parent and not (PROJECT_ROOT / 'src').exists():
    PROJECT_ROOT = PROJECT_ROOT.parent

SRC_DIR = PROJECT_ROOT / 'src'
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
# --- end sys.path bootstrap ---

from typing import Any, Dict, List, Tuple

import pandas as pd

from config.output_paths import results_dir


@dataclass
class _LoadedData:
    results_file: Path
    timestamp: str
    results: List[Dict[str, Any]]
    metrics: Dict[str, Any]
    metadata: Dict[str, Any]


def _extract_timestamp_from_filename(results_file: Path, platform: str, condition: str) -> str:
    prefix = f"{platform}_{condition}_raw_results_"
    name = results_file.name
    if name.startswith(prefix) and name.endswith('.json'):
        return name[len(prefix) : -5]
    return datetime.now().strftime('%Y%m%d_%H%M%S')


def _safe_float(value: Any) -> float:
    try:
        if value is None:
            return 0.0
        return float(value)
    except Exception:
        return 0.0


def _fmt3(x: Any) -> str:
    return f"{_safe_float(x):.3f}"


def _display_category(cat: Any) -> str:
    s = str(cat or 'unknown').strip().lower()
    mapping = {
        'hash': 'Hash',
        'asymmetric': 'Asymmetric',
        'classical': 'Classical',
        'modern_symmetric': 'Modern_symmetric',
    }
    return mapping.get(s, str(cat or 'unknown'))


def _css() -> str:
    # Keep styling extremely close to the screenshot look.
    return """
<style>
  body { font-family: Arial, Helvetica, sans-serif; margin: 12px; }
  .report-title { font-size: 18px; font-weight: 700; margin: 6px 0 10px; }
  table.report { border-collapse: collapse; width: 100%; max-width: 1400px; }
  table.report th, table.report td { border: 1px solid #cfcfcf; padding: 6px 8px; font-size: 13px; }
  table.report th { background: #f0f0f0; text-align: center; font-weight: 700; }
  table.report td { text-align: center; }
  table.report td.left { text-align: left; }

  tr.category-header td { background: #ffffff; font-weight: 700; text-align: left; }
  tr.category-row td { background: #eef7e8; font-weight: 700; }

  tr.overall-header td { background: #eef7e8; font-weight: 700; text-align: left; }
  tr.overall-labels td { background: #e8f4fb; font-weight: 700; }
  tr.overall-values td { background: #e8f4fb; }
</style>
"""


class AlgorithmInformedTableGenerator:
    def __init__(self, platform: str, condition: str = 'algorithm_informed'):
        self.platform = (platform or 'unknown').lower()
        self.condition = condition
        self.raw_dir = results_dir(self.platform, self.condition, 'raw_results')
        self.output_dir = results_dir(self.platform, self.condition)

    def _find_latest_raw_results_file(self) -> Path:
        pattern = f"{self.platform}_{self.condition}_raw_results_*.json"
        files = sorted(self.raw_dir.glob(pattern))
        if not files:
            raise FileNotFoundError(f"No raw results files found: {self.raw_dir} / {pattern}")
        return files[-1]

    def load_experiment_data(self, results_file: str | Path | None = None) -> _LoadedData:
        rf = Path(results_file) if results_file else self._find_latest_raw_results_file()
        data = json.loads(rf.read_text(encoding='utf-8'))
        results = data.get('results', [])
        if not results:
            raise ValueError('No results found in raw results JSON')

        ts = _extract_timestamp_from_filename(rf, self.platform, self.condition)
        return _LoadedData(
            results_file=rf,
            timestamp=ts,
            results=results,
            metrics=data.get('metrics', {}),
            metadata=data.get('metadata', {}),
        )

    def _rows(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for r in results:
            test_case = r.get('test_case', {})
            evaluation = r.get('evaluation', {})

            out.append(
                {
                    'Algorithm': test_case.get('algorithm', 'unknown'),
                    'Category': _display_category(test_case.get('category') or evaluation.get('category') or 'unknown'),
                    'Overall': _safe_float(evaluation.get('overall_score', 0.0)),
                    'Vuln': _safe_float(evaluation.get('vulnerability_detection_score', evaluation.get('vulnerability_score', 0.0))),
                    'Decrypt': _safe_float(evaluation.get('decryption_success_score', evaluation.get('decryption_score', 0.0))),
                    'Reason': _safe_float(evaluation.get('reasoning_quality_score', evaluation.get('reasoning_score', 0.0))),
                    'Success': bool(evaluation.get('response_success', True)),
                }
            )
        return out

    def _build_tables(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.DataFrame, Dict[str, Any]]:
        algo = (
            df.groupby(['Algorithm', 'Category'], dropna=False)
            .agg(
                Avg_Score=('Overall', 'mean'),
                Score_Std=('Overall', 'std'),
                Test_Count=('Overall', 'count'),
                Vuln_Score=('Vuln', 'mean'),
                Decrypt_Score=('Decrypt', 'mean'),
                Reason_Score=('Reason', 'mean'),
            )
            .reset_index()
        )
        algo['Score_Std'] = algo['Score_Std'].fillna(0.0)
        algo = algo.sort_values('Avg_Score', ascending=False)

        cat = (
            df.groupby(['Category'], dropna=False)
            .agg(
                Avg_Score=('Overall', 'mean'),
                Score_Std=('Overall', 'std'),
                Test_Count=('Overall', 'count'),
                Vuln_Score=('Vuln', 'mean'),
                Decrypt_Score=('Decrypt', 'mean'),
                Reason_Score=('Reason', 'mean'),
            )
            .reset_index()
        )
        cat['Score_Std'] = cat['Score_Std'].fillna(0.0)

        total_tests = int(df.shape[0])
        successful = int(df['Success'].sum())

        overall = {
            'Total Tests': total_tests,
            'Successful Analyses': successful,
            'Overall Score': float(df['Overall'].mean() if total_tests else 0.0),
            'Score Std Avg': float(df['Overall'].std()) if total_tests > 1 else None,
            'Success Rate': float((successful / total_tests) if total_tests else 0.0),
            'Vuln Score Avg': float(df['Vuln'].mean() if total_tests else 0.0),
            'Decrypt Score Avg': float(df['Decrypt'].mean() if total_tests else 0.0),
            'Reason Score Avg': float(df['Reason'].mean() if total_tests else 0.0),
        }

        return algo, cat, overall

    def _render_html(self, algo: pd.DataFrame, cat: pd.DataFrame, overall: Dict[str, Any], timestamp: str) -> str:
        cols = [
            ('Algorithm', 'left'),
            ('Category', ''),
            ('Avg Score', ''),
            ('Score Std', ''),
            ('Test Count', ''),
            ('Vuln Score', ''),
            ('Decrypt Score', ''),
            ('Reason Score', ''),
        ]
        colspan = len(cols)

        def th_row() -> str:
            return '<tr>' + ''.join(f'<th>{html.escape(h)}</th>' for h, _ in cols) + '</tr>'

        def algo_rows() -> str:
            out = []
            for _, r in algo.iterrows():
                out.append(
                    '<tr>'
                    f'<td class="left">{html.escape(str(r["Algorithm"]))}</td>'
                    f'<td>{html.escape(str(r["Category"]))}</td>'
                    f'<td>{_fmt3(r["Avg_Score"])}</td>'
                    f'<td>{(_fmt3(r["Score_Std"]) if int(r["Test_Count"]) > 1 else "N/A")}</td>'
                    f'<td>{int(r["Test_Count"])}</td>'
                    f'<td>{_fmt3(r["Vuln_Score"])}</td>'
                    f'<td>{_fmt3(r["Decrypt_Score"])}</td>'
                    f'<td>{_fmt3(r["Reason_Score"])}</td>'
                    '</tr>'
                )
            return '\n'.join(out)

        def category_rows() -> str:
            out = []
            for _, r in cat.iterrows():
                out.append(
                    '<tr class="category-row">'
                    '<td></td>'
                    f'<td class="left">{html.escape(str(r["Category"]))}</td>'
                    f'<td>{_fmt3(r["Avg_Score"])}</td>'
                    f'<td>{(_fmt3(r["Score_Std"]) if int(r["Test_Count"]) > 1 else "N/A")}</td>'
                    f'<td>{int(r["Test_Count"])}</td>'
                    f'<td>{_fmt3(r["Vuln_Score"])}</td>'
                    f'<td>{_fmt3(r["Decrypt_Score"])}</td>'
                    f'<td>{_fmt3(r["Reason_Score"])}</td>'
                    '</tr>'
                )
            return '\n'.join(out)

        overall_labels = [
            'Total Tests',
            'Successful Analyses',
            'Overall Score',
            'Score Std Avg',
            'Success Rate',
            'Vuln Score Avg',
            'Decrypt Score Avg',
            'Reason Score Avg',
        ]

        def overall_values() -> List[str]:
            vals = []
            for k in overall_labels:
                v = overall.get(k, 0.0)
                if k in ('Total Tests', 'Successful Analyses'):
                    vals.append(str(int(v)))
                elif k == 'Success Rate':
                    vals.append(f"{_safe_float(v) * 100:.1f}%")
                else:
                    vals.append('N/A' if v is None else _fmt3(v))
            return vals

        ov_vals = overall_values()

        return (
            '<!doctype html><html><head><meta charset="utf-8">'
            + _css()
            + '</head><body>'
            + f'<div class="report-title">Algorithm Informed Summary Table ({html.escape(self.platform)})</div>'
            + '<table class="report">'
            + th_row()
            + algo_rows()
            + f'<tr class="category-header"><td class="left" colspan="{colspan}">CATEGORY SUMMARY</td></tr>'
            + category_rows()
            + f'<tr class="overall-header"><td class="left" colspan="{colspan}">OVERALL SUMMARY</td></tr>'
            + '<tr class="overall-labels">' + ''.join(f'<td>{html.escape(h)}</td>' for h in overall_labels) + '</tr>'
            + '<tr class="overall-values">' + ''.join(f'<td>{html.escape(v)}</td>' for v in ov_vals) + '</tr>'
            + '</table>'
            + '</body></html>'
        )

    def create_summary_table(self, results: List[Dict[str, Any]], timestamp: str) -> str:
        df = pd.DataFrame(self._rows(results))
        algo, cat, overall = self._build_tables(df)

        html_text = self._render_html(algo, cat, overall, timestamp)
        html_file = self.output_dir / f"{self.condition}_summary_table_{timestamp}.html"
        html_file.write_text(html_text, encoding='utf-8')

        print('SUCCESS: Algorithm informed summary table generated!')
        print(f'Output directory: {self.output_dir}')
        print(f'HTML: {html_file.name}')
        return str(html_file)

    def run(self, results_file: str | Path | None = None) -> None:
        print('=' * 60)
        print('ALGORITHM INFORMED SUMMARY TABLE GENERATOR')
        print('=' * 60)

        data = self.load_experiment_data(results_file)
        print(f'Loaded {len(data.results)} test cases from: {data.results_file}')
        self.create_summary_table(data.results, data.timestamp)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description='Generate algorithm-informed summary table')
    parser.add_argument('--platform', default='deepseek')
    parser.add_argument('--results-file', help='Optional explicit raw results JSON file path')

    args = parser.parse_args()
    gen = AlgorithmInformedTableGenerator(platform=args.platform)
    gen.run(args.results_file)




# Backward-compat: existing runners import `TableGenerator`
TableGenerator = AlgorithmInformedTableGenerator

if __name__ == '__main__':
    main()
