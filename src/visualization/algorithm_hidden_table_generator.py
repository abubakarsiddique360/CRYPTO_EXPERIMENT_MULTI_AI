#!/usr/bin/env python3
"""Algorithm Hidden Summary Table Generator.

Format: MUST match the user's screenshot for the algorithm_hidden experiment.
- Single table
- Main algorithm rows
- "CATEGORY SUMMARY" block embedded in the same table (with its own header row)
- "OVERALL EXPERIMENT SUMMARY" block embedded in the same table (metric/value rows)

Reads latest raw results from:
  data/results/{platform}/algorithm_hidden/raw_results/

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
    s = str(cat or 'unknown').strip()
    # Hidden tables use spaced Title Case in the screenshot
    s = s.replace('_', ' ')
    return ' '.join(w.capitalize() for w in s.split()) or 'Unknown'


def _css() -> str:
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
  tr.category-labels td { background: #eef7e8; font-weight: 700; }
  tr.category-row td { background: #eef7e8; font-weight: 700; }

  tr.overall-header td { background: #e8f4fb; font-weight: 700; text-align: left; }
  tr.overall-row td { background: #e8f4fb; }
</style>
"""


class AlgorithmHiddenTableGenerator:
    def __init__(self, platform: str, condition: str = 'algorithm_hidden'):
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
            evaluation = r.get('evaluation', {})
            test_case = r.get('test_case', {})
            original_info = r.get('original_info', {})

            algo = (
                (original_info.get('algorithm') if isinstance(original_info, dict) else None)
                or (test_case.get('algorithm') if isinstance(test_case, dict) else None)
                or evaluation.get('algorithm', 'unknown')
            )
            cat = (
                (original_info.get('category') if isinstance(original_info, dict) else None)
                or (test_case.get('category') if isinstance(test_case, dict) else None)
                or evaluation.get('category')
                or 'unknown'
            )

            out.append(
                {
                    'Algorithm': algo,
                    'Category': _display_category(cat),
                    'Overall': _safe_float(evaluation.get('overall_score', 0.0)),
                    'ID': _safe_float(evaluation.get('identified_algorithm_score', 0.0)),
                    'CatScore': _safe_float(evaluation.get('identified_category_score', 0.0)),
                    'Exact': bool(evaluation.get('exact_match', False)),
                    'CategoryMatch': bool(evaluation.get('category_match', False)),
                    'Vuln': _safe_float(evaluation.get('vulnerability_score', 0.0)),
                    'Decrypt': _safe_float(evaluation.get('decryption_score', 0.0)),
                    'Reason': _safe_float(evaluation.get('reasoning_score', 0.0)),
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
                ID_Score=('ID', 'mean'),
                Cat_Score=('CatScore', 'mean'),
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
                ID_Score=('ID', 'mean'),
                Cat_Score=('CatScore', 'mean'),
                Exact_Match_Rate=('Exact', 'mean'),
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
            'Score Std Dev': (float(df['Overall'].std()) if total_tests > 1 else None),
            'ID Score Avg': float(df['ID'].mean() if total_tests else 0.0),
            'Category Score Avg': float(df['CatScore'].mean() if total_tests else 0.0),
            'Vuln Score Avg': float(df['Vuln'].mean() if total_tests else 0.0),
            'Decrypt Score Avg': float(df['Decrypt'].mean() if total_tests else 0.0),
            'Reason Score Avg': float(df['Reason'].mean() if total_tests else 0.0),
            'Exact Match Rate': float(df['Exact'].mean() if total_tests else 0.0),
            'Category Match Rate': float(df['CategoryMatch'].mean() if total_tests else 0.0),
        }

        return algo, cat, overall

    def _render_html(self, algo: pd.DataFrame, cat: pd.DataFrame, overall: Dict[str, Any], timestamp: str) -> str:
        cols = [
            ('Algorithm', 'left'),
            ('Category', ''),
            ('Avg Score', ''),
            ('Score Std', ''),
            ('Test Count', ''),
            ('ID Score', ''),
            ('Cat Score', ''),
            ('Vuln Score', ''),
            ('Decrypt Score', ''),
            ('Reason Score', ''),
        ]
        ncols = len(cols)

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
                    f'<td>{_fmt3(r["ID_Score"])}</td>'
                    f'<td>{_fmt3(r["Cat_Score"])}</td>'
                    f'<td>{_fmt3(r["Vuln_Score"])}</td>'
                    f'<td>{_fmt3(r["Decrypt_Score"])}</td>'
                    f'<td>{_fmt3(r["Reason_Score"])}</td>'
                    '</tr>'
                )
            return '\n'.join(out)

        # Category summary: header row + data rows.
        category_labels = ['Category', 'Avg Score', 'Score Std', 'Test Count', 'ID Score', 'Cat Score', 'Exact Match Rate']

        def cat_header_row() -> str:
            tds = []
            for i in range(ncols):
                if i < len(category_labels):
                    tds.append(f'<td>{html.escape(category_labels[i])}</td>')
                else:
                    tds.append('<td></td>')
            return '<tr class="category-labels">' + ''.join(tds) + '</tr>'

        def category_rows() -> str:
            out = []
            for _, r in cat.iterrows():
                exact_pct = f"{_safe_float(r.get('Exact_Match_Rate', 0.0)) * 100:.1f}%"
                row_vals = [
                    str(r['Category']),
                    _fmt3(r['Avg_Score']),
                    (_fmt3(r['Score_Std']) if int(r['Test_Count']) > 1 else 'N/A'),
                    str(int(r['Test_Count'])),
                    _fmt3(r['ID_Score']),
                    _fmt3(r.get('Cat_Score', 0.0)),
                    exact_pct,
                ]
                tds = []
                for i in range(ncols):
                    if i < len(row_vals):
                        cls = ' class="left"' if i == 0 else ''
                        tds.append(f'<td{cls}>{html.escape(row_vals[i])}</td>')
                    else:
                        tds.append('<td></td>')
                out.append('<tr class="category-row">' + ''.join(tds) + '</tr>')
            return '\n'.join(out)

        overall_metrics = [
            ('Total Tests', lambda v: str(int(v))),
            ('Successful Analyses', lambda v: str(int(v))),
            ('Overall Score', lambda v: _fmt3(v)),
            ('Score Std Dev', lambda v: ('N/A' if v is None else _fmt3(v))),
            ('ID Score Avg', lambda v: _fmt3(v)),
            ('Category Score Avg', lambda v: _fmt3(v)),
            ('Vuln Score Avg', lambda v: _fmt3(v)),
            ('Decrypt Score Avg', lambda v: _fmt3(v)),
            ('Reason Score Avg', lambda v: _fmt3(v)),
            ('Exact Match Rate', lambda v: f"{_safe_float(v) * 100:.1f}%"),
            ('Category Match Rate', lambda v: f"{_safe_float(v) * 100:.1f}%"),
        ]

        overall_rows = []
        for key, fmt in overall_metrics:
            val = overall.get(key, 0.0)
            sval = fmt(val)
            tds = [
                f'<td class="left"><b>{html.escape(key)}</b></td>',
                f'<td>{html.escape(sval)}</td>',
            ] + ['<td></td>' for _ in range(ncols - 2)]
            overall_rows.append('<tr class="overall-row">' + ''.join(tds) + '</tr>')

        return (
            '<!doctype html><html><head><meta charset="utf-8">'
            + _css()
            + '</head><body>'
            + f'<div class="report-title">Algorithm Hidden Summary Table ({html.escape(self.platform)})</div>'
            + '<table class="report">'
            + th_row()
            + algo_rows()
            + f'<tr class="category-header"><td class="left" colspan="{ncols}">CATEGORY SUMMARY</td></tr>'
            + cat_header_row()
            + category_rows()
            + f'<tr class="overall-header"><td class="left" colspan="{ncols}">OVERALL EXPERIMENT SUMMARY</td></tr>'
            + '\n'.join(overall_rows)
            + '</table>'
            + '</body></html>'
        )

    def create_summary_table(self, results: List[Dict[str, Any]], timestamp: str) -> str:
        # Prefer recomputed CSV (fresh evaluator logic) when available,
        # so tables stay consistent with scoring changes.
        df = None
        base_ts = str(timestamp).split('_smoke')[0]
        candidates = sorted(self.output_dir.glob(f"*{base_ts}*recomputed*.csv"))

        if candidates:
            df_csv = pd.read_csv(candidates[-1])

            def _to_bool(v: Any) -> bool:
                return str(v).strip().lower() in {'1', 'true', 'yes', 'y', 't'}

            df = pd.DataFrame({
                'Algorithm': df_csv.get('algorithm', 'unknown'),
                'Category': [_display_category(c) for c in df_csv.get('category', 'unknown')],
                'Overall': df_csv.get('overall_score', 0.0),
                'ID': df_csv.get('identified_algorithm_score', 0.0),
                'CatScore': df_csv.get('identified_category_score', 0.0),
                'Exact': [_to_bool(x) for x in df_csv.get('exact_match', False)],
                'CategoryMatch': [_to_bool(x) for x in df_csv.get('category_match', False)],
                'Vuln': df_csv.get('vulnerability_score', 0.0),
                'Decrypt': df_csv.get('decryption_score', 0.0),
                'Reason': df_csv.get('reasoning_score', 0.0),
                'Success': [_to_bool(x) for x in df_csv.get('response_success', True)],
            })

        if df is None:
            df = pd.DataFrame(self._rows(results))

        algo, cat, overall = self._build_tables(df)

        html_text = self._render_html(algo, cat, overall, timestamp)
        html_file = self.output_dir / f"{self.condition}_summary_table_{timestamp}.html"
        html_file.write_text(html_text, encoding='utf-8')

        print('SUCCESS: Algorithm hidden summary table generated!')
        print(f'Output directory: {self.output_dir}')
        print(f'HTML: {html_file.name}')
        return str(html_file)

    def run(
self, results_file: str | Path | None = None) -> None:
        print('=' * 60)
        print('ALGORITHM HIDDEN SUMMARY TABLE GENERATOR')
        print('=' * 60)

        data = self.load_experiment_data(results_file)
        print(f'Loaded {len(data.results)} test cases from: {data.results_file}')
        self.create_summary_table(data.results, data.timestamp)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description='Generate algorithm-hidden summary table')
    parser.add_argument('--platform', default='deepseek')
    parser.add_argument('--results-file', help='Optional explicit raw results JSON file path')

    args = parser.parse_args()
    gen = AlgorithmHiddenTableGenerator(platform=args.platform)
    gen.run(args.results_file)


if __name__ == '__main__':
    main()

# REFRESH_2026
