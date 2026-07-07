"""Algorithm Hidden Performance Charts - 3 charts for the algorithm-hidden experiment."""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import pandas as pd
import plotly.graph_objects as go


class AlgorithmHiddenPerformanceCharts:
    def __init__(self):
        self.color_scheme = {
            'Classical': '#FF6B6B',
            'Symmetric': '#4ECDC4',
            'Asymmetric': '#45B7D1',
            'Hash': '#96CEB4',
            'exact_match': '#32CD32',
            'category_match': '#FFA500',
            'no_match': '#DC143C',
        }

    def create_three_charts(self, results: List[Dict], timestamp: str, output_dir: str | Path | None = None, file_prefix: str = '') -> None:
        out_dir = Path(output_dir) if output_dir else Path('data') / 'results'
        out_dir.mkdir(parents=True, exist_ok=True)

        print('Creating 3 performance charts for algorithm hidden experiment...')

        df = self._prepare_performance_data(results)
        if df.empty or 'algorithm' not in df.columns:
            print('No results available; skipping chart generation.')
            return

        self.create_algorithm_identification_chart(df, timestamp, output_dir=out_dir, file_prefix=file_prefix)
        self.create_performance_by_algorithm_chart(df, timestamp, output_dir=out_dir, file_prefix=file_prefix)
        self.create_performance_trend_chart(df, timestamp, output_dir=out_dir, file_prefix=file_prefix)

        print(f'Created 3 charts in {out_dir} directory')

    def create_algorithm_identification_chart(self, df: pd.DataFrame, timestamp: str, output_dir: str | Path | None = None, file_prefix: str = '') -> None:
        out_dir = Path(output_dir) if output_dir else Path('data') / 'results'
        out_dir.mkdir(parents=True, exist_ok=True)

        fig = go.Figure()

        algo_metrics = []
        for algo in sorted(df['algorithm'].unique()):
            algo_df = df[df['algorithm'] == algo]
            if len(algo_df) == 0:
                continue

            exact_rate = float(algo_df['exact_match'].mean())
            category_rate = float(algo_df['category_match'].mean())
            avg_id_score = float(algo_df['identified_algorithm_score'].mean())
            avg_cat_score = float(algo_df['identified_category_score'].mean())

            algo_metrics.append({
                'Algorithm': algo,
                'Exact Match Rate': exact_rate,
                'Category Match Rate': category_rate,
                'Avg Identified_Algo_Score': avg_id_score,
                'Avg Identified_Category_Score': avg_cat_score,
                'Test Count': int(len(algo_df)),
            })

        metrics_df = pd.DataFrame(algo_metrics)
        metrics_df = metrics_df.sort_values('Avg Identified_Algo_Score', ascending=False)

        fig.add_trace(go.Bar(name='Exact Match', x=metrics_df['Algorithm'], y=metrics_df['Exact Match Rate'], marker_color=self.color_scheme['exact_match']))
        fig.add_trace(go.Bar(name='Category Match', x=metrics_df['Algorithm'], y=metrics_df['Category Match Rate'], marker_color=self.color_scheme['category_match']))
        fig.add_trace(go.Scatter(x=metrics_df['Algorithm'], y=metrics_df['Avg Identified_Algo_Score'], mode='lines+markers', name='Avg Identified_Algo_Score', line=dict(color='black', width=2), yaxis='y2'))
        fig.add_trace(go.Scatter(x=metrics_df['Algorithm'], y=metrics_df['Avg Identified_Category_Score'], mode='lines+markers', name='Avg Identified_Category_Score', line=dict(color='gray', width=2, dash='dot'), yaxis='y2'))
        fig.update_layout(
            title='Algorithm Identification Performance',
            xaxis_title='Algorithm',
            yaxis_title='Match Rate',
            yaxis=dict(tickformat='.0%', range=[0, 1]),
            yaxis2=dict(title='Avg Identified_Algo_Score', tickformat='.0%', overlaying='y', side='right', range=[0, 1]),
            barmode='group',
            height=600,
            showlegend=True,
            legend=dict(x=1.02, y=1),
            xaxis_tickangle=45,
        )

        for i, count in enumerate(metrics_df['Test Count']):
            fig.add_annotation(x=i, y=1.05, text=f'n={count}', showarrow=False, font=dict(size=10))

        filename = f"{file_prefix}algorithm_hidden_algorithm_identification_{timestamp}.html"
        fig.write_html(str(out_dir / filename))
        print(f'Saved: {filename}')

    def create_performance_by_algorithm_chart(self, df: pd.DataFrame, timestamp: str, output_dir: str | Path | None = None, file_prefix: str = '') -> None:
        out_dir = Path(output_dir) if output_dir else Path('data') / 'results'
        out_dir.mkdir(parents=True, exist_ok=True)

        algo_performance = (
            df.groupby('algorithm')
            .agg({'overall_score': ['mean', 'std', 'count'], 'identified_algorithm_score': 'mean', 'identified_category_score': 'mean', 'vulnerability_score': 'mean', 'decryption_score': 'mean', 'reasoning_score': 'mean'})
            .round(3)
        )
        algo_performance.columns = ['_'.join(col).strip() for col in algo_performance.columns.values]
        algo_performance = algo_performance.rename(columns={
            'overall_score_mean': 'Overall',
            'overall_score_std': 'Std',
            'overall_score_count': 'Count',
            'identified_algorithm_score_mean': 'Identified_Algo_Score',
            'identified_category_score_mean': 'Identified_Category_Score',
            'vulnerability_score_mean': 'Vuln_Score',
            'decryption_score_mean': 'Decrypt_Score',
            'reasoning_score_mean': 'Reason_Score',
        }).reset_index().sort_values('Overall', ascending=False)

        fig = go.Figure()
        metrics = ['Overall', 'Identified_Algo_Score', 'Identified_Category_Score', 'Vuln_Score', 'Decrypt_Score', 'Reason_Score']
        colors = ['#1f77b4', '#ff7f0e', '#7f7f7f', '#2ca02c', '#d62728', '#9467bd']

        for metric, color in zip(metrics, colors):
            fig.add_trace(go.Bar(
                name=metric.replace('_', ' '),
                x=algo_performance['algorithm'],
                y=algo_performance[metric],
                marker_color=color,
                error_y=dict(type='data', array=algo_performance['Std'] if metric == 'Overall' else [0]*len(algo_performance), visible=True if metric == 'Overall' else False),
            ))

        fig.update_layout(
            title='Comprehensive Performance by Algorithm',
            xaxis_title='Algorithm',
            yaxis_title='Score',
            yaxis=dict(range=[0, 1]),
            barmode='group',
            height=700,
            showlegend=True,
            legend=dict(x=1.02, y=1),
            xaxis_tickangle=45,
        )

        for i in range(len(algo_performance)):
            fig.add_annotation(x=i, y=float(algo_performance.iloc[i]['Overall']) + 0.05, text=f"{float(algo_performance.iloc[i]['Overall']):.3f}", showarrow=False, font=dict(size=10))

        filename = f"{file_prefix}algorithm_hidden_performance_by_algorithm_{timestamp}.html"
        fig.write_html(str(out_dir / filename))
        print(f'Saved: {filename}')

    def create_performance_trend_chart(self, df: pd.DataFrame, timestamp: str, output_dir: str | Path | None = None, file_prefix: str = '') -> None:
        out_dir = Path(output_dir) if output_dir else Path('data') / 'results'
        out_dir.mkdir(parents=True, exist_ok=True)

        df = df.reset_index(drop=True)
        df['test_sequence'] = df.index + 1
        window = 20
        df['rolling_overall'] = df['overall_score'].rolling(window=window, min_periods=1).mean()
        df['rolling_id_score'] = df['identified_algorithm_score'].rolling(window=window, min_periods=1).mean()

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=df['test_sequence'], y=df['overall_score'], mode='markers', name='Individual Scores', marker=dict(size=6, color='lightgray', opacity=0.3)))
        fig.add_trace(go.Scatter(x=df['test_sequence'], y=df['rolling_overall'], mode='lines', name=f'Overall (n={window})', line=dict(color='red', width=3)))
        fig.add_trace(go.Scatter(x=df['test_sequence'], y=df['rolling_id_score'], mode='lines', name=f'Identified_Algo_Score (n={window})', line=dict(color='blue', width=2, dash='dash')))

        fig.update_layout(title='Performance Trend Over Test Sequence', xaxis_title='Test Sequence', yaxis_title='Score', yaxis=dict(range=[0, 1]), height=600, showlegend=True, legend=dict(x=0.02, y=0.98))

        filename = f"{file_prefix}algorithm_hidden_performance_trend_{timestamp}.html"
        fig.write_html(str(out_dir / filename))
        print(f'Saved: {filename}')

    def _prepare_performance_data(self, results: List[Dict]) -> pd.DataFrame:
        data = []
        for result in results:
            test_case = result.get('test_case', {})
            evaluation = result.get('evaluation', {})
            original_info = result.get('original_info', {})
            algorithm = (
            (original_info.get('algorithm') if isinstance(original_info, dict) else None)
            or (test_case.get('algorithm') if isinstance(test_case, dict) else None)
            or evaluation.get('algorithm')
            or 'unknown'
        )
            data.append({
                'test_id': test_case.get('test_id', ''),
                'algorithm': algorithm,
                'identified_algorithm': evaluation.get('identified_algorithm', 'unknown'),
                'identified_algorithm_score': float(evaluation.get('identified_algorithm_score', 0) or 0),
                'identified_category_score': float(evaluation.get('identified_category_score', 0) or 0),
                'overall_score': float(evaluation.get('overall_score', 0) or 0),
                'vulnerability_score': float(evaluation.get('vulnerability_score', 0) or 0),
                'decryption_score': float(evaluation.get('decryption_score', 0) or 0),
                'reasoning_score': float(evaluation.get('reasoning_score', 0) or 0),
                'exact_match': bool(evaluation.get('exact_match', False)),
                'category_match': bool(evaluation.get('category_match', False)),
            })

        return pd.DataFrame(data)

# REFRESH_2026
