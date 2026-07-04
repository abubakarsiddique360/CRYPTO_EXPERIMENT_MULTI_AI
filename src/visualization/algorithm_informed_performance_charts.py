"""Algorithm Informed Performance Charts.

Writes 5 interactive HTML charts. By default writes to data/results/, but
callers should pass output_dir to control where files land.

Expected output naming (no platform prefix needed if output_dir is per-platform):
  algorithm_informed_confidence_vs_actual_{timestamp}.html
  algorithm_informed_time_series_analysis_{timestamp}.html
  algorithm_informed_component_score_breakdown_{timestamp}.html
  algorithm_informed_performance_by_category_{timestamp}.html
  algorithm_informed_performance_by_algorithm_{timestamp}.html
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List

import plotly.express as px
import plotly.graph_objects as go
import pandas as pd


class PerformanceCharts:
    def __init__(self):
        self.color_scheme = {
            'classical': '#FF6B6B',
            'modern_symmetric': '#4ECDC4',
            'asymmetric': '#45B7D1',
            'hash': '#96CEB4',
        }

    def create_comprehensive_dashboard(
        self,
        results: List[Dict[str, Any]],
        metrics: Dict[str, Any],
        timestamp: str,
        output_dir: str | Path | None = None,
        file_prefix: str = '',
    ) -> None:
        """Create 5 individual charts as separate HTML files."""
        out_dir = Path(output_dir) if output_dir else Path('data') / 'results'
        out_dir.mkdir(parents=True, exist_ok=True)

        print('Creating comprehensive performance dashboard...')

        self.create_confidence_vs_actual_chart(results, timestamp, output_dir=out_dir, file_prefix=file_prefix)
        self.create_time_series_analysis(results, timestamp, output_dir=out_dir, file_prefix=file_prefix)
        self.create_component_score_breakdown(results, timestamp, output_dir=out_dir, file_prefix=file_prefix)
        self.create_performance_by_category(results, timestamp, output_dir=out_dir, file_prefix=file_prefix)
        self.create_performance_by_algorithm(results, timestamp, output_dir=out_dir, file_prefix=file_prefix)

        print(f'Created 5 visualization files in {out_dir} directory')

    def _fname(self, base: str, timestamp: str, file_prefix: str) -> str:
        return f"{file_prefix}algorithm_informed_{base}_{timestamp}.html"

    def _get_response_success(self, result: Dict[str, Any]) -> bool:
        # support deepseek_response / grok_response / gemini_response / chatgpt_response
        for key, value in result.items():
            if key.endswith('_response') and isinstance(value, dict):
                return bool(value.get('success'))
        resp = result.get('response')
        if isinstance(resp, dict):
            return bool(resp.get('success'))
        return False

    def create_confidence_vs_actual_chart(self, results: List[Dict[str, Any]], timestamp: str, output_dir: str | Path | None = None, file_prefix: str = '') -> None:
        out_dir = Path(output_dir) if output_dir else Path('data') / 'results'
        out_dir.mkdir(parents=True, exist_ok=True)

        confidence_data = []
        for result in results:
            evaluation = result.get('evaluation', {})
            test_case = result.get('test_case', {})
            confidence_data.append({
                'confidence': evaluation.get('confidence_score', evaluation.get('confidence', 0)),
                'actual_score': evaluation.get('overall_score', 0),
                'algorithm': test_case.get('algorithm', 'unknown'),
                'category': test_case.get('category', 'unknown'),
            })

        df = pd.DataFrame(confidence_data)

        fig = px.scatter(
            df,
            x='confidence',
            y='actual_score',
            color='category',
            title='Confidence vs Actual Performance',
            hover_data=['algorithm'],
            color_discrete_map={
                'classical': self.color_scheme['classical'],
                'modern_symmetric': self.color_scheme['modern_symmetric'],
                'asymmetric': self.color_scheme['asymmetric'],
                'hash': self.color_scheme['hash'],
            },
        )

        fig.add_trace(
            go.Scatter(
                x=[0, 1],
                y=[0, 1],
                mode='lines',
                line=dict(color='red', dash='dash'),
                name='Perfect Calibration',
            )
        )

        fig.update_layout(xaxis_title='Confidence Score', yaxis_title='Actual Performance Score', showlegend=True, height=600)

        filename = self._fname('confidence_vs_actual', timestamp, file_prefix)
        fig.write_html(str(out_dir / filename))
        print(f'Saved: {filename}')

    def create_time_series_analysis(self, results: List[Dict[str, Any]], timestamp: str, output_dir: str | Path | None = None, file_prefix: str = '') -> None:
        out_dir = Path(output_dir) if output_dir else Path('data') / 'results'
        out_dir.mkdir(parents=True, exist_ok=True)

        df = self._prepare_performance_data(results)
        if df.empty:
            fig = self._create_empty_chart('No results available')
            filename = self._fname('time_series_analysis', timestamp, file_prefix)
            fig.write_html(str(out_dir / filename))
            return

        df = df.reset_index(drop=True)
        df['test_sequence'] = range(len(df))
        df['rolling_score'] = df['overall_score'].rolling(window=10, min_periods=1).mean()

        fig = go.Figure()
        fig.add_trace(go.Scatter(
            x=df['test_sequence'],
            y=df['overall_score'],
            mode='markers',
            name='Individual Scores',
            marker=dict(size=10, color=df['overall_score'], colorscale='Viridis', showscale=True, colorbar=dict(title='Score', x=1.02), opacity=0.7),
        ))
        fig.add_trace(go.Scatter(
            x=df['test_sequence'],
            y=df['rolling_score'],
            mode='lines',
            name='Rolling Average (10 tests)',
            line=dict(color='red', width=3),
            yaxis='y2',
        ))

        fig.update_layout(
            title='Performance Trend Over Test Sequence',
            xaxis_title='Test Sequence',
            yaxis=dict(title='Individual Scores', range=[0, 1], showgrid=True, gridcolor='lightgray'),
            yaxis2=dict(title='Rolling Average', range=[0, 1], overlaying='y', side='right', showgrid=False),
            showlegend=True,
            height=600,
            legend=dict(x=0.02, y=0.98, bgcolor='rgba(255, 255, 255, 0.8)', bordercolor='black', borderwidth=1),
        )

        filename = self._fname('time_series_analysis', timestamp, file_prefix)
        fig.write_html(str(out_dir / filename))
        print(f'Saved: {filename}')

    def create_component_score_breakdown(self, results: List[Dict[str, Any]], timestamp: str, output_dir: str | Path | None = None, file_prefix: str = '') -> None:
        out_dir = Path(output_dir) if output_dir else Path('data') / 'results'
        out_dir.mkdir(parents=True, exist_ok=True)

        df = self._prepare_performance_data(results)
        if df.empty:
            fig = self._create_empty_chart('No results available')
            filename = self._fname('component_score_breakdown', timestamp, file_prefix)
            fig.write_html(str(out_dir / filename))
            return

        component_scores = {
            'Vulnerability Detection': float(df['vulnerability_score'].mean()),
            'Decryption Success': float(df['decryption_score'].mean()),
            'Reasoning Quality': float(df['reasoning_score'].mean()),
        }

        fig = go.Figure()
        fig.add_trace(go.Bar(x=list(component_scores.keys()), y=list(component_scores.values()), marker_color=['#FF6B6B', '#4ECDC4', '#45B7D1']))
        fig.update_layout(title='Component Score Breakdown', xaxis_title='Component', yaxis_title='Average Score', showlegend=False, height=600)

        filename = self._fname('component_score_breakdown', timestamp, file_prefix)
        fig.write_html(str(out_dir / filename))
        print(f'Saved: {filename}')

    def create_performance_by_category(self, results: List[Dict[str, Any]], timestamp: str, output_dir: str | Path | None = None, file_prefix: str = '') -> None:
        out_dir = Path(output_dir) if output_dir else Path('data') / 'results'
        out_dir.mkdir(parents=True, exist_ok=True)

        df = self._prepare_performance_data(results)
        if df.empty:
            fig = self._create_empty_chart('No results available')
            filename = self._fname('performance_by_category', timestamp, file_prefix)
            fig.write_html(str(out_dir / filename))
            return

        category_performance = df.groupby('category')['overall_score'].mean().reset_index()

        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=category_performance['category'],
            y=category_performance['overall_score'],
            marker_color=[self.color_scheme.get(cat, '#999999') for cat in category_performance['category']],
        ))
        fig.update_layout(title='Performance by Algorithm Category', xaxis_title='Category', yaxis_title='Average Score', showlegend=False, height=600)

        filename = self._fname('performance_by_category', timestamp, file_prefix)
        fig.write_html(str(out_dir / filename))
        print(f'Saved: {filename}')

    def create_performance_by_algorithm(self, results: List[Dict[str, Any]], timestamp: str, output_dir: str | Path | None = None, file_prefix: str = '') -> None:
        out_dir = Path(output_dir) if output_dir else Path('data') / 'results'
        out_dir.mkdir(parents=True, exist_ok=True)

        df = self._prepare_performance_data(results)
        if df.empty:
            fig = self._create_empty_chart('No results available')
            filename = self._fname('performance_by_algorithm', timestamp, file_prefix)
            fig.write_html(str(out_dir / filename))
            return

        algorithm_performance = df.groupby('algorithm')['overall_score'].agg(['mean', 'count']).reset_index().sort_values('mean', ascending=False)

        category_colors = {}
        for _, row in df[['algorithm', 'category']].drop_duplicates().iterrows():
            category_colors[row['algorithm']] = self.color_scheme.get(row['category'], '#999999')

        fig = go.Figure()
        fig.add_trace(go.Bar(
            x=algorithm_performance['algorithm'],
            y=algorithm_performance['mean'],
            marker_color=[category_colors.get(algo, '#999999') for algo in algorithm_performance['algorithm']],
            text=algorithm_performance['mean'].round(3),
            textposition='auto',
            customdata=algorithm_performance['count'],
            hovertemplate='<b>%{x}</b><br>Average Score: %{y:.3f}<br>Test Count: %{customdata}<br><extra></extra>',
        ))
        fig.update_layout(title='Performance by Algorithm (Sorted by Average Score)', xaxis_title='Algorithm', yaxis_title='Average Score', showlegend=False, height=800, xaxis_tickangle=45)

        filename = self._fname('performance_by_algorithm', timestamp, file_prefix)
        fig.write_html(str(out_dir / filename))
        print(f'Saved: {filename}')

    def _prepare_performance_data(self, results: List[Dict[str, Any]]) -> pd.DataFrame:
        data = []
        for result in results:
            test_case = result.get('test_case', {})
            evaluation = result.get('evaluation', {})

            data.append({
                'test_id': test_case.get('test_id', ''),
                'algorithm': test_case.get('algorithm', 'unknown'),
                'category': test_case.get('category', 'unknown'),
                'difficulty': test_case.get('difficulty', 'unknown'),
                'overall_score': float(evaluation.get('overall_score', 0) or 0),
                'vulnerability_score': float(evaluation.get('vulnerability_detection_score', evaluation.get('vulnerability_score', 0)) or 0),
                'decryption_score': float(evaluation.get('decryption_success_score', evaluation.get('decryption_score', 0)) or 0),
                'reasoning_score': float(evaluation.get('reasoning_quality_score', evaluation.get('reasoning_score', 0)) or 0),
                'response_success': self._get_response_success(result),
            })

        return pd.DataFrame(data)

    def _create_empty_chart(self, message: str) -> go.Figure:
        fig = go.Figure()
        fig.add_annotation(x=0.5, y=0.5, text=message, showarrow=False, font=dict(size=16), xref='paper', yref='paper')
        fig.update_layout(title='No Data Available', xaxis=dict(visible=False), yaxis=dict(visible=False), height=600)
        return fig
