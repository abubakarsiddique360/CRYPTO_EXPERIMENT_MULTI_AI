"""
Multi-AI Comparison Charts for Research Paper
"""

import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import numpy as np
from typing import Dict, List, Tuple
import json
import os

class MultiAIComparisonCharts:
    def __init__(self):
        self.model_colors = {
            'deepseek': '#1f77b4',
            'chatgpt': '#ff7f0e',
            'gemini': '#2ca02c',
            'grok': '#d62728'
        }
        
        self.model_names = {
            'deepseek': 'DeepSeek',
            'chatgpt': 'ChatGPT-4',
            'gemini': 'Gemini Pro',
            'grok': 'Grok'
        }
        
        self.category_colors = {
            'classical': '#FF6B6B',
            'modern_symmetric': '#4ECDC4',
            'asymmetric': '#45B7D1',
            'hash': '#96CEB4'
        }
    
    def create_overall_performance_comparison(self, results_by_model: Dict[str, List[Dict]], timestamp: str):
        """Bar chart comparing overall scores across all models"""
        model_scores = []
        
        for model_name, results in results_by_model.items():
            scores = [r['evaluation']['overall_score'] for r in results if r['evaluation']['response_success']]
            if scores:
                avg_score = np.mean(scores)
                std_score = np.std(scores)
                ci_95 = 1.96 * (std_score / np.sqrt(len(scores)))
                
                model_scores.append({
                    'Model': self.model_names.get(model_name, model_name),
                    'Average Score': avg_score,
                    'Std Dev': std_score,
                    '95% CI Lower': avg_score - ci_95,
                    '95% CI Upper': avg_score + ci_95,
                    'Test Count': len(scores),
                    'Raw Model': model_name
                })
        
        if not model_scores:
            print("No data for overall performance comparison")
            return
        
        df = pd.DataFrame(model_scores)
        df = df.sort_values('Average Score', ascending=False)
        
        fig = go.Figure()
        
        # Add bars with error bars (confidence intervals)
        fig.add_trace(go.Bar(
            x=df['Model'],
            y=df['Average Score'],
            error_y=dict(
                type='data',
                symmetric=False,
                array=df['95% CI Upper'] - df['Average Score'],
                arrayminus=df['Average Score'] - df['95% CI Lower'],
                visible=True,
                color='black',
                thickness=1.5
            ),
            marker_color=[self.model_colors.get(model, '#999999') for model in df['Raw Model']],
            text=[f'{score:.3f} (±{ci:.3f})' for score, ci in zip(df['Average Score'], df['95% CI Upper'] - df['Average Score'])],
            textposition='auto',
            hovertemplate='<b>%{x}</b><br>' +
                         'Avg Score: %{y:.3f}<br>' +
                         '95% CI: [%{customdata[0]:.3f}, %{customdata[1]:.3f}]<br>' +
                         'Std Dev: %{customdata[2]:.3f}<br>' +
                         'Tests: %{customdata[3]}<br>' +
                         '<extra></extra>',
            customdata=list(zip(df['95% CI Lower'], df['95% CI Upper'], df['Std Dev'], df['Test Count']))
        ))
        
        fig.update_layout(
            title={'text': 'AI Model Performance Comparison', 'x': 0.5, 'xanchor': 'center'},
            xaxis_title='AI Model',
            yaxis_title='Average Score',
            yaxis=dict(range=[0, 1], gridcolor='lightgray'),
            plot_bgcolor='white',
            showlegend=False,
            height=600,
            width=900,
            font=dict(size=12)
        )
        
        os.makedirs('data/comparisons/cross_model', exist_ok=True)
        fig.write_html(f"data/comparisons/cross_model/overall_performance_comparison_{timestamp}.html")
        fig.write_image(f"data/comparisons/cross_model/overall_performance_comparison_{timestamp}.png", 
                       width=1000, height=700, scale=2)
        
        print(f"Saved: overall_performance_comparison_{timestamp}.html")
        
        return fig
    
    def create_algorithm_identification_comparison(self, results_by_model: Dict[str, List[Dict]], timestamp: str):
        """Compare algorithm identification accuracy (hidden condition)"""
        comparison_data = []
        
        for model_name, results in results_by_model.items():
            exact_matches = []
            category_matches = []
            id_scores = []
            
            for result in results:
                evaluation = result['evaluation']
                if evaluation['response_success']:
                    exact_matches.append(evaluation.get('exact_match', False))
                    category_matches.append(evaluation.get('category_match', False))
                    id_scores.append(evaluation.get('identified_algorithm_score', 0))
            
            if exact_matches:
                exact_rate = np.mean(exact_matches)
                exact_ci = 1.96 * np.sqrt((exact_rate * (1 - exact_rate)) / len(exact_matches))
                
                category_rate = np.mean(category_matches)
                category_ci = 1.96 * np.sqrt((category_rate * (1 - category_rate)) / len(category_matches))
                
                avg_id_score = np.mean(id_scores)
                id_ci = 1.96 * (np.std(id_scores) / np.sqrt(len(id_scores)))
                
                comparison_data.append({
                    'Model': self.model_names.get(model_name, model_name),
                    'Exact Match Rate': exact_rate,
                    'Exact CI': exact_ci,
                    'Category Match Rate': category_rate,
                    'Category CI': category_ci,
                    'ID Score': avg_id_score,
                    'ID CI': id_ci,
                    'Test Count': len(exact_matches),
                    'Raw Model': model_name
                })
        
        if not comparison_data:
            print("No data for algorithm identification comparison")
            return
        
        df = pd.DataFrame(comparison_data)
        
        fig = go.Figure()
        
        # Exact match with error bars
        fig.add_trace(go.Bar(
            name='Exact Match',
            x=df['Model'],
            y=df['Exact Match Rate'],
            error_y=dict(
                type='data',
                array=df['Exact CI'],
                visible=True
            ),
            marker_color='#32CD32',
            hovertemplate='<b>%{x}</b><br>' +
                         'Exact Match: %{y:.1%}<br>' +
                         '95% CI: ±%{customdata:.1%}<br>' +
                         'Tests: %{customdata[1]}<br>' +
                         '<extra></extra>',
            customdata=list(zip(df['Exact CI'], df['Test Count']))
        ))
        
        # Category match with error bars
        fig.add_trace(go.Bar(
            name='Category Match',
            x=df['Model'],
            y=df['Category Match Rate'],
            error_y=dict(
                type='data',
                array=df['Category CI'],
                visible=True
            ),
            marker_color='#FFA500',
            hovertemplate='<b>%{x}</b><br>' +
                         'Category Match: %{y:.1%}<br>' +
                         '95% CI: ±%{customdata:.1%}<br>' +
                         'Tests: %{customdata[1]}<br>' +
                         '<extra></extra>',
            customdata=list(zip(df['Category CI'], df['Test Count']))
        ))
        
        # ID score line
        fig.add_trace(go.Scatter(
            x=df['Model'],
            y=df['ID Score'],
            mode='lines+markers',
            name='ID Score',
            line=dict(color='black', width=2),
            marker=dict(size=10),
            yaxis='y2',
            hovertemplate='<b>%{x}</b><br>' +
                         'ID Score: %{y:.3f}<br>' +
                         '<extra></extra>'
        ))
        
        fig.update_layout(
            title={'text': 'Algorithm Identification Accuracy (Hidden Condition)', 'x': 0.5, 'xanchor': 'center'},
            xaxis_title='AI Model',
            yaxis=dict(
                title='Match Rate',
                tickformat='.0%',
                range=[0, 1],
                gridcolor='lightgray'
            ),
            yaxis2=dict(
                title='ID Score',
                tickformat='.0%',
                overlaying='y',
                side='right',
                range=[0, 1]
            ),
            barmode='group',
            plot_bgcolor='white',
            height=600,
            width=900,
            font=dict(size=12),
            legend=dict(x=1.02, y=1)
        )
        
        os.makedirs('data/comparisons/cross_model', exist_ok=True)
        fig.write_html(f"data/comparisons/cross_model/algorithm_identification_comparison_{timestamp}.html")
        fig.write_image(f"data/comparisons/cross_model/algorithm_identification_comparison_{timestamp}.png", 
                       width=1000, height=700, scale=2)
        
        print(f"Saved: algorithm_identification_comparison_{timestamp}.html")
        
        return fig
    
    def create_cost_effectiveness_chart(self, results_by_model: Dict[str, List[Dict]], timestamp: str):
        """Cost vs Performance scatter plot"""
        from config.api_config import AIConfig
        
        cost_data = []
        config = AIConfig()
        
        cost_map = {
            'deepseek': config.get_model_cost('deepseek'),
            'chatgpt': config.get_model_cost('chatgpt'),
            'gemini': config.get_model_cost('gemini'),
            'grok': config.get_model_cost('grok')
        }
        
        for model_name, results in results_by_model.items():
            if model_name not in cost_map:
                continue
                
            scores = [r['evaluation']['overall_score'] for r in results if r['evaluation']['response_success']]
            if not scores:
                continue
            
            # Calculate average tokens and cost
            total_input_tokens = 0
            total_output_tokens = 0
            successful_tests = 0
            
            for result in results:
                if result['evaluation']['response_success']:
                    response = result.get('chatgpt_response') or result.get('deepseek_response') or \
                              result.get('gemini_response') or result.get('grok_response')
                    if response:
                        total_input_tokens += response.get('input_tokens', 0)
                        total_output_tokens += response.get('output_tokens', 0)
                        successful_tests += 1
            
            if successful_tests > 0:
                avg_input_tokens = total_input_tokens / successful_tests
                avg_output_tokens = total_output_tokens / successful_tests
                
                # Calculate cost per test
                cost_per_test = (avg_input_tokens/1000 * cost_map[model_name]['input'] + 
                                avg_output_tokens/1000 * cost_map[model_name]['output'])
                
                avg_score = np.mean(scores)
                std_score = np.std(scores)
                
                cost_data.append({
                    'Model': self.model_names.get(model_name, model_name),
                    'Average Score': avg_score,
                    'Score Std': std_score,
                    'Cost per Test ($)': cost_per_test,
                    'Input Tokens': avg_input_tokens,
                    'Output Tokens': avg_output_tokens,
                    'Total Tests': successful_tests,
                    'Raw Model': model_name
                })
        
        if not cost_data:
            print("No cost data available")
            return
        
        df = pd.DataFrame(cost_data)
        
        fig = px.scatter(
            df,
            x='Cost per Test ($)',
            y='Average Score',
            size='Total Tests',
            color='Model',
            hover_name='Model',
            hover_data=['Input Tokens', 'Output Tokens', 'Score Std'],
            title='Cost-Effectiveness Analysis',
            color_discrete_map={self.model_names.get(k, k): v for k, v in self.model_colors.items() if k in df['Raw Model'].values},
            size_max=60
        )
        
        # Add error bars
        for i, row in df.iterrows():
            fig.add_trace(go.Scatter(
                x=[row['Cost per Test ($)'], row['Cost per Test ($)']],
                y=[row['Average Score'] - row['Score Std'], row['Average Score'] + row['Score Std']],
                mode='lines',
                line=dict(color=self.model_colors.get(row['Raw Model'], '#999999'), width=1),
                showlegend=False,
                hoverinfo='skip'
            ))
        
        # Add trend line
        if len(df) > 1:
            z = np.polyfit(df['Cost per Test ($)'], df['Average Score'], 1)
            p = np.poly1d(z)
            trend_x = np.linspace(df['Cost per Test ($)'].min(), df['Cost per Test ($)'].max(), 100)
            trend_y = p(trend_x)
            
            fig.add_trace(go.Scatter(
                x=trend_x,
                y=trend_y,
                mode='lines',
                line=dict(color='gray', dash='dash', width=2),
                name='Trend Line',
                hovertemplate='Trend: y = %{customdata[0]:.3f}x + %{customdata[1]:.3f}<extra></extra>',
                customdata=[z[0], z[1]]
            ))
        
        fig.update_layout(
            xaxis_title='Cost per Test ($)',
            yaxis_title='Average Score',
            yaxis=dict(range=[0, 1]),
            plot_bgcolor='white',
            height=600,
            width=900,
            font=dict(size=12)
        )
        
        os.makedirs('data/comparisons/cross_model', exist_ok=True)
        fig.write_html(f"data/comparisons/cross_model/cost_effectiveness_{timestamp}.html")
        fig.write_image(f"data/comparisons/cross_model/cost_effectiveness_{timestamp}.png", 
                       width=1000, height=700, scale=2)
        
        print(f"Saved: cost_effectiveness_{timestamp}.html")
        
        return fig
    
    def create_performance_by_category_comparison(self, results_by_model: Dict[str, List[Dict]], timestamp: str):
        """Compare performance by algorithm category across models"""
        category_data = []
        
        for model_name, results in results_by_model.items():
            for result in results:
                evaluation = result['evaluation']
                test_case = result['test_case']
                
                if evaluation['response_success']:
                    category_data.append({
                        'Model': self.model_names.get(model_name, model_name),
                        'Category': test_case.get('category', 'unknown'),
                        'Score': evaluation['overall_score'],
                        'Raw Model': model_name
                    })
        
        if not category_data:
            print("No category data available")
            return
        
        df = pd.DataFrame(category_data)
        
        # Map category names
        category_map = {
            'classical': 'Classical',
            'modern_symmetric': 'Modern Symmetric',
            'asymmetric': 'Asymmetric',
            'hash': 'Hash'
        }
        df['Category'] = df['Category'].map(category_map).fillna(df['Category'])
        
        # Calculate statistics
        category_stats = df.groupby(['Model', 'Category']).agg({
            'Score': ['mean', 'std', 'count']
        }).round(3)
        category_stats.columns = ['Mean', 'Std', 'Count']
        category_stats = category_stats.reset_index()
        
        fig = go.Figure()
        
        # Create grouped bar chart
        categories = sorted(df['Category'].unique())
        models = sorted(df['Model'].unique())
        
        for i, model in enumerate(models):
            model_data = category_stats[category_stats['Model'] == model]
            # Ensure all categories are present
            model_scores = []
            model_errors = []
            
            for category in categories:
                cat_data = model_data[model_data['Category'] == category]
                if len(cat_data) > 0:
                    model_scores.append(cat_data['Mean'].values[0])
                    # Calculate standard error
                    n = cat_data['Count'].values[0]
                    std = cat_data['Std'].values[0]
                    se = 1.96 * (std / np.sqrt(n)) if n > 0 else 0
                    model_errors.append(se)
                else:
                    model_scores.append(0)
                    model_errors.append(0)
            
            fig.add_trace(go.Bar(
                name=model,
                x=categories,
                y=model_scores,
                error_y=dict(
                    type='data',
                    array=model_errors,
                    visible=True
                ),
                marker_color=self.model_colors.get(self._get_raw_model(model), '#999999'),
                hovertemplate='<b>%{x}</b><br>' +
                             'Model: %{fullData.name}<br>' +
                             'Score: %{y:.3f}<br>' +
                             '95% CI: ±%{customdata:.3f}<br>' +
                             '<extra></extra>',
                customdata=model_errors
            ))
        
        fig.update_layout(
            title={'text': 'Performance by Algorithm Category', 'x': 0.5, 'xanchor': 'center'},
            xaxis_title='Category',
            yaxis_title='Average Score',
            yaxis=dict(range=[0, 1], gridcolor='lightgray'),
            barmode='group',
            plot_bgcolor='white',
            height=600,
            width=1000,
            font=dict(size=12),
            legend=dict(x=1.02, y=1)
        )
        
        os.makedirs('data/comparisons/cross_model', exist_ok=True)
        fig.write_html(f"data/comparisons/cross_model/category_performance_comparison_{timestamp}.html")
        fig.write_image(f"data/comparisons/cross_model/category_performance_comparison_{timestamp}.png", 
                       width=1100, height=700, scale=2)
        
        print(f"Saved: category_performance_comparison_{timestamp}.html")
        
        return fig
    
    def create_radar_chart_comparison(self, results_by_model: Dict[str, List[Dict]], timestamp: str):
        """Radar chart showing model strengths"""
        radar_data = []
        
        for model_name, results in results_by_model.items():
            if not results:
                continue
                
            successful = [r for r in results if r['evaluation']['response_success']]
            if not successful:
                continue
            
            # Calculate different metrics
            overall_scores = [r['evaluation']['overall_score'] for r in successful]
            vuln_scores = [r['evaluation'].get('vulnerability_score', 0) for r in successful]
            decrypt_scores = [r['evaluation'].get('decryption_score', 0) for r in successful]
            reason_scores = [r['evaluation'].get('reasoning_score', 0) for r in successful]
            
            # Calculate consistency (inverse of coefficient of variation)
            if np.mean(overall_scores) > 0:
                cv = np.std(overall_scores) / np.mean(overall_scores)
                consistency = 1 / (1 + cv)  # Normalized consistency score
            else:
                consistency = 0
            
            radar_data.append({
                'Model': self.model_names.get(model_name, model_name),
                'Overall': np.mean(overall_scores),
                'Vulnerability': np.mean(vuln_scores),
                'Decryption': np.mean(decrypt_scores),
                'Reasoning': np.mean(reason_scores),
                'Consistency': consistency,
                'Speed': 0.7,  # Placeholder - would need actual timing data
                'Raw Model': model_name
            })
        
        if not radar_data:
            print("No data for radar chart")
            return
        
        df = pd.DataFrame(radar_data)
        categories = ['Overall', 'Vulnerability', 'Decryption', 'Reasoning', 'Consistency', 'Speed']
        
        fig = go.Figure()
        
        for _, row in df.iterrows():
            fig.add_trace(go.Scatterpolar(
                r=[row[cat] for cat in categories],
                theta=categories,
                fill='toself',
                name=row['Model'],
                line_color=self.model_colors.get(row['Raw Model'], '#999999'),
                opacity=0.7
            ))
        
        fig.update_layout(
            polar=dict(
                radialaxis=dict(
                    visible=True,
                    range=[0, 1],
                    gridcolor='lightgray',
                    tickfont=dict(size=10)
                ),
                angularaxis=dict(
                    gridcolor='lightgray',
                    linecolor='gray'
                ),
                bgcolor='white'
            ),
            title={'text': 'AI Model Strengths Comparison (Radar Chart)', 'x': 0.5, 'xanchor': 'center'},
            showlegend=True,
            height=700,
            width=800,
            font=dict(size=11),
            legend=dict(
                x=1.1,
                y=0.5,
                bgcolor='rgba(255, 255, 255, 0.8)'
            )
        )
        
        os.makedirs('data/comparisons/cross_model', exist_ok=True)
        fig.write_html(f"data/comparisons/cross_model/radar_chart_comparison_{timestamp}.html")
        fig.write_image(f"data/comparisons/cross_model/radar_chart_comparison_{timestamp}.png", 
                       width=900, height=800, scale=2)
        
        print(f"Saved: radar_chart_comparison_{timestamp}.html")
        
        return fig
    
    def create_component_score_comparison(self, results_by_model: Dict[str, List[Dict]], timestamp: str):
        """Compare component scores across models"""
        component_data = []
        
        for model_name, results in results_by_model.items():
            for result in results:
                evaluation = result['evaluation']
                if evaluation['response_success']:
                    component_data.append({
                        'Model': self.model_names.get(model_name, model_name),
                        'Vulnerability': evaluation.get('vulnerability_score', 0),
                        'Decryption': evaluation.get('decryption_score', 0),
                        'Reasoning': evaluation.get('reasoning_score', 0),
                        'Confidence': evaluation.get('confidence', 0),
                        'Raw Model': model_name
                    })
        
        if not component_data:
            print("No component data available")
            return
        
        df = pd.DataFrame(component_data)
        
        # Melt for grouped bar chart
        df_melted = df.melt(id_vars=['Model', 'Raw Model'], 
                           value_vars=['Vulnerability', 'Decryption', 'Reasoning', 'Confidence'],
                           var_name='Component', value_name='Score')
        
        # Calculate statistics
        stats = df_melted.groupby(['Model', 'Component']).agg({
            'Score': ['mean', 'std', 'count']
        }).round(3)
        stats.columns = ['Mean', 'Std', 'Count']
        stats = stats.reset_index()
        
        # Calculate standard errors
        stats['SE'] = 1.96 * (stats['Std'] / np.sqrt(stats['Count']))
        
        fig = px.bar(
            stats,
            x='Component',
            y='Mean',
            color='Model',
            barmode='group',
            error_y='SE',
            title='Component Score Comparison Across AI Models',
            color_discrete_map={self.model_names.get(k, k): self.model_colors.get(k, '#999999') 
                               for k in df['Raw Model'].unique()},
            labels={'Mean': 'Average Score', 'Component': 'Score Component'},
            hover_data=['Std', 'Count']
        )
        
        fig.update_layout(
            xaxis_title='Score Component',
            yaxis_title='Average Score',
            yaxis=dict(range=[0, 1], gridcolor='lightgray'),
            plot_bgcolor='white',
            height=600,
            width=1000,
            font=dict(size=12),
            legend=dict(x=1.02, y=1)
        )
        
        os.makedirs('data/comparisons/cross_model', exist_ok=True)
        fig.write_html(f"data/comparisons/cross_model/component_score_comparison_{timestamp}.html")
        fig.write_image(f"data/comparisons/cross_model/component_score_comparison_{timestamp}.png", 
                       width=1100, height=700, scale=2)
        
        print(f"Saved: component_score_comparison_{timestamp}.html")
        
        return fig
    
    def _get_raw_model(self, display_name: str) -> str:
        """Get raw model name from display name"""
        for raw, display in self.model_names.items():
            if display == display_name:
                return raw
        return display_name
# REFRESH_2026
