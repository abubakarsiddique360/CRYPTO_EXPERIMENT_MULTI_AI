"""
Cross-model comparison tables for research paper
"""

import pandas as pd
import plotly.graph_objects as go
from typing import Dict, List
import numpy as np
import os

class CrossModelTables:
    def __init__(self):
        self.model_names = {
            'deepseek': 'DeepSeek',
            'chatgpt': 'ChatGPT-4',
            'gemini': 'Gemini Pro',
            'grok': 'Grok'
        }
        
        self.category_names = {
            'classical': 'Classical',
            'modern_symmetric': 'Modern Symmetric',
            'asymmetric': 'Asymmetric',
            'hash': 'Hash'
        }
    
    def create_performance_summary_table(self, results_by_model: Dict[str, List[Dict]], timestamp: str):
        """Create comprehensive performance summary table"""
        summary_data = []
        
        for model_name, results in results_by_model.items():
            if not results:
                continue
                
            successful = [r for r in results if r['evaluation']['response_success']]
            if not successful:
                continue
            
            evaluations = [r['evaluation'] for r in successful]
            
            # Calculate metrics
            total_tests = len(successful)
            overall_scores = [e['overall_score'] for e in evaluations]
            vuln_scores = [e.get('vulnerability_score', 0) for e in evaluations]
            decrypt_scores = [e.get('decryption_score', 0) for e in evaluations]
            reason_scores = [e.get('reasoning_score', 0) for e in evaluations]
            
            # Exact match for hidden condition
            exact_matches = [e.get('exact_match', False) for e in evaluations]
            exact_rate = np.mean(exact_matches) if exact_matches else 0
            
            # Calculate statistics
            avg_overall = np.mean(overall_scores)
            std_overall = np.std(overall_scores)
            ci_95 = 1.96 * (std_overall / np.sqrt(len(overall_scores)))
            
            summary_data.append({
                'Model': self.model_names.get(model_name, model_name),
                'Tests': total_tests,
                'Overall Score': f"{avg_overall:.3f} ± {ci_95:.3f}",
                'Mean': avg_overall,
                'Std': std_overall,
                'Vulnerability': np.mean(vuln_scores),
                'Decryption': np.mean(decrypt_scores),
                'Reasoning': np.mean(reason_scores),
                'Exact Match': f"{exact_rate:.1%}",
                'Raw Model': model_name
            })
        
        if not summary_data:
            print("No data for summary table")
            return
        
        df = pd.DataFrame(summary_data)
        df = df.sort_values('Mean', ascending=False)
        
        # Create table
        fig = go.Figure(data=[go.Table(
            columnorder=list(range(9)),
            columnwidth=[20, 12, 20, 15, 15, 15, 15, 15, 15],
            header=dict(
                values=['<b>Model</b>', '<b>Tests</b>', '<b>Overall Score<br>(Mean ± 95% CI)</b>',
                       '<b>Vulnerability<br>Score</b>', '<b>Decryption<br>Score</b>',
                       '<b>Reasoning<br>Score</b>', '<b>Exact Match<br>Rate</b>',
                       '<b>Std Dev</b>', '<b>Rank</b>'],
                fill_color='#2E86C1',
                align=['left', 'center', 'center', 'center', 'center', 'center', 'center', 'center', 'center'],
                font=dict(size=12, color='white', family='Arial'),
                height=40
            ),
            cells=dict(
                values=[
                    df['Model'],
                    df['Tests'],
                    df['Overall Score'],
                    [f"{v:.3f}" for v in df['Vulnerability']],
                    [f"{v:.3f}" for v in df['Decryption']],
                    [f"{v:.3f}" for v in df['Reasoning']],
                    df['Exact Match'],
                    [f"{v:.3f}" for v in df['Std']],
                    [f"{i+1}" for i in range(len(df))]
                ],
                fill_color=[['white', '#f2f2f2'] * (len(df) // 2 + 1)],
                align=['left', 'center', 'center', 'center', 'center', 'center', 'center', 'center', 'center'],
                font=dict(size=11, family='Arial'),
                height=35
            )
        )])
        
        fig.update_layout(
            title={'text': f'AI Model Performance Summary Table ({timestamp})', 
                   'x': 0.5, 'xanchor': 'center', 'font': {'size': 16}},
            width=1200,
            height=300 + len(df) * 40,
            margin=dict(l=20, r=20, t=60, b=20)
        )
        
        os.makedirs('data/comparisons/cross_model/tables', exist_ok=True)
        fig.write_html(f"data/comparisons/cross_model/tables/performance_summary_{timestamp}.html")
        fig.write_image(f"data/comparisons/cross_model/tables/performance_summary_{timestamp}.png", 
                       width=1300, height=400 + len(df) * 40, scale=2)
        
        print(f"Saved: performance_summary_{timestamp}.html")
        
        return fig
    
    def create_statistical_comparison_table(self, results_by_model: Dict[str, List[Dict]], timestamp: str):
        """Create table with statistical comparisons between models"""
        import scipy.stats as stats
        
        models = list(results_by_model.keys())
        if len(models) < 2:
            print("Need at least 2 models for statistical comparison")
            return
        
        # Prepare data
        model_scores = {}
        for model_name, results in results_by_model.items():
            scores = [r['evaluation']['overall_score'] for r in results if r['evaluation']['response_success']]
            if scores:
                model_scores[model_name] = scores
        
        if len(model_scores) < 2:
            print("Not enough models with valid scores")
            return
        
        # Perform pairwise t-tests
        comparisons = []
        model_list = list(model_scores.keys())
        
        for i in range(len(model_list)):
            for j in range(i+1, len(model_list)):
                model1 = model_list[i]
                model2 = model_list[j]
                
                scores1 = model_scores[model1]
                scores2 = model_scores[model2]
                
                # Perform t-test
                t_stat, p_value = stats.ttest_ind(scores1, scores2, equal_var=False)
                
                # Calculate effect size (Cohen's d)
                mean1, mean2 = np.mean(scores1), np.mean(scores2)
                std1, std2 = np.std(scores1, ddof=1), np.std(scores2, ddof=1)
                n1, n2 = len(scores1), len(scores2)
                
                pooled_std = np.sqrt(((n1-1)*std1**2 + (n2-1)*std2**2) / (n1 + n2 - 2))
                cohens_d = (mean1 - mean2) / pooled_std if pooled_std != 0 else 0
                
                # Determine significance
                significance = "***" if p_value < 0.001 else "**" if p_value < 0.01 else "*" if p_value < 0.05 else "ns"
                
                comparisons.append({
                    'Comparison': f"{self.model_names.get(model1, model1)} vs {self.model_names.get(model2, model2)}",
                    'Mean Diff': f"{mean1 - mean2:.3f}",
                    't-statistic': f"{t_stat:.3f}",
                    'p-value': f"{p_value:.4f}",
                    "Cohen's d": f"{abs(cohens_d):.3f}",
                    'Significance': significance,
                    'Interpretation': self._interpret_effect_size(abs(cohens_d))
                })
        
        df = pd.DataFrame(comparisons)
        
        # Create table
        fig = go.Figure(data=[go.Table(
            columnorder=list(range(7)),
            columnwidth=[25, 15, 15, 15, 15, 15, 20],
            header=dict(
                values=['<b>Comparison</b>', '<b>Mean Difference</b>', '<b>t-statistic</b>',
                       '<b>p-value</b>', "<b>Cohen's d</b>", '<b>Significance</b>',
                       '<b>Effect Size</b>'],
                fill_color='#27AE60',
                align=['left', 'center', 'center', 'center', 'center', 'center', 'left'],
                font=dict(size=12, color='white', family='Arial'),
                height=40
            ),
            cells=dict(
                values=[
                    df['Comparison'],
                    df['Mean Diff'],
                    df['t-statistic'],
                    df['p-value'],
                    df["Cohen's d"],
                    df['Significance'],
                    df['Interpretation']
                ],
                fill_color=[['white', '#f2f2f2'] * (len(df) // 2 + 1)],
                align=['left', 'center', 'center', 'center', 'center', 'center', 'left'],
                font=dict(size=11, family='Arial'),
                height=35
            )
        )])
        
        fig.update_layout(
            title={'text': f'Statistical Comparison Table ({timestamp})', 
                   'x': 0.5, 'xanchor': 'center', 'font': {'size': 16}},
            width=1200,
            height=300 + len(df) * 40,
            margin=dict(l=20, r=20, t=60, b=20)
        )
        
        os.makedirs('data/comparisons/cross_model/tables', exist_ok=True)
        fig.write_html(f"data/comparisons/cross_model/tables/statistical_comparison_{timestamp}.html")
        fig.write_image(f"data/comparisons/cross_model/tables/statistical_comparison_{timestamp}.png", 
                       width=1300, height=400 + len(df) * 40, scale=2)
        
        print(f"Saved: statistical_comparison_{timestamp}.html")
        
        return fig
    
    def create_cost_analysis_table(self, results_by_model: Dict[str, List[Dict]], timestamp: str):
        """Create cost analysis table"""
        from config.api_config import AIConfig
        
        cost_data = []
        config = AIConfig()
        
        for model_name, results in results_by_model.items():
            if not results:
                continue
                
            successful = [r for r in results if r['evaluation']['response_success']]
            if not successful:
                continue
            
            # Get cost structure
            cost_info = config.get_model_cost(model_name)
            if not cost_info:
                continue
            
            # Calculate token usage and costs
            total_input_tokens = 0
            total_output_tokens = 0
            total_cost = 0
            
            for result in successful:
                response = self._get_response_data(result, model_name)
                if response:
                    input_tokens = response.get('input_tokens', 0)
                    output_tokens = response.get('output_tokens', 0)
                    
                    total_input_tokens += input_tokens
                    total_output_tokens += output_tokens
                    
                    # Calculate cost for this test
                    test_cost = (input_tokens/1000 * cost_info['input'] + 
                                output_tokens/1000 * cost_info['output'])
                    total_cost += test_cost
            
            avg_input_tokens = total_input_tokens / len(successful)
            avg_output_tokens = total_output_tokens / len(successful)
            avg_cost_per_test = total_cost / len(successful)
            total_tests = len(successful)
            
            cost_data.append({
                'Model': self.model_names.get(model_name, model_name),
                'Tests': total_tests,
                'Avg Input Tokens': f"{avg_input_tokens:.0f}",
                'Avg Output Tokens': f"{avg_output_tokens:.0f}",
                'Cost per 1K Input': f"${cost_info['input']:.6f}",
                'Cost per 1K Output': f"${cost_info['output']:.6f}",
                'Avg Cost per Test': f"${avg_cost_per_test:.6f}",
                'Total Cost': f"${total_cost:.4f}",
                'Raw Model': model_name
            })
        
        if not cost_data:
            print("No cost data available")
            return
        
        df = pd.DataFrame(cost_data)
        
        # Create table
        fig = go.Figure(data=[go.Table(
            columnorder=list(range(9)),
            columnwidth=[20, 12, 15, 15, 15, 15, 15, 15, 15],
            header=dict(
                values=['<b>Model</b>', '<b>Tests</b>', '<b>Avg Input<br>Tokens</b>',
                       '<b>Avg Output<br>Tokens</b>', '<b>Cost per 1K<br>Input</b>',
                       '<b>Cost per 1K<br>Output</b>', '<b>Avg Cost<br>per Test</b>',
                       '<b>Total Cost</b>', '<b>Cost Rank</b>'],
                fill_color='#E74C3C',
                align=['left', 'center', 'center', 'center', 'center', 'center', 'center', 'center', 'center'],
                font=dict(size=12, color='white', family='Arial'),
                height=40
            ),
            cells=dict(
                values=[
                    df['Model'],
                    df['Tests'],
                    df['Avg Input Tokens'],
                    df['Avg Output Tokens'],
                    df['Cost per 1K Input'],
                    df['Cost per 1K Output'],
                    df['Avg Cost per Test'],
                    df['Total Cost'],
                    [f"{i+1}" for i in range(len(df))]
                ],
                fill_color=[['white', '#f2f2f2'] * (len(df) // 2 + 1)],
                align=['left', 'center', 'center', 'center', 'center', 'center', 'center', 'center', 'center'],
                font=dict(size=11, family='Arial'),
                height=35
            )
        )])
        
        fig.update_layout(
            title={'text': f'Cost Analysis Table ({timestamp})', 
                   'x': 0.5, 'xanchor': 'center', 'font': {'size': 16}},
            width=1300,
            height=300 + len(df) * 40,
            margin=dict(l=20, r=20, t=60, b=20)
        )
        
        os.makedirs('data/comparisons/cross_model/tables', exist_ok=True)
        fig.write_html(f"data/comparisons/cross_model/tables/cost_analysis_{timestamp}.html")
        fig.write_image(f"data/comparisons/cross_model/tables/cost_analysis_{timestamp}.png", 
                       width=1400, height=400 + len(df) * 40, scale=2)
        
        print(f"Saved: cost_analysis_{timestamp}.html")
        
        return fig
    
    def create_category_performance_table(self, results_by_model: Dict[str, List[Dict]], timestamp: str):
        """Create table showing performance by algorithm category"""
        category_data = []
        
        for model_name, results in results_by_model.items():
            for result in results:
                evaluation = result['evaluation']
                test_case = result['test_case']
                
                if evaluation['response_success']:
                    category = test_case.get('category', 'unknown')
                    category_name = self.category_names.get(category, category)
                    
                    category_data.append({
                        'Model': self.model_names.get(model_name, model_name),
                        'Category': category_name,
                        'Score': evaluation['overall_score'],
                        'Raw Model': model_name
                    })
        
        if not category_data:
            print("No category data available")
            return
        
        df = pd.DataFrame(category_data)
        
        # Create pivot table
        pivot = pd.pivot_table(df, 
                              values='Score', 
                              index='Model',
                              columns='Category', 
                              aggfunc=['mean', 'std', 'count'])
        
        # Flatten multi-level columns
        pivot.columns = [f'{col[1]} {col[0]}' for col in pivot.columns]
        pivot = pivot.reset_index()
        
        # Format values
        formatted_data = []
        for _, row in pivot.iterrows():
            formatted_row = [row['Model']]
            for category in self.category_names.values():
                mean_col = f'{category} mean'
                std_col = f'{category} std'
                count_col = f'{category} count'
                
                if mean_col in row and not pd.isna(row[mean_col]):
                    mean = row[mean_col]
                    std = row.get(std_col, 0)
                    count = row.get(count_col, 0)
                    se = 1.96 * (std / np.sqrt(count)) if count > 0 else 0
                    formatted_row.append(f"{mean:.3f} ± {se:.3f}")
                else:
                    formatted_row.append("N/A")
            
            formatted_data.append(formatted_row)
        
        # Create table
        categories = list(self.category_names.values())
        header = ['<b>Model</b>'] + [f'<b>{cat}</b><br>(Mean ± 95% CI)' for cat in categories]
        
        fig = go.Figure(data=[go.Table(
            columnorder=list(range(len(categories) + 1)),
            columnwidth=[20] + [15] * len(categories),
            header=dict(
                values=header,
                fill_color='#8E44AD',
                align=['left'] + ['center'] * len(categories),
                font=dict(size=12, color='white', family='Arial'),
                height=40
            ),
            cells=dict(
                values=list(zip(*formatted_data)),
                fill_color=[['white', '#f2f2f2'] * (len(formatted_data) // 2 + 1)],
                align=['left'] + ['center'] * len(categories),
                font=dict(size=11, family='Arial'),
                height=35
            )
        )])
        
        fig.update_layout(
            title={'text': f'Category Performance Table ({timestamp})', 
                   'x': 0.5, 'xanchor': 'center', 'font': {'size': 16}},
            width=800 + len(categories) * 100,
            height=300 + len(formatted_data) * 40,
            margin=dict(l=20, r=20, t=60, b=20)
        )
        
        os.makedirs('data/comparisons/cross_model/tables', exist_ok=True)
        fig.write_html(f"data/comparisons/cross_model/tables/category_performance_{timestamp}.html")
        fig.write_image(f"data/comparisons/cross_model/tables/category_performance_{timestamp}.png", 
                       width=900 + len(categories) * 100, height=400 + len(formatted_data) * 40, scale=2)
        
        print(f"Saved: category_performance_{timestamp}.html")
        
        return fig
    
    def _get_response_data(self, result: Dict, model_name: str) -> Dict:
        """Extract response data based on model"""
        if model_name == 'deepseek':
            return result.get('deepseek_response', {})
        elif model_name == 'chatgpt':
            return result.get('chatgpt_response', {})
        elif model_name == 'gemini':
            return result.get('gemini_response', {})
        elif model_name == 'grok':
            return result.get('grok_response', {})
        return {}
    
    def _interpret_effect_size(self, d: float) -> str:
        """Interpret Cohen's d effect size"""
        if d < 0.2:
            return "Negligible"
        elif d < 0.5:
            return "Small"
        elif d < 0.8:
            return "Medium"
        else:
            return "Large"
# REFRESH_2026
