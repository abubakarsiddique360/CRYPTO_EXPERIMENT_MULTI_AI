from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

import pandas as pd

from config.api_config import AIConfig
from config.output_paths import results_dir
from experiment_design.plaintext_recovery_generator import generate_plaintext_recovery_cases
from experiment_design.ai_algorithm_hidden_shuffler import AIAlgorithmHiddenShuffler
from evaluators.plaintext_recovery_evaluator import PlaintextRecoveryEvaluator
from evaluators.algorithm_hidden_evaluator import AlgorithmHiddenEvaluator

from visualization.performance_charts import PerformanceCharts
from visualization.algorithm_informed_table_generator import AlgorithmInformedTableGenerator
from visualization.algorithm_hidden_performance_charts import AlgorithmHiddenPerformanceCharts
from visualization.algorithm_hidden_table_generator import AlgorithmHiddenTableGenerator

from ai_clients.deepseek_client import DeepSeekCryptanalyst
from ai_clients.chatgpt_client import ChatGPTCryptanalyst
from ai_clients.grok_client import GrokCryptanalyst
from ai_clients.gemini_client import GeminiCryptanalyst


_CLIENTS = {
    "deepseek": (DeepSeekCryptanalyst, "DEEPSEEK_API_KEY"),
    "chatgpt": (ChatGPTCryptanalyst, "OPENAI_API_KEY"),
    "grok": (GrokCryptanalyst, "GROK_API_KEY"),
    "gemini": (GeminiCryptanalyst, "GEMINI_API_KEY"),
}


def _now_ts() -> str:
    return datetime.now().strftime('%Y%m%d_%H%M%S')


def _metrics_from_results(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not results:
        return {
            "total_tests": 0,
            "successful_responses": 0,
            "success_rate": 0.0,
            "overall_score": 0.0,
            "category_metrics": {},
            "algorithm_metrics": {},
            "difficulty_metrics": {},
        }

    total = len(results)
    successful = sum(1 for r in results if any((k.endswith('_response') and isinstance(r.get(k), dict) and r[k].get('success')) for k in r.keys()))

    def _group_avg(key_fn):
        buckets: Dict[str, List[float]] = {}
        for r in results:
            tc = r.get('test_case', {})
            ev = r.get('evaluation', {})
            k = key_fn(tc)
            buckets.setdefault(k, []).append(float(ev.get('overall_score', 0.0) or 0.0))
        out = {}
        for k, vals in buckets.items():
            out[k] = {"average_score": sum(vals) / len(vals) if vals else 0.0, "test_count": len(vals)}
        return out

    overall_vals = [float(r.get('evaluation', {}).get('overall_score', 0.0) or 0.0) for r in results]

    return {
        "total_tests": total,
        "successful_responses": successful,
        "success_rate": (successful / total) if total else 0.0,
        "overall_score": sum(overall_vals) / len(overall_vals) if overall_vals else 0.0,
        "category_metrics": _group_avg(lambda tc: tc.get('category', 'unknown')),
        "algorithm_metrics": _group_avg(lambda tc: tc.get('algorithm', 'unknown')),
        "difficulty_metrics": _group_avg(lambda tc: tc.get('difficulty', 'unknown')),
    }


@dataclass
class RunConfig:
    platform: str
    condition: str
    per_algorithm: int = 60
    include_substitution: bool = True
    seed: int = 42
    batch_size: int = 20
    concurrent_requests: int = 2
    batch_delay: float = 2.0


class PlaintextRecoveryExperiment:
    def __init__(self, run_cfg: RunConfig):
        self.run_cfg = run_cfg
        self.platform = run_cfg.platform
        self.condition = run_cfg.condition

        self.timestamp = _now_ts()

        self.out_dir = results_dir(self.platform, self.condition)
        self.raw_dir = results_dir(self.platform, self.condition, 'raw_results')
        self.summary_dir = results_dir(self.platform, self.condition, 'experiment_summary')

        self.results: List[Dict[str, Any]] = []
        self.metrics: Dict[str, Any] = {}

    def _get_api_key(self) -> str:
        cfg = AIConfig()
        _, env_name = _CLIENTS[self.platform]
        # Prefer AIConfig fields; fall back to raw env var
        return getattr(cfg, env_name, '') or os.getenv(env_name, '')

    def _make_client(self):
        client_cls, _ = _CLIENTS[self.platform]
        client = client_cls(self._get_api_key())

        # Apply per-provider throttles if available
        cfg = AIConfig()
        rpm_attr = f"{self.platform.upper()}_REQUESTS_PER_MINUTE"
        if hasattr(cfg, rpm_attr):
            try:
                client.requests_per_minute = int(getattr(cfg, rpm_attr))
            except Exception:
                pass

        return client

    def _generate_cases(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
        cases = generate_plaintext_recovery_cases(
            per_algorithm=self.run_cfg.per_algorithm,
            seed=self.run_cfg.seed,
            include_substitution=self.run_cfg.include_substitution,
        )

        if self.condition == 'algorithm_hidden':
            shuffler = AIAlgorithmHiddenShuffler(cases)
            shuffled = shuffler.shuffle_with_stratification(seed=self.run_cfg.seed)

            # Attach original test-case metadata for evaluation & reporting
            eval_cases: List[Dict[str, Any]] = []
            for c in shuffled:
                info = shuffler.mapping.get(c['test_id'], {})
                original = info.get('original_case', {})
                eval_cases.append(
                    {
                        **c,
                        "algorithm": info.get('algorithm', 'unknown'),
                        "category": info.get('category', 'unknown'),
                        "difficulty": info.get('difficulty', 'unknown'),
                        "original_test_case": original,
                    }
                )

            return eval_cases, shuffler.mapping

        return cases, {}

    async def run(self) -> Tuple[List[Dict[str, Any]], Dict[str, Any], Path]:
        if self.platform not in _CLIENTS:
            raise ValueError(f"Unsupported platform: {self.platform}")

        api_key = self._get_api_key()
        if not api_key:
            _, env_name = _CLIENTS[self.platform]
            raise RuntimeError(f"Missing API key. Set environment variable: {env_name}")

        client = self._make_client()
        if not client.validate_api_key():
            raise RuntimeError("API key validation failed")

        test_cases, mapping = self._generate_cases()

        # Pick evaluator
        if self.condition == 'algorithm_hidden':
            evaluator = AlgorithmHiddenEvaluator(
                identification_weight=0.15,
                category_weight=0.05,
                decryption_weight=0.7,
                vulnerability_weight=0.05,
                reasoning_weight=0.05,
            )
        else:
            evaluator = PlaintextRecoveryEvaluator()

        batch_size = int(self.run_cfg.batch_size)
        total_batches = (len(test_cases) + batch_size - 1) // batch_size

        async with client as analyst:
            for batch_num in range(total_batches):
                start_idx = batch_num * batch_size
                end_idx = min(start_idx + batch_size, len(test_cases))
                batch = test_cases[start_idx:end_idx]

                # For the hidden condition, we must send the anonymized case to the model
                # (i.e., without the attached original_test_case + algorithm fields).
                if self.condition == 'algorithm_hidden':
                    to_send = [
                        {"test_id": tc["test_id"], "encrypted_data": tc["encrypted_data"], "algorithm_hidden": True}
                        for tc in batch
                    ]
                else:
                    # Send only the minimum required fields to the model (do NOT send plaintext).
                    to_send = [
                        {
                            "test_id": tc.get("test_id", ""),
                            "encrypted_data": tc.get("encrypted_data", {}),
                            "algorithm": tc.get("algorithm", "unknown"),
                        }
                        for tc in batch
                    ]

                # Mission marker for the prompt factory
                for tc in to_send:
                    tc.setdefault('mission', 'plaintext_recovery')

                # Run model calls
                batch_results = await analyst.batch_analyze(
                    to_send,
                    concurrent_requests=int(self.run_cfg.concurrent_requests),
                )

                for tc_eval, resp in zip(batch, batch_results):
                    # ensure prompt routing
                    resp.parsed_data = resp.parsed_data or {}

                    evaluation = evaluator.evaluate_cryptanalysis(resp, tc_eval) if hasattr(evaluator, 'evaluate_cryptanalysis') else evaluator.evaluate(resp, tc_eval)

                    self.results.append(
                        {
                            "test_case": tc_eval,
                            f"{self.platform}_response": {
                                "success": bool(resp.success),
                                "error": resp.error,
                                "parsed_data": resp.parsed_data,
                            },
                            "evaluation": evaluation,
                        }
                    )

                # progress marker
                progress = {
                    "batch": batch_num + 1,
                    "timestamp": datetime.now().isoformat(),
                    "results_so_far": len(self.results),
                }
                (self.summary_dir / f"experiment_progress_batch_{batch_num+1}_{self.timestamp}.json").write_text(
                    json.dumps(progress, indent=2, ensure_ascii=False),
                    encoding='utf-8',
                )

                if batch_num < total_batches - 1 and float(self.run_cfg.batch_delay) > 0:
                    await asyncio.sleep(float(self.run_cfg.batch_delay))

        self.metrics = _metrics_from_results(self.results)

        raw_path = self._write_raw_results(mapping)
        self._write_csv(self.timestamp)
        self._write_artifacts(raw_path)

        return self.results, self.metrics, raw_path

    def _write_raw_results(self, mapping: Dict[str, Any]) -> Path:
        payload = {
            "metadata": {
                "platform": self.platform,
                "condition": self.condition,
                "mission": "plaintext_recovery",
                "timestamp": self.timestamp,
                "per_algorithm": self.run_cfg.per_algorithm,
                "include_substitution": self.run_cfg.include_substitution,
                "seed": self.run_cfg.seed,
            },
            "metrics": self.metrics,
            "results": self.results,
        }
        if mapping:
            payload["metadata"]["hidden_mapping_included"] = True

        raw_path = self.raw_dir / f"{self.platform}_{self.condition}_raw_results_{self.timestamp}.json"
        raw_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding='utf-8')
        return raw_path

    def _write_csv(self, timestamp: str) -> None:
        rows = []
        for r in self.results:
            tc = r.get('test_case', {})
            ev = r.get('evaluation', {})
            resp = r.get(f'{self.platform}_response', {})

            # hidden evaluator uses different key names; normalize
            vuln = ev.get('vulnerability_detection_score', ev.get('vulnerability_score', 0.0))
            dec = ev.get('decryption_success_score', ev.get('decryption_score', 0.0))
            rea = ev.get('reasoning_quality_score', ev.get('reasoning_score', 0.0))
            conf = ev.get('confidence_score', ev.get('confidence', 0.0))

            row = {
                'test_id': tc.get('test_id', ''),
                'algorithm': tc.get('algorithm', 'unknown'),
                'category': tc.get('category', 'unknown'),
                'difficulty': tc.get('difficulty', 'unknown'),
                'response_success': bool(resp.get('success')),
                'overall_score': float(ev.get('overall_score', 0.0) or 0.0),
            }

            # Only the hidden condition needs algorithm-identification columns
            if self.condition == 'algorithm_hidden':
                row['identified_algorithm'] = ev.get('identified_algorithm', '')
                row['identified_algorithm_score'] = float(ev.get('identified_algorithm_score', 0.0) or 0.0)
                row['identified_category'] = ev.get('identified_category', '') or ''
                row['identified_category_score'] = float(ev.get('identified_category_score', 0.0) or 0.0)
                row['exact_match'] = bool(ev.get('exact_match', False))
                row['category_match'] = bool(ev.get('category_match', False))

            row.update({
                'vulnerability_score': float(vuln or 0.0),
                'decryption_score': float(dec or 0.0),
                'reasoning_score': float(rea or 0.0),
                'confidence': float(conf or 0.0),
            })

            rows.append(row)

        df = pd.DataFrame(rows)
        out = results_dir(self.platform, self.condition) / f"{self.condition}_experiment_summary_{timestamp}.csv"
        df.to_csv(str(out), index=False, encoding='utf-8-sig')

    def _write_artifacts(self, raw_path: Path) -> None:
        if self.condition == 'algorithm_hidden':
            AlgorithmHiddenPerformanceCharts().create_three_charts(self.results, self.timestamp, output_dir=self.out_dir)
            AlgorithmHiddenTableGenerator(platform=self.platform, condition=self.condition).run(raw_path)
            return

        PerformanceCharts().create_comprehensive_dashboard(self.results, self.metrics, self.timestamp, output_dir=self.out_dir)
        AlgorithmInformedTableGenerator(platform=self.platform, condition=self.condition).run(raw_path)

