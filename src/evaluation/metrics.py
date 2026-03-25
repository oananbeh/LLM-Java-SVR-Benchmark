"""
Evaluation metrics for LLM-based Java vulnerability repair.

Implements precision, recall, F1-score, and fix rate as defined
in Section 3.4 of the paper:

  Precision  = TP / (TP + FP)
  Recall     = TP / (TP + FN)
  F1-score   = 2 * (Precision * Recall) / (Precision + Recall)
  Fix Rate   = TP / Total vulnerabilities in benchmark

Where:
  TP  = generated fix correctly eliminates the vulnerability
  FP  = generated fix is invalid or introduces new issues
  FN  = vulnerability left unfixed by the model
"""

import json
import logging
import numpy as np
import pandas as pd
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class FixResult:
    """Outcome record for a single vulnerability repair attempt."""
    vulnerability_id: str          # unique row id from the dataset
    model: str
    strategy: str                  # one_shot | cot | rag
    cwe_id: str
    project_name: str
    generated_fix: str
    is_correct: bool               # set by validator
    codeql_clean: bool = False     # vulnerability removed by CodeQL
    snyk_clean: bool = False       # vulnerability removed by Snyk
    tests_passed: bool = False
    error: Optional[str] = None
    run_index: int = 1             # which of the 5 repetitions

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ModelMetrics:
    """Aggregated metrics for one model + strategy combination."""
    model: str
    strategy: str
    n_total: int
    n_correct: int      # TP
    n_incorrect: int    # FP
    n_unfixed: int      # FN
    precision: float
    recall: float
    f1: float
    fix_rate: float
    std_fix_rate: float = 0.0       # across 5 runs
    per_cwe: dict = field(default_factory=dict)
    per_project: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ------------------------------------------------------------------
# Core computation
# ------------------------------------------------------------------

def compute_metrics(results: list[FixResult],
                    total_vulnerabilities: Optional[int] = None) -> ModelMetrics:
    """
    Compute precision, recall, F1, and fix rate from a list of FixResult
    objects for a single (model, strategy) combination.

    results:               All FixResult records for one model+strategy.
                           If 5 repetitions were run, pass all 5*N records
                           and set n_runs=5 via the caller.
    total_vulnerabilities: Denominator for fix rate (paper uses the full 2,362).
                           If None, uses len(unique vulnerability IDs).
    """
    if not results:
        raise ValueError("results list is empty.")

    model = results[0].model
    strategy = results[0].strategy

    # Aggregate across repetitions: a vulnerability counts as fixed if it
    # was fixed in at least one run (conservative approach matches paper).
    by_vuln: dict[str, list[bool]] = defaultdict(list)
    by_cwe: dict[str, list[bool]] = defaultdict(list)
    by_project: dict[str, list[bool]] = defaultdict(list)

    for r in results:
        by_vuln[r.vulnerability_id].append(r.is_correct)
        by_cwe[r.cwe_id].append(r.is_correct)
        by_project[r.project_name].append(r.is_correct)

    # Per-vulnerability decision: correct if majority of runs are correct
    vuln_correct = {vid: np.mean(votes) >= 0.5 for vid, votes in by_vuln.items()}
    tp = sum(v for v in vuln_correct.values())
    fp = sum(1 for r in results
             if r.is_correct and not vuln_correct.get(r.vulnerability_id, False))
    fn = sum(1 for v, correct in vuln_correct.items() if not correct)

    n_unique = len(vuln_correct)
    n_total = total_vulnerabilities or n_unique

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) > 0 else 0.0)
    fix_rate = tp / n_total if n_total > 0 else 0.0

    # Fix rate std across repetitions (each run's fix_rate)
    run_fix_rates = _per_run_fix_rates(results, n_total)
    std_fix_rate = float(np.std(run_fix_rates)) if run_fix_rates else 0.0

    # Per-CWE summary
    per_cwe = _aggregate_group(by_cwe)
    per_project = _aggregate_group(by_project)

    return ModelMetrics(
        model=model,
        strategy=strategy,
        n_total=n_total,
        n_correct=int(tp),
        n_incorrect=int(fp),
        n_unfixed=int(fn),
        precision=round(precision * 100, 2),
        recall=round(recall * 100, 2),
        f1=round(f1 * 100, 2),
        fix_rate=round(fix_rate * 100, 2),
        std_fix_rate=round(std_fix_rate * 100, 2),
        per_cwe=per_cwe,
        per_project=per_project,
    )


def _per_run_fix_rates(results: list[FixResult], n_total: int) -> list[float]:
    by_run: dict[int, int] = defaultdict(int)
    for r in results:
        if r.is_correct:
            by_run[r.run_index] += 1
    if not by_run:
        return []
    # Deduplicate — one fix per vulnerability per run
    by_run_vuln: dict[int, set] = defaultdict(set)
    for r in results:
        if r.is_correct:
            by_run_vuln[r.run_index].add(r.vulnerability_id)
    return [len(vids) / n_total for vids in by_run_vuln.values()]


def _aggregate_group(group: dict[str, list[bool]]) -> dict:
    summary = {}
    for key, votes in group.items():
        n = len(votes)
        correct = sum(votes)
        summary[key] = {
            "n_attempts": n,
            "n_correct": correct,
            "fix_rate": round(correct / n * 100, 2) if n > 0 else 0.0,
        }
    return summary


# ------------------------------------------------------------------
# Multi-model comparison table
# ------------------------------------------------------------------

def compare_models(results_by_model: dict[str, list[FixResult]],
                   total_vulnerabilities: int = 2362) -> pd.DataFrame:
    """
    Build the comparison table shown in the paper (Table 4 / Table 5).

    results_by_model: { "gpt-4|one_shot": [FixResult, ...], ... }
    Returns a DataFrame with one row per (model, strategy).
    """
    rows = []
    for key, results in results_by_model.items():
        try:
            metrics = compute_metrics(results, total_vulnerabilities)
            rows.append({
                "Model": metrics.model,
                "Strategy": metrics.strategy,
                "Precision (%)": metrics.precision,
                "Recall (%)": metrics.recall,
                "F1-score (%)": metrics.f1,
                "Fix Rate (%)": metrics.fix_rate,
                "Fix Rate Std (%)": metrics.std_fix_rate,
                "TP": metrics.n_correct,
                "FP": metrics.n_incorrect,
                "FN": metrics.n_unfixed,
            })
        except Exception as exc:
            logger.error("Failed to compute metrics for %s: %s", key, exc)
    return pd.DataFrame(rows).sort_values(["Fix Rate (%)"], ascending=False)


# ------------------------------------------------------------------
# Persistence helpers
# ------------------------------------------------------------------

def save_results(results: list[FixResult], output_path: str) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump([r.to_dict() for r in results], f, indent=2)
    logger.info("Saved %d results to %s", len(results), output_path)


def load_results(input_path: str) -> list[FixResult]:
    with open(input_path) as f:
        data = json.load(f)
    return [FixResult(**d) for d in data]


def save_metrics_table(df: pd.DataFrame, output_path: str) -> None:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)
    logger.info("Saved metrics table to %s", output_path)
