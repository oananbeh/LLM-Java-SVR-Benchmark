"""
Metrics Computation Script
============================
Loads raw FixResult JSON files from results/raw/ and produces:
  - results/metrics/overall_comparison.csv   (Table 4 in paper)
  - results/metrics/per_cwe_analysis.csv     (Table 6 / unfixed CWE analysis)
  - results/metrics/per_project_analysis.csv (project-level table)
  - results/metrics/prompting_strategies.csv (Table 5: strategy comparison)
  - results/metrics/baseline_comparison.csv  (Table 7: vs RepairLLaMA, RAP-Gen)
  - results/metrics/variance_analysis.csv    (Table: std across 5 runs)

Usage:
  python scripts/compute_metrics.py
  python scripts/compute_metrics.py --results_dir results/raw --output_dir results/metrics
"""

import sys
import json
import logging
import argparse
import pandas as pd
from pathlib import Path
from collections import defaultdict

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.evaluation.metrics import (
    FixResult, load_results, compute_metrics,
    compare_models, save_metrics_table,
)

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("compute_metrics")


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--results_dir", default=str(ROOT / "results" / "raw"))
    p.add_argument("--output_dir",  default=str(ROOT / "results" / "metrics"))
    p.add_argument("--total_vulns", type=int, default=2362)
    return p.parse_args()


def main():
    args = parse_args()
    results_dir = Path(args.results_dir)
    output_dir  = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # 1. Load all result files
    # ------------------------------------------------------------------
    all_results: dict[str, list[FixResult]] = {}
    for path in sorted(results_dir.glob("*.json")):
        try:
            results = load_results(str(path))
            if not results:
                continue
            key = path.stem   # e.g. "gpt-4_one_shot"
            all_results[key] = results
            logger.info("Loaded %d results from %s", len(results), path.name)
        except Exception as exc:
            logger.warning("Skipping %s: %s", path.name, exc)

    if not all_results:
        logger.error("No result files found in %s", results_dir)
        sys.exit(1)

    # ------------------------------------------------------------------
    # 2. Overall comparison table (all models × all strategies)
    # ------------------------------------------------------------------
    overall_df = compare_models(all_results, args.total_vulns)
    save_metrics_table(overall_df, str(output_dir / "overall_comparison.csv"))
    logger.info("Overall comparison table:\n%s", overall_df.to_string(index=False))

    # ------------------------------------------------------------------
    # 3. Prompting strategy comparison  (Table 5)
    # ------------------------------------------------------------------
    strategy_rows = []
    for key, results in all_results.items():
        if not results:
            continue
        model = results[0].model
        strategy = results[0].strategy
        if strategy not in ("one_shot", "cot", "rag"):
            continue
        metrics = compute_metrics(results, args.total_vulns)
        strategy_rows.append({
            "Model": model,
            "Strategy": strategy,
            "Precision (%)": metrics.precision,
            "Recall (%)": metrics.recall,
            "F1 (%)": metrics.f1,
            "Fix Rate (%)": metrics.fix_rate,
            "Std (%)": metrics.std_fix_rate,
        })
    if strategy_rows:
        strategy_df = pd.DataFrame(strategy_rows)
        strategy_df = strategy_df.sort_values(["Model", "Fix Rate (%)"],
                                               ascending=[True, False])
        save_metrics_table(strategy_df,
                           str(output_dir / "prompting_strategies.csv"))

    # ------------------------------------------------------------------
    # 4. Per-CWE analysis
    # ------------------------------------------------------------------
    cwe_rows = []
    for key, results in all_results.items():
        if not results:
            continue
        metrics = compute_metrics(results, args.total_vulns)
        for cwe, stats in metrics.per_cwe.items():
            cwe_rows.append({
                "Model": metrics.model,
                "Strategy": metrics.strategy,
                "CWE ID": cwe,
                "N Attempts": stats["n_attempts"],
                "N Correct": stats["n_correct"],
                "Fix Rate (%)": stats["fix_rate"],
            })
    if cwe_rows:
        cwe_df = pd.DataFrame(cwe_rows)
        cwe_df = cwe_df.sort_values(["CWE ID", "Fix Rate (%)"],
                                     ascending=[True, False])
        save_metrics_table(cwe_df, str(output_dir / "per_cwe_analysis.csv"))

    # ------------------------------------------------------------------
    # 5. Per-project analysis
    # ------------------------------------------------------------------
    proj_rows = []
    for key, results in all_results.items():
        if not results:
            continue
        metrics = compute_metrics(results, args.total_vulns)
        for project, stats in metrics.per_project.items():
            proj_rows.append({
                "Model": metrics.model,
                "Strategy": metrics.strategy,
                "Project": project,
                "N Attempts": stats["n_attempts"],
                "N Correct": stats["n_correct"],
                "Fix Rate (%)": stats["fix_rate"],
            })
    if proj_rows:
        proj_df = pd.DataFrame(proj_rows)
        proj_df = proj_df.sort_values(["Project", "Fix Rate (%)"],
                                       ascending=[True, False])
        save_metrics_table(proj_df, str(output_dir / "per_project_analysis.csv"))

    # ------------------------------------------------------------------
    # 6. Baseline comparison (Table 7)
    # ------------------------------------------------------------------
    llm_keys     = [k for k in all_results if not any(
        b in k for b in ["repairllama", "rapgen"])]
    baseline_keys = [k for k in all_results if any(
        b in k for b in ["repairllama", "rapgen"])]

    if baseline_keys:
        compare_keys = llm_keys + baseline_keys
        baseline_df  = compare_models(
            {k: all_results[k] for k in compare_keys},
            args.total_vulns,
        )
        save_metrics_table(baseline_df,
                           str(output_dir / "baseline_comparison.csv"))

    # ------------------------------------------------------------------
    # 7. Variance analysis (Table: std across 5 runs)
    # ------------------------------------------------------------------
    var_rows = []
    for key, results in all_results.items():
        if not results:
            continue
        metrics = compute_metrics(results, args.total_vulns)
        if metrics.std_fix_rate > 0:
            var_rows.append({
                "Model": metrics.model,
                "Strategy": metrics.strategy,
                "Fix Rate Mean (%)": metrics.fix_rate,
                "Fix Rate Std (%)": metrics.std_fix_rate,
                "N Runs": len(set(r.run_index for r in results)),
            })
    if var_rows:
        var_df = pd.DataFrame(var_rows)
        save_metrics_table(var_df, str(output_dir / "variance_analysis.csv"))

    logger.info("All metrics saved to %s", output_dir)


if __name__ == "__main__":
    main()
