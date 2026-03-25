"""
Main Experiment Orchestration Script
======================================
Runs the full comparative evaluation described in the paper:
  - 4 LLMs  × 3 strategies × 5 repetitions × 2,362 vulnerabilities
  - RepairLLaMA and RAP-Gen baselines (single run each)

Results are written to results/raw/ for each (model, strategy, run).
Call scripts/compute_metrics.py afterwards to generate the final tables.

Usage:
  # Run all four LLMs with all three strategies (5 repetitions each)
  python scripts/run_experiment.py --models all --strategies all

  # Run only GPT-4 with one-shot (quick sanity check)
  python scripts/run_experiment.py --models gpt-4 --strategies one_shot --n_runs 1

  # Run baselines only
  python scripts/run_experiment.py --baselines_only

  # Resume interrupted run (skips already-completed vuln IDs)
  python scripts/run_experiment.py --resume

Full run takes ~24 h with API rate limits; use --limit N for a subset.
"""

import os
import sys
import json
import logging
import argparse
import pandas as pd
from pathlib import Path
from datetime import datetime

# Repo root on sys.path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from src.inference.llm_client import LLMClient, SUPPORTED_MODELS
from src.prompts.prompt_builder import PromptBuilder, VulnerabilityRecord, extract_fixed_code
from src.rag.retrieval import RAGRetriever
from src.evaluation.metrics import FixResult, save_results
from baselines.repairllama.run_repairllama import RepairLLaMARunner
from baselines.rapgen.run_rapgen import RAPGenRunner

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(ROOT / "results" / "experiment.log"),
    ],
)
logger = logging.getLogger("run_experiment")

# ------------------------------------------------------------------
# Constants
# ------------------------------------------------------------------

DATASET_PATH = ROOT / "SVR-Benchmark.csv"
RAW_RESULTS_DIR = ROOT / "results" / "raw"
CORPUS_PATH = ROOT / "data" / "cvefixes_corpus.csv"
N_RUNS = 5
TOTAL_VULNS = 2362


def parse_args():
    p = argparse.ArgumentParser(description="LLM-Java-SVR Benchmark Experiment Runner")
    p.add_argument("--models", nargs="+",
                   default=["gpt-4", "claude-3-5-sonnet-20241022",
                            "gemini-2.0-flash", "llama3.2"],
                   help="Models to evaluate. Pass 'all' or specific model names.")
    p.add_argument("--strategies", nargs="+",
                   default=["one_shot", "cot", "rag"],
                   help="Prompting strategies: one_shot, cot, rag.")
    p.add_argument("--n_runs", type=int, default=N_RUNS,
                   help="Number of repetitions per vulnerability (default 5).")
    p.add_argument("--limit", type=int, default=None,
                   help="Limit to the first N vulnerabilities (for testing).")
    p.add_argument("--resume", action="store_true",
                   help="Skip vulnerability IDs already present in output files.")
    p.add_argument("--baselines_only", action="store_true",
                   help="Run RepairLLaMA and RAP-Gen baselines only.")
    p.add_argument("--llms_only", action="store_true",
                   help="Run LLM experiments only (skip baselines).")
    p.add_argument("--repairllama_root", default=None,
                   help="Path to RepairLLaMA repo clone.")
    p.add_argument("--rapgen_root", default=None,
                   help="Path to RAP-Gen repo clone.")
    p.add_argument("--projects_root", default=None,
                   help="Path to cloned Java project repos for validation.")
    p.add_argument("--codeql_db_root", default=None,
                   help="Path to pre-built CodeQL databases.")
    p.add_argument("--skip_validation", action="store_true",
                   help="Skip CodeQL/Snyk validation (mark all fixes as correct=unknown).")
    return p.parse_args()


# ------------------------------------------------------------------
# Data loading
# ------------------------------------------------------------------

def load_dataset(limit: int = None) -> list[dict]:
    df = pd.read_csv(DATASET_PATH)
    if limit:
        df = df.head(limit)
    records = []
    for idx, row in df.iterrows():
        records.append({
            "vulnerability_id": f"vuln_{idx:05d}",
            "cwe_id":           str(row.get("CWE ID", "")),
            "project_name":     str(row.get("Project Name", "")),
            "vulnerable_file":  str(row.get("Vulnerable File", "")),
            "code_snippet":     str(row.get("Code Snippet", "")),
            "exact_vulnerable_line": str(row.get("Exact Vulnerable Line", "")),
            "description":      str(row.get("Description", "")),
        })
    logger.info("Loaded %d vulnerability records.", len(records))
    return records


def load_completed_ids(output_path: Path) -> set[str]:
    if not output_path.exists():
        return set()
    with open(output_path) as f:
        data = json.load(f)
    return {r["vulnerability_id"] + f"_run{r['run_index']}" for r in data}


# ------------------------------------------------------------------
# LLM experiment loop
# ------------------------------------------------------------------

def run_llm_experiments(args, records: list[dict],
                        retriever: RAGRetriever = None) -> None:
    models = args.models
    if "all" in models:
        models = list(SUPPORTED_MODELS.keys())

    strategies = args.strategies
    if "all" in strategies:
        strategies = ["one_shot", "cot", "rag"]

    RAW_RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    for model_name in models:
        try:
            client = LLMClient(model=model_name)
        except Exception as exc:
            logger.error("Failed to initialise client for %s: %s", model_name, exc)
            continue

        for strategy in strategies:
            output_path = RAW_RESULTS_DIR / f"{model_name}_{strategy}.json"
            completed = load_completed_ids(output_path) if args.resume else set()
            session_results: list[FixResult] = []

            logger.info("=== %s | %s ===", model_name, strategy)

            for run_idx in range(1, args.n_runs + 1):
                for rec in records:
                    uid = rec["vulnerability_id"]
                    run_key = f"{uid}_run{run_idx}"
                    if run_key in completed:
                        continue

                    vuln = VulnerabilityRecord(
                        cwe_id=rec["cwe_id"],
                        project_name=rec["project_name"],
                        vulnerable_file=rec["vulnerable_file"],
                        code_snippet=rec["code_snippet"],
                        exact_vulnerable_line=rec["exact_vulnerable_line"],
                        description=rec["description"],
                    )

                    # Build prompt
                    retrieved_vuln = retrieved_fix = sim_score = None
                    if strategy == "rag" and retriever is not None:
                        hits = retriever.retrieve(rec["code_snippet"], top_k=1)
                        if hits:
                            retrieved_vuln = hits[0].vulnerable_code
                            retrieved_fix  = hits[0].fixed_code
                            sim_score      = hits[0].similarity

                    prompt = PromptBuilder.build(
                        strategy=strategy,
                        record=vuln,
                        retrieved_vulnerable=retrieved_vuln,
                        retrieved_fixed=retrieved_fix,
                        similarity_score=sim_score,
                    )

                    # Query the LLM
                    response = client.query(prompt, temperature=0.0, max_tokens=2048)

                    if response.error:
                        logger.warning("LLM error for %s run %d: %s",
                                       uid, run_idx, response.error)
                        generated_fix = ""
                        is_correct = False
                    else:
                        generated_fix = extract_fixed_code(response.output, strategy)
                        is_correct = _validate_or_skip(
                            args, rec, generated_fix
                        )

                    session_results.append(FixResult(
                        vulnerability_id=uid,
                        model=model_name,
                        strategy=strategy,
                        cwe_id=rec["cwe_id"],
                        project_name=rec["project_name"],
                        generated_fix=generated_fix,
                        is_correct=is_correct,
                        run_index=run_idx,
                        error=response.error,
                    ))

                    # Checkpoint every 50 records
                    if len(session_results) % 50 == 0:
                        save_results(session_results, str(output_path))

            save_results(session_results, str(output_path))
            logger.info("Saved %d results → %s", len(session_results), output_path)


# ------------------------------------------------------------------
# Baseline experiments
# ------------------------------------------------------------------

def run_baselines(args, records: list[dict]) -> None:
    RAW_RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    # --- RepairLLaMA ---
    logger.info("=== RepairLLaMA baseline ===")
    repairllama = RepairLLaMARunner(
        repairllama_root=args.repairllama_root,
        mode="subprocess" if args.repairllama_root else "hf_direct",
    )
    rl_results: list[FixResult] = []
    rl_out = RAW_RESULTS_DIR / "repairllama_fine-tuned.json"

    for rec in records:
        result = repairllama.repair(
            vulnerability_id=rec["vulnerability_id"],
            vulnerable_code=rec["code_snippet"],
            cwe_id=rec["cwe_id"],
            description=rec["description"],
        )
        is_correct = _validate_or_skip(args, rec, result.generated_fix)
        rl_results.append(FixResult(
            vulnerability_id=rec["vulnerability_id"],
            model="repairllama",
            strategy="fine-tuned",
            cwe_id=rec["cwe_id"],
            project_name=rec["project_name"],
            generated_fix=result.generated_fix,
            is_correct=is_correct,
            error=result.error,
        ))
    save_results(rl_results, str(rl_out))
    logger.info("RepairLLaMA done → %s", rl_out)

    # --- RAP-Gen ---
    logger.info("=== RAP-Gen baseline ===")
    rapgen = RAPGenRunner(
        rapgen_root=args.rapgen_root,
        corpus_path=str(CORPUS_PATH),
        mode="subprocess" if args.rapgen_root else "hf_direct",
    )
    rg_results: list[FixResult] = []
    rg_out = RAW_RESULTS_DIR / "rapgen_retrieval-augmented.json"

    for rec in records:
        result = rapgen.repair(
            vulnerability_id=rec["vulnerability_id"],
            vulnerable_code=rec["code_snippet"],
            cwe_id=rec["cwe_id"],
            description=rec["description"],
        )
        is_correct = _validate_or_skip(args, rec, result.generated_fix)
        rg_results.append(FixResult(
            vulnerability_id=rec["vulnerability_id"],
            model="rapgen",
            strategy="retrieval-augmented",
            cwe_id=rec["cwe_id"],
            project_name=rec["project_name"],
            generated_fix=result.generated_fix,
            is_correct=is_correct,
            error=result.error,
        ))
    save_results(rg_results, str(rg_out))
    logger.info("RAP-Gen done → %s", rg_out)


# ------------------------------------------------------------------
# Validation helper
# ------------------------------------------------------------------

def _validate_or_skip(args, rec: dict, generated_fix: str) -> bool:
    """
    If --skip_validation is set, return False (unknown) so that
    results can later be scored manually or by re-running with
    validation enabled. Otherwise call the full FixValidator.
    """
    if args.skip_validation or not generated_fix:
        return False

    if not args.projects_root or not args.codeql_db_root:
        logger.debug(
            "projects_root or codeql_db_root not set — skipping validation for %s",
            rec["vulnerability_id"],
        )
        return False

    from src.evaluation.validator import FixValidator
    validator = FixValidator(
        projects_root=args.projects_root,
        codeql_db_root=args.codeql_db_root,
    )
    result = validator.validate(
        vulnerability_id=rec["vulnerability_id"],
        project_name=rec["project_name"],
        vulnerable_file=rec["vulnerable_file"],
        original_code=rec["code_snippet"],
        generated_fix=generated_fix,
        cwe_id=rec["cwe_id"],
    )
    return result.is_correct


# ------------------------------------------------------------------
# Entry point
# ------------------------------------------------------------------

def main():
    args = parse_args()
    (ROOT / "results").mkdir(exist_ok=True)

    records = load_dataset(limit=args.limit)

    # Pre-build RAG index if needed
    retriever = None
    if not args.baselines_only and "rag" in args.strategies:
        if CORPUS_PATH.exists():
            retriever = RAGRetriever(corpus_path=str(CORPUS_PATH))
            retriever.build_index()
        else:
            logger.warning(
                "CVEfixes corpus not found at %s. "
                "RAG strategy will use empty context. "
                "Run: python src/rag/retrieval.py --prepare_corpus",
                CORPUS_PATH,
            )

    if not args.baselines_only:
        run_llm_experiments(args, records, retriever)

    if not args.llms_only:
        run_baselines(args, records)

    logger.info("Experiment complete. Run scripts/compute_metrics.py for results tables.")


if __name__ == "__main__":
    main()
