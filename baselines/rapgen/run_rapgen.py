"""
RAP-Gen Baseline Integration
==============================
Wraps the RAP-Gen pipeline (Wang et al., 2023) for use in our
comparative evaluation against the four general-purpose LLMs.

Original repo : https://github.com/zimin9/RAP-Gen
Paper         : "RAP-Gen: Retrieval-Augmented Patch Generation with
                 CodeT5 for Automatic Program Repair" (Wang et al., 2023)

Architecture:
  - Retrieval : BM25 over a fix-pattern corpus to get top-k similar patches
  - Generator : CodeT5 conditioned on (buggy code + retrieved patches)
  - Training  : fine-tuned on Defects4J, Bears, and C/C++/Java CVE datasets

Setup (run once):
  git clone https://github.com/zimin9/RAP-Gen
  cd RAP-Gen && pip install -r requirements.txt
  # Download pre-built BM25 index and CodeT5 weights (see their README)

Usage:
  runner = RAPGenRunner(rapgen_root="/path/to/RAP-Gen")
  result = runner.repair("vuln_001", vulnerable_code, cwe_id, description)
"""

import os
import sys
import json
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)

RAPGEN_MODEL = os.environ.get(
    "RAPGEN_MODEL_ID", "Salesforce/codet5-large"
)
RAPGEN_CHECKPOINT = os.environ.get(
    "RAPGEN_CHECKPOINT", ""           # path to fine-tuned checkpoint if available
)


@dataclass
class RAPGenResult:
    vulnerability_id: str
    model: str = "rapgen"
    strategy: str = "retrieval-augmented"
    generated_fix: str = ""
    retrieved_patches: list = None
    retrieval_scores: list = None
    tokens_used: int = 0
    error: Optional[str] = None

    def __post_init__(self):
        if self.retrieved_patches is None:
            self.retrieved_patches = []
        if self.retrieval_scores is None:
            self.retrieval_scores = []


class RAPGenRunner:
    """
    Two modes:
      1. subprocess  — delegates to RAP-Gen's own run_repair.py
      2. hf_direct   — loads CodeT5 + BM25 index directly in-process
    """

    def __init__(self,
                 rapgen_root: Optional[str] = None,
                 corpus_path: Optional[str] = None,
                 mode: str = "hf_direct",
                 model_id: str = RAPGEN_MODEL,
                 checkpoint: str = RAPGEN_CHECKPOINT,
                 top_k_retrieve: int = 3,
                 device: Optional[str] = None,
                 max_new_tokens: int = 512):
        self.rapgen_root = Path(rapgen_root) if rapgen_root else None
        self.corpus_path = corpus_path
        self.mode = mode
        self.model_id = model_id
        self.checkpoint = checkpoint
        self.top_k = top_k_retrieve
        self.device = device
        self.max_new_tokens = max_new_tokens
        self._model = None
        self._tokenizer = None
        self._bm25_index = None
        self._corpus: Optional[list[dict]] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def repair(self,
               vulnerability_id: str,
               vulnerable_code: str,
               cwe_id: str,
               description: str = "") -> RAPGenResult:
        if self.mode == "subprocess":
            return self._repair_subprocess(
                vulnerability_id, vulnerable_code, cwe_id, description
            )
        else:
            return self._repair_hf(
                vulnerability_id, vulnerable_code, cwe_id, description
            )

    def repair_batch(self,
                     records: list[dict],
                     output_path: Optional[str] = None) -> list[RAPGenResult]:
        results = []
        for i, rec in enumerate(records):
            logger.info("[RAP-Gen] Processing %d/%d — %s",
                        i + 1, len(records), rec.get("vulnerability_id", "?"))
            result = self.repair(
                vulnerability_id=rec["vulnerability_id"],
                vulnerable_code=rec["code_snippet"],
                cwe_id=rec.get("cwe_id", ""),
                description=rec.get("description", ""),
            )
            results.append(result)

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump([vars(r) for r in results], f, indent=2, default=list)
            logger.info("Saved %d RAP-Gen results to %s", len(results), output_path)
        return results

    # ------------------------------------------------------------------
    # HuggingFace in-process mode
    # ------------------------------------------------------------------

    def _repair_hf(self, vulnerability_id: str, vulnerable_code: str,
                   cwe_id: str, description: str) -> RAPGenResult:
        try:
            self._load_model()
            self._load_index()

            # Step 1: BM25 retrieval of similar fix patterns
            retrieved = self._retrieve(vulnerable_code, self.top_k)

            # Step 2: Build CodeT5 input with retrieved context
            input_text = self._build_input(
                vulnerable_code, cwe_id, description, retrieved
            )

            # Step 3: Generate patch with CodeT5
            import torch
            inputs = self._tokenizer(
                input_text,
                return_tensors="pt",
                max_length=512,
                truncation=True,
            ).to(self.device or "cpu")

            with torch.no_grad():
                outputs = self._model.generate(
                    **inputs,
                    max_new_tokens=self.max_new_tokens,
                    num_beams=5,
                    early_stopping=True,
                )
            fixed_code = self._tokenizer.decode(
                outputs[0], skip_special_tokens=True
            ).strip()

            return RAPGenResult(
                vulnerability_id=vulnerability_id,
                generated_fix=fixed_code,
                retrieved_patches=[r["fixed_code"] for r in retrieved],
                retrieval_scores=[r["score"] for r in retrieved],
            )

        except Exception as exc:
            logger.error("[RAP-Gen] Error on %s: %s", vulnerability_id, exc)
            return RAPGenResult(
                vulnerability_id=vulnerability_id,
                error=str(exc),
            )

    def _load_model(self) -> None:
        if self._model is not None:
            return
        try:
            import torch
            from transformers import AutoTokenizer, T5ForConditionalGeneration

            logger.info("Loading CodeT5 model: %s", self.model_id)
            self.device = self.device or ("cuda" if torch.cuda.is_available() else "cpu")
            self._tokenizer = AutoTokenizer.from_pretrained(self.model_id)

            if self.checkpoint and Path(self.checkpoint).exists():
                logger.info("Loading fine-tuned checkpoint from %s", self.checkpoint)
                self._model = T5ForConditionalGeneration.from_pretrained(
                    self.checkpoint
                ).to(self.device)
            else:
                logger.warning(
                    "No fine-tuned checkpoint found. Using base CodeT5 — "
                    "repair quality will be lower than the fine-tuned RAP-Gen. "
                    "Set RAPGEN_CHECKPOINT env variable to the checkpoint path."
                )
                self._model = T5ForConditionalGeneration.from_pretrained(
                    self.model_id
                ).to(self.device)
        except ImportError as exc:
            raise ImportError(
                f"Missing dependencies for RAP-Gen: {exc}\n"
                "Install with: pip install transformers rank_bm25"
            )

    def _load_index(self) -> None:
        if self._bm25_index is not None:
            return
        try:
            from rank_bm25 import BM25Okapi
        except ImportError:
            raise ImportError("Install rank_bm25: pip install rank_bm25")

        if not self.corpus_path or not Path(self.corpus_path).exists():
            logger.warning(
                "RAP-Gen corpus not found at '%s'. "
                "Retrieval will be skipped (no-retrieval fallback). "
                "Set corpus_path to 'data/cvefixes_corpus.csv'.",
                self.corpus_path,
            )
            self._corpus = []
            self._bm25_index = None
            return

        import pandas as pd
        df = pd.read_csv(self.corpus_path)
        self._corpus = df.to_dict("records")
        tokenized = [doc["vulnerable_code"].split() for doc in self._corpus]
        self._bm25_index = BM25Okapi(tokenized)
        logger.info("BM25 index built for %d corpus entries.", len(self._corpus))

    def _retrieve(self, query_code: str, top_k: int) -> list[dict]:
        if self._bm25_index is None or not self._corpus:
            return []
        from rank_bm25 import BM25Okapi
        scores = self._bm25_index.get_scores(query_code.split())
        top_indices = sorted(range(len(scores)),
                             key=lambda i: scores[i], reverse=True)[:top_k]
        results = []
        for idx in top_indices:
            entry = dict(self._corpus[idx])
            entry["score"] = float(scores[idx])
            results.append(entry)
        return results

    @staticmethod
    def _build_input(vulnerable_code: str, cwe_id: str,
                     description: str, retrieved: list[dict]) -> str:
        """
        CodeT5 seq2seq input: concatenate buggy code + retrieved context.
        Follows RAP-Gen's input format (see their code/data preprocessing).
        """
        retrieved_block = ""
        for i, ex in enumerate(retrieved, start=1):
            retrieved_block += (
                f"\n[Retrieved Example {i}]\n"
                f"Buggy: {ex.get('vulnerable_code', '')}\n"
                f"Fixed: {ex.get('fixed_code', '')}\n"
            )
        return (
            f"fix {cwe_id} vulnerability: "
            f"{description} "
            f"<s> {vulnerable_code} </s>"
            f"{retrieved_block}"
        )

    # ------------------------------------------------------------------
    # Subprocess mode (calls RAP-Gen's run_repair.py directly)
    # ------------------------------------------------------------------

    def _repair_subprocess(self, vulnerability_id: str, vulnerable_code: str,
                            cwe_id: str, description: str) -> RAPGenResult:
        if not self.rapgen_root or not self.rapgen_root.exists():
            return RAPGenResult(
                vulnerability_id=vulnerability_id,
                error="rapgen_root not set or does not exist.",
            )

        run_script = self.rapgen_root / "run_repair.py"
        if not run_script.exists():
            run_script = self.rapgen_root / "src" / "run_repair.py"
        if not run_script.exists():
            return RAPGenResult(
                vulnerability_id=vulnerability_id,
                error=f"run_repair.py not found in {self.rapgen_root}",
            )

        with tempfile.NamedTemporaryFile(suffix=".java", mode="w", delete=False) as f:
            f.write(vulnerable_code)
            input_file = f.name

        output_file = input_file.replace(".java", "_fixed.java")

        try:
            cmd = [
                sys.executable, str(run_script),
                "--buggy_file", input_file,
                "--output_file", output_file,
                "--model", self.model_id,
                "--top_k", str(self.top_k),
                "--max_new_tokens", str(self.max_new_tokens),
            ]
            if self.corpus_path:
                cmd += ["--corpus", self.corpus_path]
            if self.checkpoint:
                cmd += ["--checkpoint", self.checkpoint]

            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=300, cwd=self.rapgen_root,
            )
            if result.returncode != 0:
                return RAPGenResult(
                    vulnerability_id=vulnerability_id,
                    error=result.stderr[:1000],
                )
            fixed_code = (Path(output_file).read_text()
                          if Path(output_file).exists() else "")
            return RAPGenResult(
                vulnerability_id=vulnerability_id,
                generated_fix=fixed_code,
            )
        except subprocess.TimeoutExpired:
            return RAPGenResult(
                vulnerability_id=vulnerability_id,
                error="RAP-Gen inference timed out.",
            )
        except Exception as exc:
            return RAPGenResult(
                vulnerability_id=vulnerability_id,
                error=str(exc),
            )
        finally:
            for path in [input_file, output_file]:
                if os.path.exists(path):
                    os.unlink(path)
