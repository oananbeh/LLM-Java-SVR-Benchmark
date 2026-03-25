"""
RepairLLaMA Baseline Integration
=================================
Wraps the RepairLLaMA pipeline (Silva et al., 2023) for use in our
comparative evaluation against the four general-purpose LLMs.

Original repo : https://github.com/assert-kth/repairllama
Paper         : "RepairLLaMA: Efficient Representations and Fine-Tuned
                 Adapters for Program Repair" (Silva et al., 2023)

Architecture:
  - Base model : Code Llama 7B / 13B
  - Adapter    : LoRA fine-tuned on curated repair datasets (Defects4J,
                 Bears, HumanEval-Java, and security-focused subsets)
  - Input      : (buggy function, diff-style edit representation)
  - Output     : patched function

Setup (run once):
  git clone https://github.com/assert-kth/repairllama
  cd repairllama && pip install -r requirements.txt
  # Download adapter weights — see their README for HuggingFace model card

Usage:
  runner = RepairLLaMARunner(repairllama_root="/path/to/repairllama")
  result = runner.repair(vulnerable_code, cwe_id, description)
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

# HuggingFace model identifier for the fine-tuned RepairLLaMA adapter
# The authors release adapters at: https://huggingface.co/assert-kth/repairllama
REPAIRLLAMA_MODEL = os.environ.get(
    "REPAIRLLAMA_MODEL_ID", "assert-kth/repairllama-CodeLlama-7b-java"
)


@dataclass
class RepairLLaMAResult:
    vulnerability_id: str
    model: str = "repairllama"
    strategy: str = "fine-tuned"
    generated_fix: str = ""
    tokens_used: int = 0
    error: Optional[str] = None


class RepairLLaMARunner:
    """
    Two modes of operation:
      1. subprocess  — calls RepairLLaMA's inference script directly
                       (requires local clone of the repo)
      2. hf_direct   — loads adapter via HuggingFace transformers in-process
                       (simpler; requires GPU or quantised model)
    """

    def __init__(self,
                 repairllama_root: Optional[str] = None,
                 mode: str = "hf_direct",
                 model_id: str = REPAIRLLAMA_MODEL,
                 device: Optional[str] = None,
                 max_new_tokens: int = 512):
        self.repairllama_root = Path(repairllama_root) if repairllama_root else None
        self.mode = mode
        self.model_id = model_id
        self.device = device
        self.max_new_tokens = max_new_tokens
        self._pipeline = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def repair(self,
               vulnerability_id: str,
               vulnerable_code: str,
               cwe_id: str,
               description: str = "") -> RepairLLaMAResult:
        """
        Generate a patch for the given vulnerable Java code snippet.
        """
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
                     output_path: Optional[str] = None) -> list[RepairLLaMAResult]:
        """
        Batch repair. Each record must have keys:
          vulnerability_id, code_snippet, cwe_id, description
        """
        results = []
        for i, rec in enumerate(records):
            logger.info("[RepairLLaMA] Processing %d/%d — %s",
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
                json.dump([vars(r) for r in results], f, indent=2)
            logger.info("Saved %d RepairLLaMA results to %s",
                        len(results), output_path)
        return results

    # ------------------------------------------------------------------
    # HuggingFace in-process mode
    # ------------------------------------------------------------------

    def _repair_hf(self, vulnerability_id: str, vulnerable_code: str,
                   cwe_id: str, description: str) -> RepairLLaMAResult:
        try:
            self._load_pipeline()
            prompt = self._build_repair_prompt(vulnerable_code, cwe_id, description)
            outputs = self._pipeline(
                prompt,
                max_new_tokens=self.max_new_tokens,
                do_sample=False,
                temperature=None,
                top_p=None,
                pad_token_id=self._pipeline.tokenizer.eos_token_id,
            )
            # Extract only the newly generated tokens
            generated = outputs[0]["generated_text"][len(prompt):]
            fixed_code = self._parse_output(generated)
            return RepairLLaMAResult(
                vulnerability_id=vulnerability_id,
                generated_fix=fixed_code,
            )
        except Exception as exc:
            logger.error("[RepairLLaMA] Error on %s: %s", vulnerability_id, exc)
            return RepairLLaMAResult(
                vulnerability_id=vulnerability_id,
                error=str(exc),
            )

    def _load_pipeline(self) -> None:
        if self._pipeline is not None:
            return
        try:
            import torch
            from transformers import pipeline, AutoTokenizer, AutoModelForCausalLM
            from peft import PeftModel

            logger.info("Loading RepairLLaMA adapter: %s", self.model_id)
            device = self.device or ("cuda" if torch.cuda.is_available() else "cpu")

            base_model_id = "codellama/CodeLlama-7b-hf"
            tokenizer = AutoTokenizer.from_pretrained(base_model_id)
            base_model = AutoModelForCausalLM.from_pretrained(
                base_model_id,
                torch_dtype=torch.float16 if "cuda" in device else torch.float32,
                device_map="auto" if device == "cuda" else None,
                load_in_4bit=(device == "cpu"),   # quantise on CPU to fit in RAM
            )
            model = PeftModel.from_pretrained(base_model, self.model_id)
            model = model.merge_and_unload()

            self._pipeline = pipeline(
                "text-generation",
                model=model,
                tokenizer=tokenizer,
                device=0 if device == "cuda" else -1,
            )
        except ImportError as exc:
            raise ImportError(
                f"Missing dependencies for RepairLLaMA: {exc}\n"
                "Install with: pip install transformers peft accelerate bitsandbytes"
            )

    # ------------------------------------------------------------------
    # Subprocess mode (calls RepairLLaMA's own inference script)
    # ------------------------------------------------------------------

    def _repair_subprocess(self, vulnerability_id: str, vulnerable_code: str,
                            cwe_id: str, description: str) -> RepairLLaMAResult:
        if not self.repairllama_root or not self.repairllama_root.exists():
            return RepairLLaMAResult(
                vulnerability_id=vulnerability_id,
                error="repairllama_root not set or does not exist.",
            )

        inference_script = self.repairllama_root / "src" / "inference.py"
        if not inference_script.exists():
            # Try alternative path structure
            inference_script = self.repairllama_root / "inference.py"
        if not inference_script.exists():
            return RepairLLaMAResult(
                vulnerability_id=vulnerability_id,
                error=f"inference.py not found in {self.repairllama_root}",
            )

        with tempfile.NamedTemporaryFile(suffix=".java", mode="w",
                                         delete=False) as f:
            f.write(vulnerable_code)
            input_file = f.name

        output_file = input_file.replace(".java", "_fixed.java")

        try:
            cmd = [
                sys.executable, str(inference_script),
                "--input", input_file,
                "--output", output_file,
                "--model", self.model_id,
                "--max_new_tokens", str(self.max_new_tokens),
            ]
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=300, cwd=self.repairllama_root,
            )
            if result.returncode != 0:
                return RepairLLaMAResult(
                    vulnerability_id=vulnerability_id,
                    error=result.stderr[:1000],
                )
            fixed_code = (Path(output_file).read_text()
                          if Path(output_file).exists() else "")
            return RepairLLaMAResult(
                vulnerability_id=vulnerability_id,
                generated_fix=fixed_code,
            )
        except subprocess.TimeoutExpired:
            return RepairLLaMAResult(
                vulnerability_id=vulnerability_id,
                error="RepairLLaMA inference timed out.",
            )
        except Exception as exc:
            return RepairLLaMAResult(
                vulnerability_id=vulnerability_id,
                error=str(exc),
            )
        finally:
            for path in [input_file, output_file]:
                if os.path.exists(path):
                    os.unlink(path)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _build_repair_prompt(code: str, cwe_id: str, description: str) -> str:
        """
        Follows RepairLLaMA's CodeLlama instruction format.
        The model was fine-tuned with this structure.
        """
        return (
            f"[INST] Fix the following {cwe_id} vulnerability in this Java code.\n\n"
            f"Vulnerability: {description}\n\n"
            f"Buggy code:\n```java\n{code}\n```\n\n"
            f"Return only the fixed code. [/INST]\n"
        )

    @staticmethod
    def _parse_output(raw: str) -> str:
        """Strip instruction tags and extract code block if present."""
        # Remove any residual [INST]...[/INST] wrappers
        raw = raw.replace("[INST]", "").replace("[/INST]", "").strip()
        if "```" in raw:
            lines, inside, code_lines = raw.split("\n"), False, []
            for line in lines:
                if line.strip().startswith("```"):
                    if inside:
                        break
                    inside = True
                    continue
                if inside:
                    code_lines.append(line)
            return "\n".join(code_lines).strip()
        return raw.strip()
