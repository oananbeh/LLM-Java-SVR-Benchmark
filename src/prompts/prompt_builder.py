"""
Prompt builder for all three prompting strategies used in the study:
  - One-Shot Baseline
  - Chain-of-Thought (CoT)
  - Retrieval-Augmented Generation (RAG)

Each builder takes a vulnerability record (dict from the CSV) and returns
a fully-formatted prompt string ready to send to an LLM.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class VulnerabilityRecord:
    cwe_id: str
    project_name: str
    vulnerable_file: str
    code_snippet: str
    exact_vulnerable_line: str
    description: str


class PromptBuilder:
    """
    Builds the three prompt variants described in the paper.
    """

    # ------------------------------------------------------------------
    # One-Shot Baseline (Section 3.3 of paper)
    # ------------------------------------------------------------------

    @staticmethod
    def one_shot(record: VulnerabilityRecord) -> str:
        """
        Minimal prompt: identify + fix, return only corrected code.
        Deliberately avoids examples so we measure raw pretrained knowledge.
        """
        return (
            f"You are a security expert specializing in Java vulnerability repair.\n\n"
            f"The following Java code contains a {record.cwe_id} vulnerability "
            f"in the project '{record.project_name}'.\n\n"
            f"Vulnerability Description:\n{record.description}\n\n"
            f"Vulnerable File: {record.vulnerable_file}\n\n"
            f"Code Snippet:\n```java\n{record.code_snippet}\n```\n\n"
            f"Exact Vulnerable Line:\n```java\n{record.exact_vulnerable_line}\n```\n\n"
            f"Task: Fix the {record.cwe_id} vulnerability in the code above. "
            f"Preserve the original functionality and return ONLY the corrected "
            f"code snippet without any explanation, comments, or markdown formatting."
        )

    # ------------------------------------------------------------------
    # Chain-of-Thought (CoT) (Section 3.3 of paper)
    # ------------------------------------------------------------------

    @staticmethod
    def chain_of_thought(record: VulnerabilityRecord) -> str:
        """
        Augments the one-shot prompt with an explicit reasoning instruction.
        Directs the model to analyse root cause before generating the fix.
        """
        return (
            f"You are a security expert specialising in Java vulnerability repair.\n\n"
            f"The following Java code contains a {record.cwe_id} vulnerability "
            f"in the project '{record.project_name}'.\n\n"
            f"Vulnerability Description:\n{record.description}\n\n"
            f"Vulnerable File: {record.vulnerable_file}\n\n"
            f"Code Snippet:\n```java\n{record.code_snippet}\n```\n\n"
            f"Exact Vulnerable Line:\n```java\n{record.exact_vulnerable_line}\n```\n\n"
            f"Instructions:\n"
            f"Step 1 — Analyse the vulnerability: identify the root cause of the "
            f"{record.cwe_id} issue and explain precisely what makes this code insecure.\n"
            f"Step 2 — Identify the repair strategy: describe the minimal, correct "
            f"change needed to eliminate the vulnerability without breaking functionality.\n"
            f"Step 3 — Generate the fix: produce the corrected Java code.\n\n"
            f"Format your response EXACTLY as:\n"
            f"ANALYSIS: <your analysis>\n"
            f"STRATEGY: <your repair strategy>\n"
            f"FIXED CODE:\n```java\n<corrected code only>\n```"
        )

    # ------------------------------------------------------------------
    # Retrieval-Augmented Generation (RAG) (Section 3.3 of paper)
    # ------------------------------------------------------------------

    @staticmethod
    def rag(record: VulnerabilityRecord,
            retrieved_vulnerable: str,
            retrieved_fixed: str,
            similarity_score: Optional[float] = None) -> str:
        """
        Enriches the prompt with a retrieved exemplar fix from CVEfixes.
        The exemplar is the top-1 CodeBERT cosine-similarity match.
        """
        sim_note = (
            f" (similarity score: {similarity_score:.4f})" if similarity_score else ""
        )
        return (
            f"You are a security expert specialising in Java vulnerability repair.\n\n"
            f"Below is a REFERENCE example of a similar vulnerability and its fix{sim_note}:\n\n"
            f"[Reference Vulnerable Code]\n```java\n{retrieved_vulnerable}\n```\n\n"
            f"[Reference Fixed Code]\n```java\n{retrieved_fixed}\n```\n\n"
            f"---\n\n"
            f"Now fix the following {record.cwe_id} vulnerability in the project "
            f"'{record.project_name}'.\n\n"
            f"Vulnerability Description:\n{record.description}\n\n"
            f"Vulnerable File: {record.vulnerable_file}\n\n"
            f"Code Snippet:\n```java\n{record.code_snippet}\n```\n\n"
            f"Exact Vulnerable Line:\n```java\n{record.exact_vulnerable_line}\n```\n\n"
            f"Task: Using the reference example as guidance, fix the {record.cwe_id} "
            f"vulnerability above. Preserve the original functionality and return ONLY "
            f"the corrected code snippet without any explanation, comments, or markdown "
            f"formatting."
        )

    # ------------------------------------------------------------------
    # Convenience factory
    # ------------------------------------------------------------------

    @classmethod
    def build(cls, strategy: str, record: VulnerabilityRecord,
              retrieved_vulnerable: Optional[str] = None,
              retrieved_fixed: Optional[str] = None,
              similarity_score: Optional[float] = None) -> str:
        """
        Factory method. strategy must be 'one_shot', 'cot', or 'rag'.
        For 'rag', retrieved_vulnerable and retrieved_fixed are required.
        """
        if strategy == "one_shot":
            return cls.one_shot(record)
        elif strategy == "cot":
            return cls.chain_of_thought(record)
        elif strategy == "rag":
            if retrieved_vulnerable is None or retrieved_fixed is None:
                raise ValueError("RAG strategy requires retrieved_vulnerable and retrieved_fixed.")
            return cls.rag(record, retrieved_vulnerable, retrieved_fixed, similarity_score)
        else:
            raise ValueError(f"Unknown strategy '{strategy}'. Use: 'one_shot', 'cot', 'rag'.")


def extract_fixed_code(llm_output: str, strategy: str) -> str:
    """
    Parse the LLM's raw output to extract the repaired code block.
    Handles:
      - Plain code returns (one_shot / rag)
      - CoT structured response with 'FIXED CODE:' marker
      - Markdown fenced blocks (```java ... ```)
    """
    if strategy == "cot":
        # Look for 'FIXED CODE:' section
        marker = "FIXED CODE:"
        if marker in llm_output:
            code_section = llm_output.split(marker, 1)[1].strip()
        else:
            code_section = llm_output
    else:
        code_section = llm_output

    # Strip markdown fences if present
    if "```" in code_section:
        lines = code_section.split("\n")
        inside = False
        extracted = []
        for line in lines:
            if line.strip().startswith("```"):
                if inside:
                    break
                inside = True
                continue
            if inside:
                extracted.append(line)
        return "\n".join(extracted).strip()

    return code_section.strip()
