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
    Builds the three prompt variants described in the paper (Section 3.3).

    All templates are reproduced verbatim from the paper's prompt boxes.
    Placeholders map as follows:
      {CWE-ID: CWE Name}  → "{record.cwe_id}: {record.description}"
                            (the dataset Description column is the vulnerability
                            description that contextualises the CWE type, matching
                            what Section 3.5 calls "a brief vulnerability description")
      {Vulnerable Code}   → record.code_snippet
    """

    # ------------------------------------------------------------------
    # One-Shot Baseline (Section 3.3 of paper)
    # Paper template (verbatim):
    #   "The following Java code contains a vulnerability of type
    #    {CWE-ID: CWE Name}. Please fix the vulnerability while
    #    preserving the intended functionality of the code.
    #    Return only the fixed code.
    #    {Vulnerable Code}"
    # ------------------------------------------------------------------

    @staticmethod
    def one_shot(record: VulnerabilityRecord) -> str:
        cwe_label = f"{record.cwe_id}: {record.description}"
        return (
            f"The following Java code contains a vulnerability of type "
            f"{cwe_label}. "
            f"Please fix the vulnerability while preserving the intended "
            f"functionality of the code. Return only the fixed code.\n\n"
            f"{record.code_snippet}"
        )

    # ------------------------------------------------------------------
    # Chain-of-Thought (CoT) (Section 3.3 of paper)
    # Paper template (verbatim):
    #   "The following Java code contains a vulnerability of type
    #    {CWE-ID: CWE Name}. First, explain the root cause of this
    #    vulnerability and describe the repair strategy. Then, provide
    #    the fixed code that addresses the vulnerability while preserving
    #    the intended functionality. Return the analysis followed by the
    #    fixed code.
    #    {Vulnerable Code}"
    # ------------------------------------------------------------------

    @staticmethod
    def chain_of_thought(record: VulnerabilityRecord) -> str:
        cwe_label = f"{record.cwe_id}: {record.description}"
        return (
            f"The following Java code contains a vulnerability of type "
            f"{cwe_label}. "
            f"First, explain the root cause of this vulnerability and describe "
            f"the repair strategy. Then, provide the fixed code that addresses "
            f"the vulnerability while preserving the intended functionality. "
            f"Return the analysis followed by the fixed code.\n\n"
            f"{record.code_snippet}"
        )

    # ------------------------------------------------------------------
    # Retrieval-Augmented Generation (RAG) (Section 3.3 of paper)
    # Paper template (verbatim):
    #   "The following Java code contains a vulnerability of type
    #    {CWE-ID: CWE Name}. Below is an example of a similar
    #    vulnerability and its fix for reference:
    #    [Example Vulnerable Code]
    #    [Example Fixed Code]
    #    Now fix the following vulnerable code while preserving the
    #    intended functionality. Return only the fixed code.
    #    {Vulnerable Code}"
    # ------------------------------------------------------------------

    @staticmethod
    def rag(record: VulnerabilityRecord,
            retrieved_vulnerable: str,
            retrieved_fixed: str,
            similarity_score: Optional[float] = None) -> str:
        cwe_label = f"{record.cwe_id}: {record.description}"
        return (
            f"The following Java code contains a vulnerability of type "
            f"{cwe_label}. "
            f"Below is an example of a similar vulnerability and its fix "
            f"for reference:\n\n"
            f"[Example Vulnerable Code]\n{retrieved_vulnerable}\n\n"
            f"[Example Fixed Code]\n{retrieved_fixed}\n\n"
            f"Now fix the following vulnerable code while preserving the "
            f"intended functionality. Return only the fixed code.\n\n"
            f"{record.code_snippet}"
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

    For one_shot and rag: the paper instructs "Return only the fixed code",
    so the entire output IS the code (possibly wrapped in a markdown fence).

    For cot: the paper instructs "Return the analysis followed by the fixed
    code" — no rigid markers. We extract the LAST code block in the output,
    which is consistently where the generated fix appears after the analysis
    prose. If no code block is present, we take everything after the last
    paragraph break as a best-effort extraction.
    """
    if strategy == "cot":
        # Extract the last ```...``` block, which follows the analysis prose
        code_section = _extract_last_code_block(llm_output)
        if code_section:
            return code_section
        # Fallback: take text after the last double-newline (last paragraph)
        parts = llm_output.strip().rsplit("\n\n", 1)
        return parts[-1].strip()
    else:
        # one_shot / rag: full output is the fix (strip fences if present)
        code_section = _extract_last_code_block(llm_output)
        return code_section if code_section else llm_output.strip()


def _extract_last_code_block(text: str) -> str:
    """
    Extract the content of the last fenced code block (``` ... ```) in text.
    Returns empty string if no fence is found.
    """
    if "```" not in text:
        return ""
    blocks = []
    lines = text.split("\n")
    inside = False
    current: list[str] = []
    for line in lines:
        if line.strip().startswith("```"):
            if inside:
                blocks.append("\n".join(current).strip())
                current = []
                inside = False
            else:
                inside = True
        elif inside:
            current.append(line)
    # In case the closing fence is missing
    if inside and current:
        blocks.append("\n".join(current).strip())
    return blocks[-1] if blocks else ""
