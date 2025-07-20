# LLM-Java-SVR-Benchmark

This repository accompanies the paper:  
**"Assessing the Effectiveness and Reliability of Large Language Models for Java Vulnerability Repair: A Comparative Case Study"**

## Overview

Automated Software Vulnerability Repair (SVR) is becoming essential as software systems grow in complexity and face increasing security threats. Large Language Models (LLMs) such as ChatGPT-4, Claude 3.5 Sonnet, Gemini 2.0 Flash, and Llama 3.2 have shown impressive capabilities in code-related tasks, but their effectiveness in repairing Java vulnerabilities has not been comprehensively benchmarked.  
This repository provides the datasets and resources used in our extensive comparative evaluation of these LLMs for Java vulnerability repair.

---

## Benchmark Datasets

### 1. LLM-Java-SVR Benchmark

**Purpose:**  
This is the raw dataset containing rows of Java code snippets and their associated vulnerabilities. It is designed for benchmarking and evaluating automated software vulnerability repair approaches.

**Dataset Columns:**  
- **CWE ID:**  
  The Common Weakness Enumeration identifier for the vulnerability (e.g., CWE-89 for SQL Injection).
- **Project Name:**  
  The open-source project from which the vulnerable code was collected.
- **Vulnerable File:**  
  The file name and path in the project containing the vulnerability.
- **Line Number:**  
  The line number(s) in the file where the vulnerability occurs.
- **Code Snippet:**  
  The code fragment containing the vulnerability, providing context for repair.
- **code_fix:**  
  The repaired version of the code snippet, representing the correct, secure fix.

**Details:**  
- The dataset includes 2,362 validated Java vulnerabilities from 20 real-world projects, categorized across 32 distinct CWE types.
- Each entry is validated using automated tools (CodeQL and Snyk) and by security experts, ensuring high-confidence data.
- Enables reproducible research and fair, rigorous comparison of automated repair methods.

---

## Citation

If you use this repository or its datasets in your research, please cite:

```bibtex


```

