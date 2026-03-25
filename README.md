# LLM-Java-SVR-Benchmark
[![Dataset](https://img.shields.io/badge/Dataset-2,362%20samples-blue)](https://github.com/oananbeh/LLM-Java-SVR-Benchmark/tree/main)
[![CWE Coverage](https://img.shields.io/badge/CWE%20Types-32-green)]()
[![Paper](https://img.shields.io/badge/Paper-Available-red)](https://github.com/oananbeh/LLM-Java-SVR-Benchmark/tree/main)

This repository accompanies the paper:

> **"Assessing the Effectiveness of Large Language Models for Java Vulnerability Repair: A Comparative Study"**

It contains the benchmark dataset, full experiment implementation, and baseline integrations for the comparative evaluation of ChatGPT-4, Claude 3.5 Sonnet, Gemini 2.0 Flash, and Llama 3.2 on automated Java vulnerability repair.

---

## Repository Structure

```
LLM-Java-SVR-Benchmark/
│
├── SVR-Benchmark.csv             ← 2,362 validated Java vulnerabilities (benchmark dataset)
│
├── src/
│   ├── inference/
│   │   └── llm_client.py         ← Unified LLM client (OpenAI, Anthropic, Google, Ollama)
│   ├── prompts/
│   │   └── prompt_builder.py     ← One-shot, CoT, and RAG prompt builders + output parser
│   ├── rag/
│   │   └── retrieval.py          ← CodeBERT cosine similarity retrieval for RAG
│   └── evaluation/
│       ├── metrics.py            ← Precision, Recall, F1, Fix Rate computation
│       └── validator.py          ← CodeQL + Snyk automated fix validation
│
├── baselines/
│   ├── repairllama/
│   │   └── run_repairllama.py    ← RepairLLaMA integration (Silva et al., 2023)
│   └── rapgen/
│       └── run_rapgen.py         ← RAP-Gen integration (Wang et al., 2023)
│
├── scripts/
│   ├── run_experiment.py         ← Main orchestration: runs all LLMs + baselines
│   └── compute_metrics.py        ← Generates all results tables from raw outputs
│
├── results/
│   ├── raw/                      ← Per-(model, strategy) JSON result files
│   └── metrics/                  ← Final CSV tables (overall, per-CWE, per-project)
│
├── data/
│   └── cvefixes_corpus.csv       ← 500-entry CVEfixes Java corpus for RAG retrieval
│
├── requirements.txt
└── .env.example                  ← API key and path configuration template
```

---

## Benchmark Dataset

**File:** `SVR-Benchmark.csv` — 2,362 validated Java vulnerabilities from 20 open-source projects, covering 32 distinct CWE types.

| Column | Description |
|--------|-------------|
| `CWE ID` | Common Weakness Enumeration identifier (e.g. CWE-89) |
| `Project Name` | Open-source Java project name |
| `Vulnerable File` | File path within the project |
| `Programming Language` | Java |
| `Line Number` | Line(s) where the vulnerability occurs |
| `Code Snippet` | Code fragment containing the vulnerability |
| `Exact Vulnerable Line` | The specific vulnerable line |
| `Description` | Description of the vulnerability and its security implications |

Each entry was confirmed by both CodeQL and Snyk; ambiguous cases were resolved by two domain experts following official CWE definitions.

---

## Evaluated Projects

| Project | CVE-ID | CWE | Description | Versions |
|---------|--------|-----|-------------|----------|
| eclipse-vertx | CVE-2019-17640 | CWE-22, 23 | Vert.x core offers event-driven, non-blocking functionalities for reactive apps. | ≥3.0.0, <3.9.4 |
| Apache Flink | CVE-2020-17518 | CWE-22, 23 | Framework for real-time stream and batch data processing. | ≥1.5.1, <1.11.3 |
| OpenTSDB | CVE-2020-35476 | CWE-78 | Distributed time series DB on HBase for large-scale metrics. | ≤2.4.0 |
| Apache Hadoop | CVE-2022-25168 | CWE-78, 88 | Distributed large dataset processing with MapReduce and HDFS. | ≥2.0.0, <2.10.2; ≥3.0.0-alpha, <3.2.4; ≥3.3.0, <3.3.3 |
| Netty | CVE-2022-41915 | CWE-113, 436 | Java framework for high-performance network apps. | ≥4.1.83.Final, <4.1.86.Final |
| Undertow | CVE-2018-1067 | CWE-113 | Flexible Java web server with blocking/non-blocking APIs. | ≤7.1.1.GA |
| wire | CVE-2021-41193 | CWE-134 | Secure messaging platform with pre-built WebRTC binaries. | ≤7.1.1.GA |
| Apache Dubbo | CVE-2021-36161 | CWE-134 | Java RPC framework for microservices communication. | <7.1.12 |
| Apache NiFi | CVE-2018-17195 | CWE-319, 863 | Automates data flow with routing and transformation. | <2.7.13 |
| James | CVE-2022-45935 | CWE-200, 319, 668 | Modular mail server with extensible components. | ≥1.0.0, ≤1.7.1 |
| Infinispan | CVE-2019-10174 | CWE-470 | In-memory key/value store with high availability. | ≤8.2.11.Final; ≥9.0.0.Final, ≤9.4.16.Final |
| HyperSQL | CVE-2022-41853 | CWE-470 | Java relational DBMS with in-memory and disk tables. | <2.7.1 |
| Apache Hive | CVE-2022-41137 | CWE-502 | SQL-like querying over Hadoop datasets. | 4.0.0-alpha-1 |
| Openmeetings | CVE-2024-54676 | CWE-502 | Video conferencing and collaborative editing. | ≥2.1.0, <8.0.0 |
| Eclipse GlassFish | CVE-2024-9329 | CWE-233, 601 | Jakarta EE-compliant application server. | ≥2.1.0, <8.0.0 |
| Keycloak | CVE-2024-8883 | CWE-601 | Identity and access management with SSO. | <7.0.17 |
| Hugegraph-toolchain | CVE-2024-27347 | CWE-918 | Tools for enhanced graph data management. | ≤22.0.12; ≥23.0.0, ≤24.0.7; ≥25.0.0, ≤25.0.5 |
| Apache CXF | CVE-2024-28752 | CWE-918 | Framework for SOAP and RESTful web services. | ≥1.0.0, <1.3.0 |
| FitNesse | CVE-2024-39610 | CWE-79 | Collaborative acceptance testing and verification. | <3.5.8; ≥3.6.0, <3.6.3; ≥4.0.0, <4.0.4 |
| OpenRefine | CVE-2024-47882 | CWE-79, 81 | Data cleaning and transformation tool. | <3.8 |

---

## Setup

### 1. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure API keys

```bash
cp .env.example .env
# Edit .env with your API keys and tool paths
```

### 3. Set up Llama 3.2 locally (Ollama)

```bash
# Install Ollama: https://ollama.com
ollama serve
ollama pull llama3.2
```

### 4. Prepare the CVEfixes RAG corpus

```bash
# Download CVEfixes DB from: https://zenodo.org/record/7029359
# Set CVEFIXES_DB=/path/to/CVEfixes.db in .env, then:
python -c "from src.rag.retrieval import prepare_cvefixes_corpus; prepare_cvefixes_corpus()"
```

### 5. Set up baselines (optional)

```bash
# RepairLLaMA — https://github.com/assert-kth/repairllama
git clone https://github.com/assert-kth/repairllama
# Set REPAIRLLAMA_ROOT in .env

# RAP-Gen — https://github.com/wang-weishi/RAP-Gen
git clone https://github.com/wang-weishi/RAP-Gen
# Set RAPGEN_ROOT in .env
```

---

## Running Experiments

```bash
# Full run — all LLMs × all strategies × 5 repetitions
python scripts/run_experiment.py

# Quick test — GPT-4, one-shot only, first 50 vulnerabilities
python scripts/run_experiment.py --models gpt-4 --strategies one_shot --n_runs 1 --limit 50

# Baselines only (RepairLLaMA + RAP-Gen)
python scripts/run_experiment.py --baselines_only

# Resume an interrupted run
python scripts/run_experiment.py --resume
```

Then generate all results tables:

```bash
python scripts/compute_metrics.py
```

Output files in `results/metrics/`: `overall_comparison.csv`, `prompting_strategies.csv`, `per_cwe_analysis.csv`, `per_project_analysis.csv`, `baseline_comparison.csv`, `variance_analysis.csv`.

---

## Evaluation Metrics

A fix is labelled **correct** only when both CodeQL and Snyk confirm the original CWE is no longer flagged **and** the project test suite still passes.

| Metric | Definition |
|--------|-----------|
| **Precision** | TP / (TP + FP) |
| **Recall** | TP / (TP + FN) |
| **F1-score** | Harmonic mean of precision and recall |
| **Fix Rate** | TP / total vulnerabilities in benchmark |

---

## Prompting Strategies

| Strategy | Description |
|----------|-------------|
| **One-Shot** | Minimal prompt; measures raw pretrained knowledge |
| **CoT** | Chain-of-Thought: model first analyses root cause, then generates fix |
| **RAG** | Top-1 CVEfixes exemplar retrieved via CodeBERT cosine similarity |

---

## Baselines

| Baseline | Architecture | Reference |
|----------|-------------|-----------|
| **RepairLLaMA** | Code Llama 7B + LoRA adapters | Silva et al. (2023) — [GitHub](https://github.com/assert-kth/repairllama) |
| **RAP-Gen** | CodeT5 + BM25 retrieval | Wang et al. (2023) — [GitHub](https://github.com/wang-weishi/RAP-Gen) |

---

## Citation

If you use this repository or its datasets in your research, please cite:

```bibtex
@article{anananbeh2025llmsvr,
  title   = {Assessing the Effectiveness of Large Language Models for Java
             Vulnerability Repair: A Comparative Study},
  author  = {Anananbeh, Obieda, Wala Alnozami and Dae-Kyoo Kim},
  journal = {},
  year    = {2026},
  url     = {https://github.com/oananbeh/LLM-Java-SVR-Benchmark}
}
```

---

## License

The benchmark dataset is released under **CC BY 4.0**. The implementation code is released under the **MIT License**.

