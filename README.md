# LLM-Java-SVR-Benchmark
[![Dataset](https://img.shields.io/badge/Dataset-2,362%20samples-blue)](https://github.com/oananbeh/LLM-Java-SVR-Benchmark/tree/main)
[![CWE Coverage](https://img.shields.io/badge/CWE%20Types-32-green)]()
[![Paper](https://img.shields.io/badge/Paper-Available-red)](https://github.com/oananbeh/LLM-Java-SVR-Benchmark/tree/main)

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
- **Programming Language:**  
  The programming language of the code (Java in this dataset).
- **Line Number:**  
  The line number(s) in the file where the vulnerability occurs.
- **Code Snippet:**  
  The code fragment containing the vulnerability, providing context for repair.
- **Exact Vulnerable Line:**  
  The specific line of code that contains the vulnerability.
- **Description:**  
  A description of the vulnerability and its security implications.

**Details:**  
- The dataset includes 2,362 validated Java vulnerabilities from 20 real-world projects, categorized across 32 distinct CWE types.
- Each entry is validated using automated tools (CodeQL and Snyk) and by security experts, ensuring high-confidence data.
- Enables reproducible research and fair, rigorous comparison of automated repair methods.

### 2. Open Source Projects Used in Evaluation

The following table summarizes the evaluated Java projects, along with their CVE identifiers, descriptions, and affected versions.

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

## Citation

If you use this repository or its datasets in your research, please cite:

```bibtex


```

