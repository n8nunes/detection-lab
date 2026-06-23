# Threat Detection Lab

This **Threat Detection Lab** is a modular, production-grade, and privacy-focused CLI tool designed for security analysts and detection engineers. It provides a structured, phased framework to ingest, analyse, scan, enrich, and perform AI-assisted triage on system logs, all while adhering to strict architectural constraints regarding data privacy and bias.

## Core Purpose

The project serves as a foundational platform for learning and implementing modern detection engineering workflows. It is built to bridge the gap between raw log collection and actionable security intelligence by enforcing modularity and standardised data pipelines.

## Key Features & Phases

The tool is developed through a phased development roadmap:

* **Phase 1: Ingestion & Normalisation:** Converts diverse log formats (Windows EVTX, Linux Syslog, JSON) into a unified, normalised schema for consistent downstream processing.


* **Phase 2: Sigma Rule Engine:** Implements a high-performance, offline logic engine to evaluate normalised events against Sigma YAML rules, enabling rapid detection of adversarial patterns.


* **Phase 3: MITRE ATT&CK Mapping:** Automates the mapping of detected threats to the MITRE ATT&CK framework, providing coverage gap analysis and generating Navigator-compatible heatmap layers.


* **Phase 4: IOC Enrichment Pipeline:** Automatically extracts indicators of compromise (IOCs) and enriches them via external threat intelligence (AbuseIPDB and VirusTotal), utilising robust, de-obfuscation-ready extraction methods.


* **Phase 5: AI-Assisted Triage:** Employs a strictly constrained, single-pass Ollama integration to perform intelligent verdict assessment on matched alerts while maintaining robust safeguards against AI bias and data leakage.



## Design Principles

This lab prioritises security and engineering excellence:

* **Privacy-First:** The AI backend is never provided with raw, un-sanitised log data, IP addresses, or PII. It only receives pre-structured, anonymised summaries.


* **Modular Architecture:** Detection logic is strictly decoupled from the detection content (YAML rules), allowing users to curate their own rulesets without modifying the codebase.


* **Performance & Efficiency:** Through rigorous token management, atomic file I/O operations, and optimised regex extraction, the tool is designed to remain lightweight and highly performant.


* **Standardisation:** All outputs utilise the `Rich` library for clear, actionable terminal rendering, ensuring high visibility during incident triage.



## Getting Started

The project is designed to be self-contained for local laboratory environments. By following the documented phases, users can deploy a custom detection pipeline, validate it against simulated attack data, and eventually bridge it to real-world Windows Event Logs for comprehensive threat hunting.

---

Developed as a modular framework for professional detection engineering and GRC integration.
