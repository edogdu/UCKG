# Research References & Methodology Justification

This document outlines the theoretical basis for the data engineering decisions made in the UCKG Incident Response pipeline.

## 1. Methodology: High-Density "Atomic" Data
We chose to pack rich context (Techniques, Mitigations, Prerequisites) into single "Atomic" training samples rather than splitting them into fragmented Q&A pairs.

**Justification:**
This aligns with the **LIMA (Less Is More for Alignment)** hypothesis. Training on a small number of high-quality, information-dense examples allows the model to learn complex reasoning and associations better than training on a large number of shallow examples.

**Reference:**
> **LIMA: Less Is More for Alignment**
> *Zhou, C., Liu, P., Xu, P., Iyer, S., Sun, J., Mao, Y., ... & Levy, O. (2023). NeurIPS.*
> *Abstract:* "We show that a 65B parameter LLaMA model fine-tuned on only 1,000 carefully curated prompts and responses... produces responses that are competitive with or superior to GPT-4."
> *Relevance:* Supports our decision to use `limit=1000` with curated "Incident Response" triads.

## 2. Methodology: Curated Synthetic Data
We use a high-quality "Teacher" (Gemini/GPT-4) to synthesize textbook-quality explanations from structured knowledge graphs, rather than using raw graph dumps.

**Justification:**
Models trained on "textbook-quality" data outperform those trained on noisy or raw data. By synthesizing natural language from the graph before training, we create a higher-quality learning signal.

**Reference:**
> **Textbooks Are All You Need**
> *Gunasekar, S., Zhang, Y., Aneja, J., Mendes, C. C. T., Del Giorno, A., Gopi, S., ... & Dubey, S. (2023).*
> *Abstract:* "We demonstrate that for code generation, a model trained on textbook-quality data... can outperform state-of-the-art models."
> *Relevance:* Justifies our "Clean & Polish" step where we format JSON strings into readable, textbook-style descriptions.

## 3. Methodology: Knowledge Graph Grounding
We explicitly anchor the generation in a curated subgraph (CAPEC-ATT&CK-MITIGATION) to prevent hallucination.

**Justification:**
Retrieval-Augmented Generation (RAG) and Graph-Augmented Generation principles suggest that providing explicit relational context (A maps to B which is mitigated by C) enables the model to perform multi-hop reasoning even within a single turn.

**Reference:**
> **Retrieval-Augmented Generation for Knowledge-Intensive NLP Tasks**
> *Lewis, P., Perez, E., Piktus, A., Petroni, F., Karpukhin, V., Goyal, N., ... & Kiela, D. (2020). NeurIPS.*
> *Relevance:* Supports our "Graph-to-Text" injection strategy.
