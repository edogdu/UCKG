# Generate Operator

The `GenerateService` is the final step in the GraphGen pipeline. It transforms structured Knowledge Graph communities into natural language Question-Answer (QA) pairs formatted for Supervised Fine-Tuning (SFT).

### Key Features:
1.  **Multiple Generation Modes**: Supports various cognitive levels—from simple atomic facts to complex multi-hop reasoning and Chain-of-Thought (CoT) scenarios.
2.  **Output Format Agnostic**: Can format the resulting data into industry-standard templates like Alpaca, ShareGPT, or ChatML.
3.  **Multimodal Awareness**: Includes specialized generators for VQA (Visual Question Answering) if image data is present in the community.
4.  **Parallel Execution**: Uses concurrent processing to generate thousands of Q&A pairs simultaneously, maximizing LLM throughput.

### Parameters:
- `method`: The generation strategy (`atomic`, `multi_hop`, `aggregated`, `vqa`, `cot`, etc.).
- `data_format`: The output schema (`Alpaca`, `Sharegpt`, `ChatML`).

### Output Schema (e.g., ShareGPT):
```json
{
  "conversations": [
    {"from": "human", "value": "How do I mitigate BlueSmacking attacks?"},
    {"from": "gpt", "value": "BlueSmacking is a DoS attack... the primary mitigation is..."}
  ]
}
```
