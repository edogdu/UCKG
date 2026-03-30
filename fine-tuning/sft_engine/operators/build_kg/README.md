# Build KG Operator

The `BuildKGService` is the core "Knowledge Construction" component of GraphGen. It transforms unstructured text chunks into a structured Knowledge Graph (KG).

### Key Features:
1.  **Iterative Extraction**: Uses a multi-loop prompting strategy to ensure high recall of entities and relationships from complex text.
2.  **Entity Deduplication**: Automatically detects when multiple text chunks refer to the same entity and merges them into a single node.
3.  **Knowledge Summarization**: Uses an LLM to synthesize multiple conflicting or overlapping descriptions into a single, high-quality summary for each node and edge.
4.  **Traceability**: Maintains a mapping (`source_id`) between graph elements and the original text chunks they were derived from.
5.  **Multi-Modal Support**: Can extract relationships from non-text sources like images, tables, and formulas using Vision-Language Models (VLM).

### Parameters:
- `max_loop`: The number of times the LLM is prompted to "find more" info in the same chunk (default: 3).
- `graph_backend`: The database used to store the graph (default: `kuzu`).

### Logic Flow:
1.  **Extract**: LLM identifies (Source, Relation, Target) triples in text.
2.  **Normalize**: Standardizes entity names and types.
3.  **Merge**: Combines existing nodes with new data, updating descriptions.
4.  **Summarize**: Compresses long descriptions into concise "factoids".
5.  **Store**: Upserts to KuzuDB.
