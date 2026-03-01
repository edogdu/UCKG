# Partition Operator

The `PartitionService` is responsible for organizing the global Knowledge Graph into smaller, coherent "Communities" or "Subgraphs." This step ensures the LLM receives relevant context during the generation phase.

### Key Features:
1.  **Multiple Algorithms**: Supports topological grouping (Leiden, BFS, DFS) and educational grouping (ECE - Expected Calibration Error).
2.  **Context Optimization**: Groups related entities (e.g., an attack and its mitigation) together so the generator can create complex, multi-hop Q&A pairs.
3.  **Multimodal Enrichment**: Automatically retrieves binary data (like images) from the chunk storage and attaches it to graph nodes for VQA (Visual Question Answering) generation.
4.  **Traceability**: Maintains links back to the original source documents and chunks.

### Parameters:
- `method`: The partitioning algorithm (`leiden`, `ece`, `bfs`, `dfs`).
- `max_units_per_community`: Limits the size of each community to prevent exceeding the LLM's context window.

### Logic Flow:
1.  **Load Graph**: Reads the current state of KuzuDB.
2.  **Partition**: Runs the selected algorithm to find clusters of nodes.
3.  **Enrich**: Fetches supplemental data (images, full text) from RocksDB.
4.  **Yield**: Passes each community as a "Batch" to the Generator.
