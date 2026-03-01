# Chunk Operator

The `ChunkService` is responsible for splitting long text documents into smaller, manageable pieces (chunks) suitable for LLM processing.

### Key Features:
1.  **Language Detection**: Automatically detects if the text is English or Chinese to use the appropriate splitting strategy.
2.  **Recursive Splitting**: Uses a recursive strategy that attempts to split text at natural boundaries (like paragraphs or sentences) rather than cutting words in half.
3.  **Token Counting**: Uses a `Tokenizer` (default: `cl100k_base`) to calculate the exact token length of each chunk, ensuring it fits within the LLM's context window.
4.  **Persistent Storage**: Chunks are saved in a key-value store (RocksDB) for fast retrieval and caching.

### Parameters:
- `chunk_size`: The maximum length of each chunk (default: 1024 characters).
- `chunk_overlap`: The number of characters to overlap between adjacent chunks (default: 100 characters).

### Output Schema:
Every chunk produced contains:
- `_chunk_id`: Unique identifier (hash).
- `content`: The text snippet.
- `length`: Token count.
- `_doc_id`: Reference to the source document.
- `language`: Detected language.
