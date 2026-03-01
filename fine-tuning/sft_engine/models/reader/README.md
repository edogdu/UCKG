# GraphGen Readers

This directory contains implementations of file readers for various formats, all inheriting from `BaseReader`.

## JSONReader (`json_reader.py`)

The `JSONReader` handles structured data in `.json` (array of objects) or `.jsonl` (one object per line) formats.

### Logic Flow:
1.  **Mode Selection**:
    - **Simple Mode**: If only one modality is requested (e.g., text only), it uses `ray.data.read_json()` for high-performance, parallel reading. This assumes a consistent schema.
    - **Complex Mode**: If multiple modalities are requested (e.g., text + images), it falls back to a manual Python loop (`json.loads`) to handle heterogeneous schemas (e.g., some rows have image metadata, others don't).

2.  **Schema Unification (`_unify_schema`)**:
    - In Complex Mode, it checks if the `content` field is a nested dictionary (e.g., structured metadata). If so, it serializes it into a JSON string to ensure the `content` column remains a uniform string type.

3.  **Validation & Filtering**:
    - Applies `BaseReader._validate_batch` to ensure `type` and `content` columns exist.
    - Applies `BaseReader._should_keep_item` to filter out empty content or unsupported types.

### Expected Input Format:
```json
// Simple Text
{"type": "text", "content": "The quick brown fox..."}

// Multimodal (Complex)
{"type": "image", "content": "/path/to/image.jpg", "metadata": {"width": 1024}}
```
