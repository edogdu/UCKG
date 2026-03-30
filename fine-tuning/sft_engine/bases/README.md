# GraphGen Bases

This directory contains the abstract base classes that define the interfaces and shared logic for all GraphGen components.

## BaseReader (`base_reader.py`)

The `BaseReader` class is the foundation for all file readers (JSON, CSV, PDF, etc.). It enforces a strict schema to ensure downstream operators receive consistent data.

### Key Responsibilities:

1.  **Schema Validation (`_validate_batch`)**:
    - Ensures every batch of data has a `type` column.
    - If `type` is "text", it ensures a `content` column exists.
    - Raises a `ValueError` if these requirements are not met.

2.  **Data Filtering (`_should_keep_item`)**:
    - **Supported Types**: Checks if `type` is one of `["text", "image", "table", "equation", "protein", "dna", "rna"]`. Crashes if an unsupported type is found.
    - **Empty Content**: For text items, it drops rows where the `content` is empty or only whitespace.

3.  **Image Validation (`_image_exists`)**:
    - For image items, it verifies that the file path or URL actually exists and is accessible.

### Usage:
Subclasses (like `JSONReader`) inherit from `BaseReader` and implement the `read()` method. The `read()` method should load the raw data and then call `_validate_batch` and `_should_keep_item` to sanitize it.
