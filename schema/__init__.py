"""
schema
======
UCKG semantic schema package.

Single entry point for all schema operations:

    from schema.semantic_schema import update, extract_schema, extract_text

    update()                                    # push Cypher into Neo4j
    extract_schema(type="json", output="...")   # export schema to file
    extract_text(relation="hasCPE", limit=100)  # generate NL sentences
"""

from schema.semantic_schema import update, extract_schema, extract_text

__all__ = ["update", "extract_schema", "extract_text"]
