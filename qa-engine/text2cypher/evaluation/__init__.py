"""
Evaluation module for Text2Cypher.

This module provides evaluation functionality for testing and benchmarking
the Text2Cypher system with different models and datasets.
"""

# IMPORTANT:
# Do not import submodules here.
# - Importing `text2cypher.evaluation` should be side-effect free.
# - Some scripts are executed via `python -m text2cypher.evaluation.<script>`,
#   which triggers this `__init__.py` before the script runs.
# - Wildcard imports here can accidentally execute heavy initialization paths
#   or fail if optional scripts are absent.

__all__ = []