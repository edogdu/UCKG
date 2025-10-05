from __future__ import annotations

def get_ontology(name: str = "connection"):
    """
    Returns an ontology object with the attributes validator expects:
      SUBJECT_TYPES, OBJECT_TYPES, PREDICATES, LITERAL_TYPES,
      ATTRIBUTE_PREDICATES, RELATION_PREDICATES,
      ALLOWED_RELATIONS, ALLOWED_ATTRIBUTES, PARENT_OF (optional)
    """
    if name.lower() == "connection":
        from .connection import get_config as _get
        onto = _get()
    elif name.lower() == "malont":
        # Only use if you actually have malont.get_config() in your project.
        from malont import get_config as _get
        onto = _get()
    else:
        raise ValueError(f"Unknown ontology '{name}'")

  
    if not hasattr(onto, "OBJECT_TYPES"):
        # sensible default: subjects ∪ literals
        setattr(onto, "OBJECT_TYPES", getattr(onto, "SUBJECT_TYPES") | getattr(onto, "LITERAL_TYPES"))
    if not hasattr(onto, "PARENT_OF"):
        setattr(onto, "PARENT_OF", {})

    return onto