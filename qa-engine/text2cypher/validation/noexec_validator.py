from typing import List, Tuple, Dict, Any

from neo4j.exceptions import CypherSyntaxError
import regex as re
from .utils.regex_patterns import (
    get_node_pattern,
    get_relationship_pattern,
    get_node_variable_pattern,
    get_relationship_variable_pattern,
    get_property_pattern,
    get_node_label_pattern,
    get_relationship_type_pattern,
    get_variable_operator_property_pattern,
)


WRITE_CLAUSES = {
    "CREATE",
    "MERGE",
    "DELETE",
    "DETACH DELETE",
    "SET",
    "REMOVE",
    "FOREACH",
    "LOAD CSV",
    "CALL dbms",
}


def _has_write_clauses(cypher: str) -> List[str]:
    upper_q = cypher.upper()
    return [wc for wc in WRITE_CLAUSES if wc in upper_q]


def _check_syntax(driver, cypher: str) -> List[str]:
    errors: List[str] = []
    try:
        with driver.session() as sess:
            # EXPLAIN performs planning without executing the query
            sess.run(f"EXPLAIN {cypher}").consume()
    except CypherSyntaxError as e:
        errors.append(str(e))
    except Exception as e:
        # Non-syntax problems can still surface; treat as syntax error for gating purposes
        errors.append(str(e))
    return errors


def _label_exists(sess, label: str) -> bool:
    rec = sess.run(f"MATCH (n:`{label}`) RETURN 1 LIMIT 1").single()
    return rec is not None


def _reltype_exists(sess, rel_type: str) -> bool:
    rec = sess.run(f"MATCH ()-[r:`{rel_type}`]-() RETURN 1 LIMIT 1").single()
    return rec is not None


def _node_property_exists(sess, label: str, prop: str) -> bool:
    rec = sess.run(
        f"MATCH (n:`{label}`) WHERE n.`{prop}` IS NOT NULL RETURN 1 LIMIT 1"
    ).single()
    return rec is not None


def _rel_property_exists(sess, rel_type: str, prop: str) -> bool:
    rec = sess.run(
        f"MATCH ()-[r:`{rel_type}`]-() WHERE r.`{prop}` IS NOT NULL RETURN 1 LIMIT 1"
    ).single()
    return rec is not None


def _is_probably_string(value: Any) -> bool:
    # Values extracted via regex are strings; try to detect numeric literals to avoid string mapping checks
    if isinstance(value, str):
        try:
            int(value)
            return False
        except Exception:
            try:
                float(value)
                return False
            except Exception:
                return True
    return False


def _check_schema_and_properties(driver, cypher: str) -> List[str]:
    errors: List[str] = []
    tasks = _extract_entities_for_validation(cypher_statement=cypher)

    with driver.session() as sess:
        # Nodes
        for t in tasks.get("nodes", []):
            labels = t.get("parsed_labels_or_types", [])
            if labels:
                for lbl in labels:
                    if not _label_exists(sess, lbl):
                        errors.append(f"Unknown node label: {lbl}")
                    # Property name existence per label
                    if t.get("property_name") and not _node_property_exists(sess, lbl, t["property_name"]):
                        errors.append(
                            f"Property '{t['property_name']}' not found on node label '{lbl}'"
                        )

                    # Optional mapping existence for strings with equality
                    if t.get("property_name") and t.get("operator") in {"=", "IN"} and _is_probably_string(t.get("property_value")):
                        rec = sess.run(
                            f"MATCH (n:`{lbl}`) WHERE toLower(n.`{t['property_name']}`) = toLower($v) RETURN 1 LIMIT 1",
                            {"v": t.get("property_value")},
                        ).single()
                        if rec is None:
                            errors.append(
                                f"No value mapping for {lbl}.{t['property_name']} = '{t.get('property_value')}'"
                            )

        # Relationships
        for t in tasks.get("relationships", []):
            rel_types = t.get("parsed_labels_or_types", [])
            if rel_types:
                for rt in rel_types:
                    if not _reltype_exists(sess, rt):
                        errors.append(f"Unknown relationship type: {rt}")
                    if t.get("property_name") and not _rel_property_exists(sess, rt, t["property_name"]):
                        errors.append(
                            f"Property '{t['property_name']}' not found on relationship type '{rt}'"
                        )

    return errors


def validate_cypher_noexec(driver, cypher: str) -> Tuple[bool, List[str]]:
    """
    Validate Cypher without executing it:
    1) Write-clause guard
    2) EXPLAIN syntax check
    3) Schema + property existence checks

    Returns: (is_valid, errors)
    """
    if not cypher or not cypher.strip():
        return False, ["Query is empty"]

    # 1) write guard
    write_hits = _has_write_clauses(cypher)
    if write_hits:
        return False, [f"Contains write clause: {', '.join(write_hits)}"]

    # 2) syntax check via EXPLAIN
    syntax_errors = _check_syntax(driver, cypher)
    if syntax_errors:
        return False, syntax_errors

    # 3) schema/property checks
    sem_errors = _check_schema_and_properties(driver, cypher)
    if sem_errors:
        return False, sem_errors

    return True, []



# -------------------------
# Minimal extractors (no Pydantic)
# -------------------------

def _parse_labels_or_types(raw: str) -> List[str]:
    if not raw:
        return []
    if "&" in raw:
        parts = [p.strip() for p in raw.split("&")]
    elif "|" in raw:
        parts = [p.strip() for p in raw.split("|")]
    elif ":" in raw:
        parts = [p.strip() for p in raw.split(":")]
    else:
        parts = [raw]
    return [p for p in parts if p and not p.startswith("!")]


def _extract_entities_for_validation(cypher_statement: str) -> Dict[str, List[Dict[str, Any]]]:
    node_tasks = _extract_nodes_and_properties(cypher_statement)
    rel_tasks = _extract_relationships_and_properties(cypher_statement)
    return {"nodes": node_tasks, "relationships": rel_tasks}


def _extract_nodes_and_properties(cypher_statement: str) -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []
    nodes = re.findall(get_node_pattern(), cypher_statement)
    used_vars = set()
    for n in nodes:
        variables = re.findall(get_node_variable_pattern(), n)
        labels = [s.strip() for s in re.findall(get_node_label_pattern(), n)]
        label = labels[0] if labels else None
        match_props = re.findall(get_property_pattern(), n)
        match_props = match_props[0] if match_props else None
        if match_props:
            for k, v in _process_match_props(match_props):
                tasks.append({
                    "labels_or_types": label,
                    "parsed_labels_or_types": _parse_labels_or_types(label) if label else [],
                    "operator": "=",
                    "property_name": k,
                    "property_value": v,
                })
        var = variables[0] if variables else None
        if var and var not in used_vars:
            for f in _find_filters(var, cypher_statement):
                f.update({
                    "labels_or_types": label,
                    "parsed_labels_or_types": _parse_labels_or_types(label) if label else [],
                })
                tasks.append(f)
            used_vars.add(var)
    return tasks


def _extract_relationships_and_properties(cypher_statement: str) -> List[Dict[str, Any]]:
    tasks: List[Dict[str, Any]] = []
    rels = re.findall(get_relationship_pattern(), cypher_statement)
    used_vars = set()
    for rtxt in rels:
        variables = re.findall(get_relationship_variable_pattern(), rtxt)
        rel_types = [s.strip() for s in re.findall(get_relationship_type_pattern(), rtxt)]
        rel_type = rel_types[0] if rel_types else None
        match_props = re.findall(get_property_pattern(), rtxt)
        match_props = match_props[0] if match_props else None
        if match_props:
            for k, v in _process_match_props(match_props):
                tasks.append({
                    "labels_or_types": rel_type,
                    "parsed_labels_or_types": _parse_labels_or_types(rel_type) if rel_type else [],
                    "operator": "=",
                    "property_name": k,
                    "property_value": v,
                })
        var = variables[0] if variables else None
        if var and var not in used_vars:
            for f in _find_filters(var, cypher_statement):
                f.update({
                    "labels_or_types": rel_type,
                    "parsed_labels_or_types": _parse_labels_or_types(rel_type) if rel_type else [],
                })
                tasks.append(f)
            used_vars.add(var)
    return tasks


def _process_match_props(section: str) -> List[Tuple[str, Any]]:
    parts = section.split(",")
    out: List[Tuple[str, Any]] = []
    for part in parts:
        kv = part.split(":")
        if len(kv) == 2:
            k = kv[0].strip().lstrip("{")
            v = kv[1].strip().rstrip("}").replace("\"", "").replace("'", "")
            out.append((k, v))
    return out


def _find_filters(variable: str, cypher_statement: str) -> List[Dict[str, Any]]:
    res = re.findall(get_variable_operator_property_pattern(variable=variable), cypher_statement)
    filters: List[Dict[str, Any]] = []
    for prop, op, val in res:
        k = prop.strip().lstrip("{")
        v = val.strip().rstrip("}").replace("\"", "").replace("'", "")
        filters.append({
            "property_name": k,
            "operator": op.strip(),
            "property_value": v,
        })
    return filters

