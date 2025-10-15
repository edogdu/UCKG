import os
import re
import sys
from typing import List
from neo4j import GraphDatabase
from cypher_validation import CypherGuardValidator

# Add shared module to path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', 'shared'))

from config import (
    EXCLUDED_LABELS, 
    EXCLUDED_RELATIONSHIPS, 
    EXCLUDED_PROPERTIES, 
    LABEL_MAPPINGS, 
    DEFAULT_QUERY_LIMIT, 
    SCHEMA_CACHE_FILENAME,
    FEW_SHOT_EXAMPLES,
    PROMPT_RULES,
    PROMPT_GUIDE,
    EMPTY_RESULTS_PROMPT,
    QUERY_ERROR_PROMPT
)

class Text2Cypher:
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str, llm, schema_path: str = "neo4j_graph_schema.txt"):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.llm = llm
        
        # Initialize Cypher Guard validator
        self.cypher_validator = CypherGuardValidator(self.driver)
        
        # Use configuration constants from config module
        self.excluded_labels = EXCLUDED_LABELS
        self.excluded_relationships = EXCLUDED_RELATIONSHIPS

    def get_cybersecurity_schema(self) -> str:
        """Get minimal schema with just node labels and relationship triples"""
        print("DEBUG: Using ULTRA-SIMPLIFIED schema method!")
        node_props = self._fetch_node_properties()
        outgoing_connections = self._fetch_outgoing_connections()
        incoming_connections = self._fetch_incoming_connections()

        # Infer property datatypes per label from sample nodes
        def detect_type(value) -> str:
            try:
                if isinstance(value, bool):
                    return "boolean"
                if isinstance(value, int):
                    return "integer"
                if isinstance(value, float):
                    return "float"
                if isinstance(value, str):
                    return "string"
                if isinstance(value, list) and value:
                    inner_type = detect_type(value[0])
                    return f"list<{inner_type}>"
                if isinstance(value, list):
                    return "list<unknown>"
                return "unknown"
            except Exception:
                return "unknown"

        label_to_prop_types: dict[str, dict[str, str]] = {}
        try:
            for label in node_props.keys():
                aggregated_types: dict[str, set[str]] = {}
                with self.driver.session() as session:
                    # Sample up to 50 nodes per label to infer types
                    cypher = f"MATCH (n:{label}) RETURN n LIMIT 50"
                    for record in session.run(cypher):
                        node_obj = record["n"]
                        # neo4j.Node supports .items() to iterate properties
                        for prop_key, prop_val in dict(node_obj).items():
                            aggregated_types.setdefault(prop_key, set()).add(detect_type(prop_val))
                # Collapse sets into type strings (e.g., "string|integer")
                collapsed = {k: "|".join(sorted(v)) if v else "unknown" for k, v in aggregated_types.items()}
                # Ensure all known properties exist even if not observed in samples
                for known_prop in node_props.get(label, []):
                    collapsed.setdefault(known_prop, collapsed.get(known_prop, "unknown"))
                label_to_prop_types[label] = collapsed
        except Exception as e:
            # Fallback: mark all properties as unknown types
            print(f"DEBUG: Property type inference failed: {e}")
            for label, props in node_props.items():
                label_to_prop_types[label] = {p: "unknown" for p in props}

        # Node lines with dictionary-style properties
        node_lines = ""
        for lbl in sorted(node_props.keys()):
            props_dict = label_to_prop_types.get(lbl, {})
            # Exclude embedding-related properties from schema output
            filtered_keys = [
                k for k in sorted(props_dict.keys())
                if k not in EXCLUDED_PROPERTIES
            ]
            # Stable ordering for readability
            items = ", ".join(f"{k}: {props_dict[k]}" for k in filtered_keys) if filtered_keys else ""
            node_lines += f"{lbl} {{ {items} }}\n"

        # Relationship triples with parentheses and square brackets
        triple_lines = ""
        all_node_labels = set(outgoing_connections.keys()) | set(incoming_connections.keys())
        for node_label in sorted(all_node_labels):
            outgoing = outgoing_connections.get(node_label, [])
            for rel_type, target_label in outgoing:
                triple_lines += f"(:{node_label}) -[:{rel_type}]-> (:{target_label})\n"

        result = (
            "NODES:\n" + node_lines + "\n" +
            "RELATIONSHIPS:\n" + triple_lines
        )
        print(f"DEBUG: Generated schema length: {len(result)}")

        # Persist schema to a cache file for reuse in prompts
        try:
            shared_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'shared')
            cache_path = os.path.join(shared_dir, SCHEMA_CACHE_FILENAME)
            with open(cache_path, "w", encoding="utf-8") as f:
                f.write(result)
        except Exception as e:
            print(f"DEBUG: Failed to write schema cache: {e}")
        return result

    # ---------------------- Prompt Builder ----------------------
    def _build_prompt(self, question: str, schema_block: str, examples: str) -> str:
        """Compose a compact, constraint-driven prompt for Cypher generation."""
        rules = PROMPT_RULES
        guide = PROMPT_GUIDE

        return (
            rules + guide +
            examples + "\n\n" +
            "SCHEMA:\n" + schema_block + "\n\n" +
            f"Question: {question}\n" +
            "Cypher:"
        )

    def get_schema_info(self) -> dict:
        """Get detailed schema information for frontend display"""
        try:
        # Get node properties
        node_props = self._fetch_node_properties()
        rel_props = self._fetch_relationship_properties()
        
        # Get validation info
        validation_info = self.cypher_validator.get_validation_info()
        
        return {
            "node_types": list(node_props.keys()),
            "relationship_types": list(rel_props.keys()),
            "node_properties": node_props,
            "relationship_properties": rel_props,
            "validation_info": validation_info,
            "schema_status": "✅ Loaded",
            "timestamp": "Current cybersecurity schema information with Cypher Guard validation"
        }
        except Exception as e:
            print(f"Error getting schema info: {e}")
            return {
                "node_types": [],
                "relationship_types": [],
                "node_properties": {},
                "relationship_properties": {},
                "validation_info": {},
                "schema_status": "❌ Error loading schema",
                "error": str(e),
                "timestamp": "Error occurred while loading schema"
            }

    def get_schema(self) -> str:
        """Get cybersecurity-focused schema"""
        return self.get_cybersecurity_schema()

    def extract_query_relationships(self, cypher: str) -> dict:
        """Extract relationship information from a Cypher query"""
        import re
        
        relationships = {
            "used_relationships": [],
            "used_node_types": [],
            "query_patterns": []
        }
        
        if not cypher:
            return relationships
        
        # Extract relationship types (e.g., [:UCOEXHASCPE], -[UCOEXHASCPE]->)
        rel_pattern = r'\[:?([A-Z_]+)\]'
        rel_matches = re.findall(rel_pattern, cypher)
        relationships["used_relationships"] = list(set(rel_matches))
        
        # Extract node types (e.g., (cve:UcoCVE), (cpe:UcoexCPE))
        node_pattern = r'\([^:]*:([A-Za-z]+)\)'
        node_matches = re.findall(node_pattern, cypher)
        relationships["used_node_types"] = list(set(node_matches))
        
        # Extract query patterns
        if 'MATCH' in cypher.upper():
            relationships["query_patterns"].append("Node matching")
        if 'WHERE' in cypher.upper():
            relationships["query_patterns"].append("Property filtering")
        if 'RETURN' in cypher.upper():
            relationships["query_patterns"].append("Result projection")
        if 'LIMIT' in cypher.upper():
            relationships["query_patterns"].append("Result limiting")
        
        return relationships

    def validate_cypher(self, cypher: str, schema: str = None) -> tuple[bool, str]:
        """Enhanced Cypher validation using Cypher Guard library"""
        try:
            # Use Cypher Guard for comprehensive validation
            is_valid, message, detailed_errors = self.cypher_validator.validate_cypher_query(cypher)
            
            if not is_valid:
                return False, message
            
            # Additional cybersecurity-specific checks
            additional_errors = self._check_cybersecurity_specific_rules(cypher)
            if additional_errors:
                return False, additional_errors[0]
            
            return True, "Valid Cypher query"
            
        except Exception as e:
            # Fallback to basic validation if Cypher Guard fails
            return self._fallback_validation(cypher)
    
    def _check_cybersecurity_specific_rules(self, cypher: str) -> List[str]:
        """Check cybersecurity-specific validation rules."""
        errors = []
        
        # Check for excluded ontology metadata (warn if found)
        has_excluded_labels = any(f":{label}" in cypher for label in self.excluded_labels)
        has_excluded_relationships = any(f":{rel}" in cypher for rel in self.excluded_relationships)
        
        if has_excluded_labels or has_excluded_relationships:
            errors.append("Warning: Query contains ontology metadata labels/relationships that should be excluded")
        
        # Check for common LLM mistakes
        if 'year:{year:' in cypher or 'year:{"year":' in cypher:
            errors.append("Invalid node syntax: Use WHERE clause for filtering, not property nodes")
        
        # Check for invalid relationship usage (semantic validation)
        if 'UcoCVE)-[:UCOHASWEAKNESS]->(cwe:UcoCWE' in cypher:
            errors.append("Invalid relationship: UCOHASWEAKNESS connects UcoExploitTarget->UcoCWE, not UcoCVE->UcoCWE")
        
        return errors
    
    def _fallback_validation(self, cypher: str) -> tuple[bool, str]:
        """Fallback validation when Cypher Guard is not available."""
        # Basic checks
        if not cypher or cypher.strip() == "":
            return False, "Generated Cypher query is empty"
        
        # Check for valid starting keywords
        valid_starters = ['MATCH', 'RETURN', 'WITH', 'UNWIND', 'CALL']
        if not any(cypher.upper().startswith(starter) for starter in valid_starters):
            return False, f"Query must start with valid Cypher keyword. Got: {cypher[:50]}"
        
        # Check for common syntax errors
        if '{{' in cypher or '}}' in cypher:
            return False, "Invalid syntax: Found {{ or }} - use proper node syntax (n:Label)"
        
        # Check for balanced parentheses and brackets
        if cypher.count('(') != cypher.count(')') or cypher.count('[') != cypher.count(']'):
            return False, "Unbalanced parentheses or brackets"
        
        return True, "Valid Cypher query (fallback validation)"

    def text_to_cypher(self, question: str, schema: str = None) -> str:
        # Prefer cached schema for speed; regenerate if missing
        shared_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'shared')
        cache_path = os.path.join(shared_dir, SCHEMA_CACHE_FILENAME)
        schema_block = None
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    schema_block = f.read()
            except Exception:
                schema_block = None
        if not schema_block:
            schema_block = schema or self.get_cybersecurity_schema()
        
        # Print schema block for debugging
        print("=" * 80)
        print("SCHEMA BLOCK SENT TO LLM:")
        print("=" * 80)
        print(schema_block)
        print("=" * 80)
        
        # Use few-shot examples from config
        few_shot_examples = FEW_SHOT_EXAMPLES
        
        prompt = self._build_prompt(question=question, schema_block=schema_block, examples=few_shot_examples)
        
        max_retries = 3
        for attempt in range(max_retries):
            try:
                llm_output = self.llm.invoke(prompt)
                cypher = extract_cypher(llm_output)
                
                is_valid, error_msg = self.validate_cypher(cypher)
                if not is_valid:
                    logger.warning(f"Attempt {attempt + 1}: Validation failed for generated query '{cypher}'. Reason: {error_msg}")
                    # Re-raise to trigger retry
                    raise ValueError(f"Validation failed: {error_msg}")
                
                logger.info(f"Successfully generated and validated Cypher: {cypher}")
                return cypher
                
            except Exception as e:
                logger.error(f"Error in text_to_cypher (attempt {attempt + 1}/{max_retries}): {e}")
                if attempt == max_retries - 1:
                    raise Exception("Failed to generate a valid Cypher query after multiple attempts.") from e
                time.sleep(0.5)

    def text_to_cypher_with_fallback(self, question: str, schema: str = None) -> dict:
        """
        Enhanced text_to_cypher with comprehensive error handling and fallback mechanisms.
        Returns a dictionary with cypher, result, status, and helpful messages.
        """
        try:
            # Generate Cypher query
            cypher = self.text_to_cypher(question, schema)
            
            # Execute query
            result_list = self.run_cypher(cypher)
            
            # Check if query returned results
            if not result_list:
                return self._handle_empty_results(question, cypher)
            
            return {
                "cypher": cypher,
                "result": result_list,
                "status": "success",
                "message": f"Query executed successfully. Found {len(result_list)} results.",
                "count": len(result_list)
            }
            
        except Exception as e:
            return self._handle_query_error(question, str(e))

    def _handle_empty_results(self, question: str, cypher: str) -> dict:
        """Handle cases where the query returns no results."""
        try:
            # Generate helpful response using LLM
            fallback_prompt = EMPTY_RESULTS_PROMPT.format(question=question, cypher=cypher)
            
            helpful_response = self.llm.invoke(fallback_prompt).strip()
            
            return {
                "cypher": cypher,
                "result": [],
                "status": "no_results",
                "message": helpful_response,
                "count": 0,
                "suggestions": self._generate_query_suggestions(question)
            }
            
        except Exception as e:
            return {
                "cypher": cypher,
                "result": [],
                "status": "no_results",
                "message": f"No results found for your query. The generated Cypher query was: {cypher}. Try broadening your search criteria or using different keywords.",
                "count": 0,
                "suggestions": self._generate_query_suggestions(question)
            }

    def _handle_query_error(self, question: str, error: str) -> dict:
        """Handle query generation or execution errors."""
        try:
            # Generate helpful error response using LLM
            error_prompt = QUERY_ERROR_PROMPT.format(question=question, error=error)
            
            helpful_response = self.llm.invoke(error_prompt).strip()
            
            return {
                "cypher": None,
                "result": [],
                "status": "error",
                "message": helpful_response,
                "count": 0,
                "error": error,
                "suggestions": self._generate_query_suggestions(question)
            }
            
        except Exception as e:
            return {
                "cypher": None,
                "result": [],
                "status": "error",
                "message": f"I encountered an error processing your question: '{question}'. Please try rephrasing your question or ask about something else.",
                "count": 0,
                "error": error,
                "suggestions": self._generate_query_suggestions(question)
            }

    def _generate_query_suggestions(self, question: str) -> list:
        """Generate alternative query suggestions based on the original question."""
        suggestions = []
        
        # Common cybersecurity query patterns
        if any(word in question.lower() for word in ['cve', 'vulnerability', 'vulnerabilities']):
            suggestions.extend([
                "Try: 'Show CVEs with high severity'",
                "Try: 'Find CVEs affecting Windows platforms'",
                "Try: 'Show recent CVEs'"
            ])
        
        if any(word in question.lower() for word in ['cwe', 'weakness', 'weaknesses']):
            suggestions.extend([
                "Try: 'Show CWE weaknesses by status'",
                "Try: 'Find CWE weaknesses related to authentication'",
                "Try: 'Show CWE weaknesses by abstraction level'"
            ])
        
        if any(word in question.lower() for word in ['capec', 'attack', 'pattern', 'patterns']):
            suggestions.extend([
                "Try: 'Show CAPEC attack patterns by severity'",
                "Try: 'Find CAPEC patterns related to specific weaknesses'",
                "Try: 'Show CAPEC patterns by abstraction level'"
            ])
        
        if any(word in question.lower() for word in ['group', 'groups', 'threat', 'actor']):
            suggestions.extend([
                "Try: 'Show threat groups by domain'",
                "Try: 'Find groups using specific techniques'",
                "Try: 'Show groups using specific software'"
            ])
        
        if any(word in question.lower() for word in ['mitre', 'technique', 'techniques', 'attack']):
            suggestions.extend([
                "Try: 'Show MITRE ATT&CK techniques by domain'",
                "Try: 'Find techniques used by specific groups'",
                "Try: 'Show techniques with specific IDs'"
            ])
        
        # Generic suggestions
        if not suggestions:
            suggestions.extend([
                "Try asking about specific node types (CVEs, CWEs, CAPEC patterns, etc.)",
                "Try using broader search terms",
                "Try asking about relationships between different entities"
            ])
        
        return suggestions[:5]  # Limit to 5 suggestions

    def run_cypher(self, cypher_query: str):
        with self.driver.session() as session:
            result = session.run(cypher_query)
            # Convert to list immediately to avoid "result has been consumed" errors
            return list(result)

    # ---- V2 helper methods for rich schema extraction ----
    
    def _fetch_node_properties(self) -> dict:
        """Return mapping label -> sorted list of property names (excluding ontology metadata)."""
        node_props = {}
        with self.driver.session() as session:
            # Get all node labels from database
            result = session.run("CALL db.labels()")
            all_labels = [record['label'] for record in result]
            
            # Filter out excluded labels (ontology metadata)
            cybersecurity_labels = [label for label in all_labels if label not in self.excluded_labels]
            
            for lbl in cybersecurity_labels:
                try:
                    # Get all distinct property keys for this label
                    res = session.run(
                        f"MATCH (n:{lbl}) RETURN DISTINCT keys(n) AS props LIMIT 10"
                    )
                    all_props = set()
                    for record in res:
                        if record["props"]:
                            all_props.update(record["props"])
                    node_props[lbl] = sorted(all_props) if all_props else []
                except Exception as e:
                    print(f"Warning: Could not get properties for {lbl}: {e}")
                    node_props[lbl] = []
        return node_props

    def _fetch_relationship_properties(self) -> dict:
        """Return mapping rel-type -> sorted list of property names (excluding ontology metadata)."""
        rel_props = {}
        with self.driver.session() as session:
            # Get all relationship types from database
            result = session.run("CALL db.relationshipTypes()")
            all_relationships = [record['relationshipType'] for record in result]
            
            # Filter out excluded relationships (ontology metadata)
            cybersecurity_relationships = [rel for rel in all_relationships if rel not in self.excluded_relationships]
            
            for rel in cybersecurity_relationships:
                try:
                    # Get all distinct property keys for this relationship type
                    res = session.run(
                        f"MATCH ()-[r:{rel}]->() RETURN DISTINCT keys(r) AS props LIMIT 10"
                    )
                    all_props = set()
                    for record in res:
                        if record["props"]:
                            all_props.update(record["props"])
                    rel_props[rel] = sorted(all_props) if all_props else []
                except Exception as e:
                    print(f"Warning: Could not get properties for {rel}: {e}")
                    rel_props[rel] = []
        return rel_props

    def _get_schema_visualization(self):
        """Get schema visualization data, cached to avoid multiple calls."""
        if not hasattr(self, '_cached_schema_viz'):
            with self.driver.session() as session:
                record = session.run("CALL db.schema.visualization()").single()
                self._cached_schema_viz = record
        return self._cached_schema_viz

    


def fix_common_label_mistakes(cypher: str) -> str:
    """Fix common LLM mistakes with node labels."""
    # Apply fixes using configuration constants
    for wrong, correct in LABEL_MAPPINGS.items():
        cypher = cypher.replace(wrong, correct)
    
    # Add LIMIT clause if missing and query doesn't have one
    if 'LIMIT' not in cypher.upper() and 'RETURN' in cypher.upper():
        cypher = cypher.rstrip(';') + f' LIMIT {DEFAULT_QUERY_LIMIT}'
    
    return cypher

def extract_cypher(text: str) -> str:
    text = re.sub(r'(?i)^\s*cypher\s*', '', text).strip()
    
    # Try to extract from code blocks first (handle both ```cypher and ```)
    pattern = r"```(?:cypher)?\s*\n?(.*?)```"
    matches = re.findall(pattern, text, re.DOTALL)
    if matches:
        cypher = matches[0].strip()
        # Remove any trailing semicolons and extra whitespace
        cypher = re.sub(r';\s*$', '', cypher).strip()
    else:
        # If no code blocks, look for lines that start with MATCH, RETURN, etc.
        lines = text.split('\n')
        cypher_lines = []
        for line in lines:
            line = line.strip()
            if line and (line.upper().startswith(('MATCH', 'RETURN', 'WITH', 'UNWIND', 'CALL', 'CREATE', 'DELETE', 'SET', 'REMOVE', 'MERGE'))):
                cypher_lines.append(line)
        
        if cypher_lines:
            cypher = '\n'.join(cypher_lines)
        else:
            # Fallback to original text
            cypher = text.strip()
    
    # Post-process to fix common LLM mistakes
    cypher = fix_common_label_mistakes(cypher)
    
    return cypher
