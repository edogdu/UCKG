"""
Cypher Guard Integration for Text2Cypher V4
Provides robust Cypher query validation using the cypher-guard library.
"""

from typing import Dict, List, Tuple, Any, Optional
from neo4j import Driver
import logging
import re

# Try to import cypher_guard, fallback to mock implementation if not available
try:
    from cypher_guard import validate_cypher, DbSchema, check_syntax, is_write, is_read
    CYPHER_GUARD_AVAILABLE = True
except ImportError:
    CYPHER_GUARD_AVAILABLE = False
    # Mock classes for fallback
    class DbSchema:
        def __init__(self, **kwargs):
            self.node_props = kwargs.get('node_props', {})
            self.relationships = kwargs.get('relationships', [])
            self.rel_props = kwargs.get('rel_props', {})
        
        @classmethod
        def from_dict(cls, schema_dict):
            return cls(**schema_dict)
    
    def validate_cypher(query, schema):
        return []  # Mock: always return no errors
    
    def check_syntax(query):
        return True  # Mock: always return valid syntax
    
    def is_write(query):
        return query.upper().strip().startswith(('CREATE', 'DELETE', 'SET', 'REMOVE', 'MERGE', 'DROP'))
    
    def is_read(query):
        return query.upper().strip().startswith(('MATCH', 'RETURN', 'WITH', 'UNWIND', 'CALL'))

logger = logging.getLogger(__name__)

class CypherGuardValidator:
    """
    Enhanced Cypher validation using Cypher Guard library.
    Provides comprehensive validation including syntax, schema, and security checks.
    """
    
    def __init__(self, driver: Driver):
        self.driver = driver
        self.schema = None
        self.cypher_guard_available = CYPHER_GUARD_AVAILABLE
        self._load_schema()
    
    def _load_schema(self):
        """Load and convert Neo4j schema to Cypher Guard format."""
        try:
            with self.driver.session() as session:
                # Get node labels and properties
                node_props = {}
                labels_result = session.run("CALL db.labels()")
                for record in labels_result:
                    label = record['label']
                    if label not in self._get_excluded_labels():
                        # Get properties for this label
                        props_result = session.run(f"MATCH (n:{label}) RETURN DISTINCT keys(n) AS props LIMIT 10")
                        properties = []
                        for prop_record in props_result:
                            if prop_record['props']:
                                for prop in prop_record['props']:
                                    if prop not in ['embedding', 'embedding_processed']:  # Skip embedding properties
                                        properties.append({
                                            "property": prop,
                                            "type": "STRING"  # Default type, could be enhanced with actual type detection
                                        })
                        if properties:
                            node_props[label] = properties
                
                # Get relationship types and properties
                rel_props = {}
                relationships = []
                rels_result = session.run("CALL db.relationshipTypes()")
                for record in rels_result:
                    rel_type = record['relationshipType']
                    if rel_type not in self._get_excluded_relationships():
                        # Get properties for this relationship type
                        props_result = session.run(f"MATCH ()-[r:{rel_type}]->() RETURN DISTINCT keys(r) AS props LIMIT 10")
                        properties = []
                        for prop_record in props_result:
                            if prop_record['props']:
                                for prop in prop_record['props']:
                                    properties.append({
                                        "property": prop,
                                        "type": "STRING"
                                    })
                        if properties:
                            rel_props[rel_type] = properties
                
                # Get relationship patterns using schema visualization
                try:
                    schema_result = session.run("CALL db.schema.visualization()").single()
                    if schema_result:
                        nodes = schema_result.get("nodes", [])
                        rels = schema_result.get("relationships", [])
                        
                        # Map node element_id to labels
                        id_to_labels = {}
                        for node in nodes:
                            if hasattr(node, 'element_id') and hasattr(node, 'labels'):
                                node_id = node.element_id
                                labels = [l for l in node.labels if l not in self._get_excluded_labels()]
                                if labels:
                                    id_to_labels[node_id] = labels
                        
                        # Build relationship patterns
                        for rel in rels:
                            if hasattr(rel, 'type') and hasattr(rel, 'start_node') and hasattr(rel, 'end_node'):
                                rel_type = rel.type
                                if rel_type not in self._get_excluded_relationships():
                                    start_node = rel.start_node
                                    end_node = rel.end_node
                                    
                                    if hasattr(start_node, 'element_id') and hasattr(end_node, 'element_id'):
                                        start_id = start_node.element_id
                                        end_id = end_node.element_id
                                        
                                        start_labels = id_to_labels.get(start_id, [])
                                        end_labels = id_to_labels.get(end_id, [])
                                        
                                        # Create relationship patterns for all combinations
                                        for start_label in start_labels:
                                            for end_label in end_labels:
                                                relationships.append({
                                                    "start": start_label,
                                                    "type": rel_type,
                                                    "end": end_label
                                                })
                except Exception as e:
                    logger.warning(f"Could not get relationship patterns from schema visualization: {e}")
                    # Fallback: create basic relationships based on common patterns
                    relationships = self._get_fallback_relationships()
                
                # Create the schema
                schema_dict = {
                    "node_props": node_props,
                    "rel_props": rel_props,
                    "relationships": relationships,
                    "metadata": {
                        "constraint": [],
                        "index": []
                    }
                }
                
                self.schema = DbSchema.from_dict(schema_dict)
                logger.info(f"Loaded schema with {len(node_props)} node types and {len(relationships)} relationship patterns")
                
        except Exception as e:
            logger.error(f"Failed to load schema: {e}")
            # Create a minimal fallback schema
            self.schema = self._create_fallback_schema()
    
    def _get_excluded_labels(self) -> set:
        """Get list of excluded ontology metadata labels."""
        return {
            "RDFRESOURCE", "RDFLIST", "RDFALT", "RDFBAG", "RDFSEQ", "RDFSTATEMENT",
            "RDFSUBJECT", "RDFPREDICATE", "RDFOBJECT", "RDFTYPE", "RDFVALUE", "RDFFIRST",
            "RDFREST", "RDFNIL", "RDFXMLLITERAL", "RDFPLAINLITERAL", "RDFLANGSTRING"
        }
    
    def _get_excluded_relationships(self) -> set:
        """Get list of excluded ontology metadata relationships."""
        return {
            "RDFTYPE", "RDFVALUE", "RDFFIRST", "RDFREST", "RDFSUBJECT", "RDFPREDICATE", "RDFOBJECT"
        }
    
    def _get_fallback_relationships(self) -> List[Dict[str, str]]:
        """Fallback relationship patterns for common cybersecurity entities."""
        return [
            {"start": "UcoCVE", "type": "UCOEXHASCPE", "end": "UcoexCPE"},
            {"start": "UcoexCAPEC", "type": "UCOEXHASRELATEDWEAKNESS", "end": "UcoCWE"},
            {"start": "UcoexGROUPS", "type": "UCOEXGROUPUSESTECHNIQUE", "end": "UcoexMITREATTACK"},
            {"start": "UcoexGROUPS", "type": "UCOEXGROUPUSESSOFTWARE", "end": "UcoexSOFTWARE"},
            {"start": "UcoexCAMPAIGNS", "type": "UCOEXATTRIBUTEDTO", "end": "UcoexGROUPS"},
            {"start": "UcoexCAMPAIGNS", "type": "UCOEXCAMPAIGNUSESTECHNIQUE", "end": "UcoexMITREATTACK"},
            {"start": "UcoexCAMPAIGNS", "type": "UCOEXCAMPAIGNUSESSOFTWARE", "end": "UcoexSOFTWARE"},
            {"start": "UcoexSOFTWARE", "type": "UCOEXSOFTWAREUSESTECHNIQUE", "end": "UcoexMITREATTACK"},
            {"start": "UcoexMITIGATIONS", "type": "UCOEXMITIGATES", "end": "UcoexMITREATTACK"},
            {"start": "UcoexCAPEC", "type": "UCOEXHASTAXONOMYMAPPING", "end": "UcoexMITREATTACK"},
            {"start": "UcoVulnerability", "type": "UCOHASCVE_ID", "end": "UcoCVE"},
            {"start": "UcoExploitTarget", "type": "UCOHASWEAKNESS", "end": "UcoCWE"},
            {"start": "UcoExploitTarget", "type": "UCOHASVULNERABILITY", "end": "UcoVulnerability"},
            {"start": "UcoCWE", "type": "UCOHASOBSERVEDEXAMPLE", "end": "UcoexObservedExample"},
            {"start": "UcoexObservedExample", "type": "UCOEXEXAMPLEOBSERVEDIN", "end": "UcoCVE"},
            {"start": "UcoexMITRED3FEND", "type": "UCOEXHASMITREATTACK", "end": "UcoexMITREATTACK"}
        ]
    
    def _create_fallback_schema(self) -> DbSchema:
        """Create a minimal fallback schema when schema loading fails."""
        schema_dict = {
            "node_props": {
                "UcoCVE": [{"property": "label", "type": "STRING"}],
                "UcoCWE": [{"property": "ucocweID", "type": "STRING"}],
                "UcoexCAPEC": [{"property": "ucoexCAPEC_id", "type": "STRING"}],
                "UcoexGROUPS": [{"property": "ucoexNAME", "type": "STRING"}],
                "UcoexMITREATTACK": [{"property": "ucoexNAME", "type": "STRING"}],
                "UcoexSOFTWARE": [{"property": "ucoexNAME", "type": "STRING"}],
                "UcoexCPE": [{"property": "cpeName", "type": "STRING"}]
            },
            "rel_props": {},
            "relationships": self._get_fallback_relationships(),
            "metadata": {"constraint": [], "index": []}
        }
        return DbSchema.from_dict(schema_dict)
    
    def validate_cypher_query(self, cypher: str) -> Tuple[bool, str, List[str]]:
        """
        Validate a Cypher query using Cypher Guard or fallback validation.
        
        Args:
            cypher: The Cypher query to validate
            
        Returns:
            Tuple of (is_valid, message, detailed_errors)
        """
        try:
            # Basic syntax check first
            if not cypher or cypher.strip() == "":
                return False, "Generated Cypher query is empty", ["Empty query"]
            
            # Check if it's a write query (we only allow read queries)
            if is_write(cypher):
                return False, "Write queries are not allowed", ["Write operation detected"]
            
            if self.cypher_guard_available:
                # Use Cypher Guard for comprehensive validation
                try:
                    # Check syntax
                    if has_parser_errors(cypher):
                        return False, "Query has syntax errors", ["Syntax error detected"]
                    
                    # Validate against schema
                    errors = validate_cypher(cypher, self.schema)
                    
                    if errors:
                        error_messages = [str(error) for error in errors]
                        return False, f"Schema validation failed: {error_messages[0]}", error_messages
                    
                    return True, "Query is valid (Cypher Guard)", []
                    
                except Exception as e:
                    logger.warning(f"Cypher Guard validation failed, using fallback: {e}")
                    return self._fallback_validation(cypher)
            else:
                # Use fallback validation
                return self._fallback_validation(cypher)
            
        except Exception as e:
            logger.error(f"Validation error: {e}")
            return False, f"Validation failed: {str(e)}", [str(e)]
    
    def _fallback_validation(self, cypher: str) -> Tuple[bool, str, List[str]]:
        """Fallback validation when Cypher Guard is not available."""
        errors = []
        
        # Basic syntax checks
        if not cypher or cypher.strip() == "":
            return False, "Generated Cypher query is empty", ["Empty query"]
        
        # Check for valid starting keywords
        valid_starters = ['MATCH', 'RETURN', 'WITH', 'UNWIND', 'CALL']
        if not any(cypher.upper().startswith(starter) for starter in valid_starters):
            errors.append(f"Query must start with valid Cypher keyword. Got: {cypher[:50]}")
        
        # Check for balanced parentheses and brackets
        if cypher.count('(') != cypher.count(')'):
            errors.append("Unbalanced parentheses")
        if cypher.count('[') != cypher.count(']'):
            errors.append("Unbalanced brackets")
        
        # Check for common syntax errors
        if '{{' in cypher or '}}' in cypher:
            errors.append("Invalid syntax: Found {{ or }} - use proper node syntax (n:Label)")
        
        # Check for proper node syntax (should have :Label)
        node_pattern = r'\([^:]+\)'
        if re.search(node_pattern, cypher):
            errors.append("Nodes should have labels: (n:Label) not (n)")
        
        # Check for proper relationship syntax
        rel_pattern = r'\[[^:]+[^]]*\]'
        if re.search(rel_pattern, cypher):
            errors.append("Relationships should have types: [:TYPE] not []")
        
        # Check for common LLM mistakes
        if 'year:{year:' in cypher or 'year:{"year":' in cypher:
            errors.append("Invalid node syntax: Use WHERE clause for filtering, not property nodes")
        
        # Schema validation (basic)
        if self.schema and hasattr(self.schema, 'node_props'):
            # Check if node labels exist in schema
            node_labels = re.findall(r':(\w+)', cypher)
            for label in node_labels:
                if label not in self.schema.node_props:
                    errors.append(f"Unknown node label: {label}")
        
        if errors:
            return False, f"Validation failed: {errors[0]}", errors
        
        return True, "Query is valid (fallback validation)", []
    
    def get_validation_info(self) -> Dict[str, Any]:
        """Get information about the current schema for debugging."""
        if not self.schema:
            return {"error": "Schema not loaded"}
        
        return {
            "cypher_guard_available": self.cypher_guard_available,
            "validation_mode": "Cypher Guard" if self.cypher_guard_available else "Fallback",
            "node_types": len(self.schema.node_props) if hasattr(self.schema, 'node_props') else 0,
            "relationship_types": len(self.schema.relationships) if hasattr(self.schema, 'relationships') else 0,
            "schema_loaded": True
        }
    
    def is_read_only(self, cypher: str) -> bool:
        """Check if the query is read-only."""
        try:
            return is_read(cypher)
        except Exception:
            return False
    
    def has_syntax_errors(self, cypher: str) -> bool:
        """Check if the query has syntax errors."""
        try:
            return has_parser_errors(cypher)
        except Exception:
            return True

def has_parser_errors(cypher: str) -> bool:
    """Check if query has parser errors."""
    try:
        from cypher_guard import has_parser_errors
        return has_parser_errors(cypher)
    except ImportError:
        # Fallback if function not available
        return False