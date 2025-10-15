"""
UCKG Schema Extraction Module

Extracts UCKG schema from Neo4j and saves it as a structured text file (schema.txt)
that can be used by other components. This module provides comprehensive schema
extraction capabilities separate from the Text2Cypher functionality.

Architecture:
- SchemaExtractor: Main class for extracting and saving schema
- SchemaFormatter: Handles different output formats (text, JSON, etc.)
- SchemaValidator: Validates extracted schema completeness
"""

import os
import json
from typing import Dict, List, Tuple, Optional, Set
from datetime import datetime
from neo4j import GraphDatabase
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'text2cypher', 'backend'))
from config import (
    EXCLUDED_LABELS, 
    EXCLUDED_RELATIONSHIPS, 
    EXCLUDED_PROPERTIES,
    SCHEMA_CACHE_FILENAME
)


class SchemaExtractor:
    """
    Main class for extracting UCKG schema from Neo4j database.
    Provides comprehensive schema extraction with multiple output formats.
    """
    
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str):
        """Initialize schema extractor with Neo4j connection."""
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.excluded_labels = EXCLUDED_LABELS
        self.excluded_relationships = EXCLUDED_RELATIONSHIPS
        self.excluded_properties = EXCLUDED_PROPERTIES
        self._cached_schema_viz = None
    
    def extract_complete_schema(self, output_file: str = "schema.txt", format: str = "text") -> Dict:
        """
        Extract complete UCKG schema and save to file.
        
        Args:
            output_file: Output filename (default: "schema.txt")
            format: Output format ("text", "json", "both")
        
        Returns:
            Dictionary with extraction results and metadata
        """
        print("🔍 Starting UCKG schema extraction...")
        
        try:
            # Extract schema components
            node_properties = self._extract_node_properties()
            relationship_properties = self._extract_relationship_properties()
            outgoing_connections = self._extract_outgoing_connections()
            incoming_connections = self._extract_incoming_connections()
            node_types = self._infer_property_types(node_properties)
            
            # Create schema data structure
            schema_data = {
                "metadata": {
                    "extraction_timestamp": datetime.now().isoformat(),
                    "database_uri": str(self.driver._pool._address),
                    "total_node_types": len(node_properties),
                    "total_relationship_types": len(relationship_properties),
                    "total_connections": len(outgoing_connections) + len(incoming_connections)
                },
                "node_types": node_properties,
                "relationship_types": relationship_properties,
                "connections": {
                    "outgoing": outgoing_connections,
                    "incoming": incoming_connections
                },
                "property_types": node_types
            }
            
            # Generate formatted output
            formatter = SchemaFormatter()
            results = {}
            
            if format in ["text", "both"]:
                text_content = formatter.format_as_text(
                    node_properties, outgoing_connections, incoming_connections, node_types
                )
                text_file = output_file if output_file.endswith('.txt') else f"{output_file}.txt"
                self._save_to_file(text_content, text_file)
                results["text_file"] = text_file
                print(f"✅ Text schema saved to: {text_file}")
            
            if format in ["json", "both"]:
                json_file = output_file.replace('.txt', '.json') if output_file.endswith('.txt') else f"{output_file}.json"
                self._save_to_file(json.dumps(schema_data, indent=2), json_file)
                results["json_file"] = json_file
                print(f"✅ JSON schema saved to: {json_file}")
            
            # Validate schema completeness
            validator = SchemaValidator()
            validation_results = validator.validate_schema(schema_data)
            results["validation"] = validation_results
            
            print(f"🎉 Schema extraction completed successfully!")
            print(f"   📊 Node types: {len(node_properties)}")
            print(f"   🔗 Relationship types: {len(relationship_properties)}")
            print(f"   📈 Total connections: {len(outgoing_connections) + len(incoming_connections)}")
            
            return {
                "status": "success",
                "files_created": results,
                "schema_data": schema_data,
                "validation": validation_results
            }
            
        except Exception as e:
            error_msg = f"Schema extraction failed: {str(e)}"
            print(f"❌ {error_msg}")
            return {
                "status": "error",
                "error": error_msg,
                "files_created": {}
            }
        finally:
            self.driver.close()
    
    def _extract_node_properties(self) -> Dict[str, List[str]]:
        """Extract node properties from Neo4j database."""
        print("📋 Extracting node properties...")
        node_props = {}
        
        with self.driver.session() as session:
            # Get all node labels
            result = session.run("CALL db.labels()")
            all_labels = [record['label'] for record in result]
            
            # Filter out excluded labels
            cybersecurity_labels = [label for label in all_labels if label not in self.excluded_labels]
            
            for label in cybersecurity_labels:
                try:
                    # Get distinct property keys for this label
                    props_result = session.run(f"MATCH (n:{label}) RETURN DISTINCT keys(n) AS props LIMIT 10")
                    all_props = set()
                    for record in props_result:
                        if record["props"]:
                            all_props.update(record["props"])
                    
                    # Filter out excluded properties
                    filtered_props = [prop for prop in all_props if prop not in self.excluded_properties]
                    node_props[label] = sorted(filtered_props) if filtered_props else []
                    
                except Exception as e:
                    print(f"⚠️  Warning: Could not extract properties for {label}: {e}")
                    node_props[label] = []
        
        return node_props
    
    def _extract_relationship_properties(self) -> Dict[str, List[str]]:
        """Extract relationship properties from Neo4j database."""
        print("🔗 Extracting relationship properties...")
        rel_props = {}
        
        with self.driver.session() as session:
            # Get all relationship types
            result = session.run("CALL db.relationshipTypes()")
            all_relationships = [record['relationshipType'] for record in result]
            
            # Filter out excluded relationships
            cybersecurity_relationships = [rel for rel in all_relationships if rel not in self.excluded_relationships]
            
            for rel_type in cybersecurity_relationships:
                try:
                    # Get distinct property keys for this relationship type
                    props_result = session.run(f"MATCH ()-[r:{rel_type}]->() RETURN DISTINCT keys(r) AS props LIMIT 10")
                    all_props = set()
                    for record in props_result:
                        if record["props"]:
                            all_props.update(record["props"])
                    rel_props[rel_type] = sorted(all_props) if all_props else []
                    
                except Exception as e:
                    print(f"⚠️  Warning: Could not extract properties for {rel_type}: {e}")
                    rel_props[rel_type] = []
        
        return rel_props
    
    def _extract_outgoing_connections(self) -> Dict[str, List[Tuple[str, str]]]:
        """Extract outgoing relationship connections."""
        print("➡️  Extracting outgoing connections...")
        return self._extract_connections(direction="outgoing")
    
    def _extract_incoming_connections(self) -> Dict[str, List[Tuple[str, str]]]:
        """Extract incoming relationship connections."""
        print("⬅️  Extracting incoming connections...")
        return self._extract_connections(direction="incoming")
    
    def _extract_connections(self, direction: str) -> Dict[str, List[Tuple[str, str]]]:
        """Extract relationship connections in specified direction."""
        from collections import defaultdict
        connections = defaultdict(set)
        
        schema_viz = self._get_schema_visualization()
        if not schema_viz:
            return {}
        
        nodes = schema_viz.get("nodes", [])
        rels = schema_viz.get("relationships", [])
        
        if not isinstance(nodes, list) or not isinstance(rels, list):
            return {}
        
        # Map node element_id to labels
        id_to_labels = {}
        for node in nodes:
            node_id = node.element_id if hasattr(node, 'element_id') else str(node)
            labels = list(node.labels) if hasattr(node, 'labels') else []
            valid_labels = [l for l in labels if l not in self.excluded_labels]
            if valid_labels:
                id_to_labels[node_id] = valid_labels
        
        # Process relationships
        for rel in rels:
            rel_type = rel.type if hasattr(rel, 'type') else str(rel)
            if rel_type in self.excluded_relationships:
                continue
            
            start_node = rel.start_node if hasattr(rel, 'start_node') else None
            end_node = rel.end_node if hasattr(rel, 'end_node') else None
            
            if start_node and end_node:
                start_id = start_node.element_id if hasattr(start_node, 'element_id') else str(start_node)
                end_id = end_node.element_id if hasattr(end_node, 'element_id') else str(end_node)
                
                start_labels = id_to_labels.get(start_id, [])
                end_labels = id_to_labels.get(end_id, [])
                
                if direction == "outgoing":
                    for start_label in start_labels:
                        for end_label in end_labels:
                            connections[start_label].add((rel_type, end_label))
                else:  # incoming
                    for end_label in end_labels:
                        for start_label in start_labels:
                            connections[end_label].add((start_label, rel_type))
        
        # Convert sets to sorted lists
        return {label: sorted(list(conn_set)) for label, conn_set in connections.items()}
    
    def _get_schema_visualization(self):
        """Get Neo4j schema visualization data."""
        if self._cached_schema_viz is None:
            with self.driver.session() as session:
                record = session.run("CALL db.schema.visualization()").single()
                self._cached_schema_viz = record
        return self._cached_schema_viz
    
    def _infer_property_types(self, node_properties: Dict[str, List[str]]) -> Dict[str, Dict[str, str]]:
        """Infer property types by sampling actual data."""
        print("🔍 Inferring property types...")
        type_inference = {}
        
        def detect_type(value) -> str:
            if isinstance(value, bool):
                return "boolean"
            elif isinstance(value, int):
                return "integer"
            elif isinstance(value, float):
                return "float"
            elif isinstance(value, str):
                return "string"
            elif isinstance(value, list) and value:
                inner_type = detect_type(value[0])
                return f"list<{inner_type}>"
            elif isinstance(value, list):
                return "list<unknown>"
            else:
                return "unknown"
        
        for label, properties in node_properties.items():
            if not properties:
                type_inference[label] = {}
                continue
                
            aggregated_types = {}
            try:
                with self.driver.session() as session:
                    # Sample up to 50 nodes per label
                    cypher = f"MATCH (n:{label}) RETURN n LIMIT 50"
                    for record in session.run(cypher):
                        node_obj = record["n"]
                        for prop_key, prop_val in dict(node_obj).items():
                            if prop_key in properties:  # Only process relevant properties
                                aggregated_types.setdefault(prop_key, set()).add(detect_type(prop_val))
                
                # Collapse types
                collapsed = {}
                for prop, types in aggregated_types.items():
                    if types:
                        collapsed[prop] = "|".join(sorted(types))
                    else:
                        collapsed[prop] = "unknown"
                
                type_inference[label] = collapsed
                
            except Exception as e:
                print(f"⚠️  Warning: Type inference failed for {label}: {e}")
                type_inference[label] = {prop: "unknown" for prop in properties}
        
        return type_inference
    
    def _save_to_file(self, content: str, filename: str):
        """Save content to file."""
        filepath = os.path.join(os.path.dirname(__file__), filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)


class SchemaFormatter:
    """Handles formatting of schema data into different output formats."""
    
    def format_as_text(self, node_properties: Dict, outgoing_connections: Dict, 
                      incoming_connections: Dict, property_types: Dict) -> str:
        """Format schema as structured text."""
        lines = []
        lines.append("# UCKG Schema")
        lines.append(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")
        
        # Node types section
        lines.append("## NODE TYPES")
        lines.append("")
        for label in sorted(node_properties.keys()):
            props = node_properties.get(label, [])
            types = property_types.get(label, {})
            
            if props:
                prop_items = []
                for prop in props:
                    prop_type = types.get(prop, "unknown")
                    prop_items.append(f"{prop}: {prop_type}")
                lines.append(f"{label} {{ {', '.join(prop_items)} }}")
            else:
                lines.append(f"{label} {{}}")
        
        lines.append("")
        
        # Relationships section
        lines.append("## RELATIONSHIPS")
        lines.append("")
        all_node_labels = set(outgoing_connections.keys()) | set(incoming_connections.keys())
        for node_label in sorted(all_node_labels):
            outgoing = outgoing_connections.get(node_label, [])
            for rel_type, target_label in outgoing:
                lines.append(f"(:{node_label}) -[:{rel_type}]-> (:{target_label})")
        
        return "\n".join(lines)


class SchemaValidator:
    """Validates extracted schema for completeness and consistency."""
    
    def validate_schema(self, schema_data: Dict) -> Dict:
        """Validate schema data and return validation results."""
        validation_results = {
            "is_valid": True,
            "warnings": [],
            "errors": [],
            "statistics": {}
        }
        
        # Check for empty schema
        if not schema_data.get("node_types"):
            validation_results["errors"].append("No node types found")
            validation_results["is_valid"] = False
        
        if not schema_data.get("relationship_types"):
            validation_results["warnings"].append("No relationship types found")
        
        # Check for isolated nodes (no connections)
        node_types = set(schema_data.get("node_types", {}).keys())
        connected_nodes = set()
        
        for connections in schema_data.get("connections", {}).values():
            for conn_list in connections.values():
                for conn in conn_list:
                    if isinstance(conn, tuple) and len(conn) == 2:
                        connected_nodes.add(conn[1])  # target node
        
        isolated_nodes = node_types - connected_nodes
        if isolated_nodes:
            validation_results["warnings"].append(f"Isolated nodes found: {sorted(isolated_nodes)}")
        
        # Statistics
        validation_results["statistics"] = {
            "total_node_types": len(schema_data.get("node_types", {})),
            "total_relationship_types": len(schema_data.get("relationship_types", {})),
            "total_connections": sum(len(conns) for conns in schema_data.get("connections", {}).get("outgoing", {}).values()),
            "isolated_nodes": len(isolated_nodes)
        }
        
        return validation_results


def main():
    """Command-line interface for schema extraction."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Extract UCKG schema from Neo4j")
    parser.add_argument("--uri", default="bolt://localhost:7687", help="Neo4j URI")
    parser.add_argument("--user", default="neo4j", help="Neo4j username")
    parser.add_argument("--password", default="password", help="Neo4j password")
    parser.add_argument("--output", default="schema.txt", help="Output filename")
    parser.add_argument("--format", choices=["text", "json", "both"], default="text", help="Output format")
    
    args = parser.parse_args()
    
    # Extract schema
    extractor = SchemaExtractor(args.uri, args.user, args.password)
    results = extractor.extract_complete_schema(args.output, args.format)
    
    if results["status"] == "success":
        print("\n🎉 Schema extraction completed successfully!")
        for file_type, filename in results["files_created"].items():
            if file_type != "validation":
                print(f"   📄 {file_type}: {filename}")
    else:
        print(f"\n❌ Schema extraction failed: {results['error']}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())