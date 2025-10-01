import os
import traceback
from neo4j import GraphDatabase

# --- Configuration ---
# TODO: Update these with your Neo4j instance details
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "abcd90909090" # Replace with your actual password
OUTPUT_FILE_NAME = "neo4j_graph_schema.txt"

class Neo4jSchemaExtractor:
    """
    Connects to a Neo4j database to extract and format its schema.
    The output is designed to be used as context for a Large Language Model (LLM)
    to help it generate accurate Cypher queries.
    """

    def __init__(self, uri, user, password):
        """
        Initializes the extractor and connects to the database.
        """
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = None
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.driver.verify_connectivity()
            print("Successfully connected to Neo4j database.")
        except Exception as e:
            print(f"Error: Could not connect to Neo4j. Please check your credentials and connection settings.")
            print(f"Details: {e}")
            raise

    def close(self):
        """
        Closes the database connection.
        """
        if self.driver:
            self.driver.close()
            print("Neo4j connection closed.")

    def get_schema(self):
        """
        Fetches the complete schema from the database using built-in procedures.
        This includes node labels, properties, relationship types, and their connections.
        """
        print("Extracting schema from the database...")
        schema_info = {
            "node_properties": [],
            "rel_properties": [],
            "relationships": []
        }
        try:
            with self.driver.session() as session:
                # Get node labels and their properties
                node_props_query = "CALL db.schema.nodeTypeProperties()"
                schema_info["node_properties"] = session.run(node_props_query).data()

                # Get relationship types and their properties
                rel_props_query = "CALL db.schema.relTypeProperties()"
                schema_info["rel_properties"] = session.run(rel_props_query).data()

                # Get the relationship schema (how nodes are connected)
                relationships_query = "CALL db.schema.visualization()"
                result = session.run(relationships_query).data()

                if not result:
                    print("Warning: `CALL db.schema.visualization()` returned no data. Could not determine relationship schema.")
                    return schema_info

                vis_data = result[0]
                nodes = vis_data.get('nodes', [])
                rels = vis_data.get('relationships', [])
                
                # 1. Build a map of node IDs to their labels for quick lookup.
                node_map = {}
                for node in nodes:
                    node_id = node.get('<id>')
                    node_label = node.get('name')
                    if node_id is not None and node_label:
                        node_map[node_id] = [node_label]

                # 2. Process relationships with robust logic to handle multiple data formats.
                for rel_tuple in rels:
                    if len(rel_tuple) < 3:
                        print(f"Warning: Skipping malformed relationship tuple: {rel_tuple}")
                        continue

                    # Correctly unpack the tuple: (start_node, relationship, end_node)
                    start_node_ref, rel_info, end_node_ref = rel_tuple[0], rel_tuple[1], rel_tuple[2]

                    start_label = None
                    end_label = None
                    
                    # Determine start node label
                    if isinstance(start_node_ref, dict) and 'name' in start_node_ref:
                        start_label = start_node_ref.get('name') # Label is in the dict directly
                    else:
                        start_node_id = start_node_ref.get('<id>') if isinstance(start_node_ref, dict) else start_node_ref
                        labels_list = node_map.get(start_node_id)
                        if labels_list:
                            start_label = labels_list[0] # Looked up the label via ID

                    # Determine end node label
                    if isinstance(end_node_ref, dict) and 'name' in end_node_ref:
                        end_label = end_node_ref.get('name') # Label is in the dict directly
                    else:
                        end_node_id = end_node_ref.get('<id>') if isinstance(end_node_ref, dict) else end_node_ref
                        labels_list = node_map.get(end_node_id)
                        if labels_list:
                            end_label = labels_list[0] # Looked up the label via ID

                    if not start_label or not end_label:
                        print(f"Warning: Could not determine start or end node label from relationship tuple: {rel_tuple}")
                        continue

                    # Extract relationship type
                    rel_type = rel_info.get('name') if isinstance(rel_info, dict) else rel_info
                    if not rel_type:
                        continue

                    # Construct and store the relationship string
                    rel_str = f"(:{start_label})-[R:{rel_type}]->(:{end_label})"
                    if rel_str not in schema_info["relationships"]:
                         schema_info["relationships"].append(rel_str)

            print("Schema extraction successful.")
            return schema_info
        except Exception as e:
            print(f"An error occurred while fetching the schema: {e}")
            print("--- Full Traceback (from get_schema) ---")
            traceback.print_exc()
            print("----------------------------------------")
            return None

    def format_schema_for_llm(self, schema_info):
        """
        Formats the extracted schema into a human-readable and LLM-friendly string.
        """
        try:
            if not schema_info:
                return "Could not generate schema report due to an error."

            report = []
            report.append("Neo4j Graph Schema\n")
            report.append("=" * 20)
            report.append("\nThis document describes the schema of a Neo4j graph database. It is intended to be used by a Large Language Model to generate accurate Cypher queries.\n")

            # 1. Node Labels and Properties
            report.append("\n1. Node Labels and Properties\n")
            report.append("-" * 28)
            if schema_info.get("node_properties"):
                nodes_by_label = {}
                for item in schema_info["node_properties"]:
                    node_labels = item.get('nodeLabels')
                    if not node_labels:
                        continue
                    label = node_labels[0]
                    
                    if label not in nodes_by_label:
                        nodes_by_label[label] = []
                    
                    # FIX: Safely get property type, handling if it is None
                    property_types = item.get('propertyTypes')
                    prop_type_str = property_types[0] if property_types else 'Unknown'
                    prop_info = f"  - `{item.get('propertyName', 'N/A')}` ({prop_type_str})"
                    nodes_by_label[label].append(prop_info)

                for label, props in sorted(nodes_by_label.items()):
                    report.append(f"\n* **Node Label:** `:{label}`")
                    report.extend(sorted(props))
            else:
                report.append("No node properties found.")

            # 2. Relationship Types and Properties
            report.append("\n\n2. Relationship Types and Properties\n")
            report.append("-" * 33)
            if schema_info.get("rel_properties"):
                rels_by_type = {}
                for item in schema_info["rel_properties"]:
                    rel_type = item.get('relType', '').strip("`")
                    if not rel_type: continue
                    if rel_type not in rels_by_type:
                        rels_by_type[rel_type] = []

                    # FIX: Safely get property type, handling if it is None
                    property_types = item.get('propertyTypes')
                    prop_type_str = property_types[0] if property_types else 'Unknown'
                    prop_info = f"  - `{item.get('propertyName', 'N/A')}` ({prop_type_str})"
                    rels_by_type[rel_type].append(prop_info)
                
                for rel_type, props in sorted(rels_by_type.items()):
                    report.append(f"\n* **Relationship Type:** `[:{rel_type}]`")
                    report.extend(sorted(props))
            else:
                report.append("No relationship properties found.")

            # 3. Graph Schema (Connectivity)
            report.append("\n\n3. Relationship Schema (How Nodes are Connected)\n")
            report.append("-" * 47)
            if schema_info.get("relationships"):
                report.append("The following patterns exist in the graph:")
                for rel in sorted(schema_info["relationships"]):
                    report.append(f"- `{rel}`")
            else:
                report.append("No relationships found.")
                
            report.append("\n\n" + "="*20)
            report.append("\nEnd of Schema Report.")

            return "\n".join(report)
        except Exception as e:
            print(f"An error occurred while formatting the schema: {e}")
            print("--- Full Traceback (from format_schema_for_llm) ---")
            traceback.print_exc()
            print("--------------------------------------------------")
            return None

def main():
    """
    Main function to run the schema extraction process.
    """
    extractor = None
    try:
        extractor = Neo4jSchemaExtractor(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        schema_data = extractor.get_schema()
        
        if schema_data:
            formatted_schema = extractor.format_schema_for_llm(schema_data)
            
            # Check if formatting failed
            if formatted_schema is None:
                 print("Stopping process because schema formatting failed.")
                 return

            with open(OUTPUT_FILE_NAME, "w", encoding="utf-8") as f:
                f.write(formatted_schema)
            print(f"\nSchema has been successfully written to '{os.path.abspath(OUTPUT_FILE_NAME)}'")

    except Exception as e:
        print(f"A critical error occurred in the main process: {e}")
        print("--- Full Traceback (from main) ---")
        traceback.print_exc()
        print("----------------------------------")
    finally:
        if extractor:
            extractor.close()


if __name__ == "__main__":
    main()