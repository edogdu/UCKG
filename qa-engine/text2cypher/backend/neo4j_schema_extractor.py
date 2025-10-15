import os
import re
import traceback
from neo4j import GraphDatabase

# --- Configuration ---
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "abcd90909090" # Replace with your actual password
FULL_SCHEMA_FILE_NAME = "neo4j_graph_schema.txt"
FILTERED_SCHEMA_FILE_NAME = "filtered_neo4j_schema.txt"

class Neo4jSchemaExtractor:
    """
    Connects to a Neo4j database to extract its schema.
    It produces two files: a complete schema dump and a filtered version
    containing only domain-specific "useful" information for an LLM.
    """

    def __init__(self, uri, user, password):
        """
        Initializes the extractor and defines the filters for the "useful" schema.
        """
        self.uri = uri
        self.user = user
        self.password = password
        self.driver = None

        # Define the cybersecurity-specific labels and relationships for filtering
        self.useful_labels = {
            "UcoCVE", "UcoCWE", "UcoVulnerability", "UcoExploitTarget", "UcoexCAPEC", 
            "UcoexCPE", "UcoexMITREATTACK", "UcoexMITRED3FEND", "UcoexObservedExample", 
            "SymmetricProperty"
        }
        self.useful_relationships = {
            "UCOEXEXAMPLEOBSERVEDIN", "UCOEXHASCPE", "UCOEXHASMITREATTACK", 
            "UCOEXHASRELATEDWEAKNESS", "UCOEXHASTAXONOMYMAPPING", "UCOHASCVE_ID", 
            "UCOHASOBSERVEDEXAMPLE", "UCOHASVULNERABILITY", "UCOHASWEAKNESS", "DOMAIN"
        }
        
        try:
            self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
            self.driver.verify_connectivity()
            print("Successfully connected to Neo4j database.")
        except Exception as e:
            print(f"Error: Could not connect to Neo4j. Please check your credentials and connection settings.")
            print(f"Details: {e}")
            raise

    def close(self):
        """ Closes the database connection. """
        if self.driver:
            self.driver.close()
            print("Neo4j connection closed.")

    def get_schema(self):
        """ 
        Fetches the complete schema from the database using a more robust direct
        query method instead of relying on potentially misleading built-in procedures.
        """
        print("Extracting schema from the database...")
        schema_info = {
            "node_properties": [],
            "rel_properties": [],
            "relationships": []
        }
        try:
            with self.driver.session() as session:
                # 1. Get node labels and their properties (this part is usually reliable)
                schema_info["node_properties"] = session.run("CALL db.schema.nodeTypeProperties()").data()
                
                # 2. Get relationship properties (if any)
                schema_info["rel_properties"] = session.run("CALL db.schema.relTypeProperties()").data()
                
                # 3. Robustly get relationship schema by directly querying the graph
                rel_query = """
                MATCH (start_node)-[rel]->(end_node)
                RETURN DISTINCT labels(start_node) AS start_labels, 
                                type(rel) AS rel_type, 
                                labels(end_node) AS end_labels
                LIMIT 500 
                """
                results = session.run(rel_query).data()
                
                for record in results:
                    start_labels = record['start_labels']
                    end_labels = record['end_labels']
                    rel_type = record['rel_type']

                    # Prefer the more specific label over generic ones like 'Resource'
                    start_label = next((l for l in start_labels if l != 'Resource'), start_labels[0])
                    end_label = next((l for l in end_labels if l != 'Resource'), end_labels[0])

                    if start_label and end_label and rel_type:
                        rel_str = f"(:{start_label})-[R:{rel_type}]->(:{end_label})"
                        if rel_str not in schema_info["relationships"]:
                            schema_info["relationships"].append(rel_str)
                            
            print("Schema extraction successful.")
            return schema_info
        except Exception as e:
            print(f"An error occurred while fetching the schema: {e}")
            traceback.print_exc()
            return None

    def format_schema_for_llm(self, schema_info, filter_useful=False):
        """
        Formats the schema into a readable string, optionally filtering for useful items.
        """
        if not schema_info:
            return "Could not generate schema report due to an error."

        report_title = "Filtered Neo4j Graph Schema" if filter_useful else "Neo4j Graph Schema"
        report = [report_title + "\n" + "=" * len(report_title)]
        report.append("\nThis document describes the schema of a Neo4j graph database. It is intended to be used by a Large Language Model to generate accurate Cypher queries.\n")

        # 1. Node Labels and Properties
        report.append("\n1. Node Labels and Properties\n" + "-" * 28)
        nodes_by_label = {}
        for item in schema_info.get("node_properties", []):
            for label in item.get('nodeLabels', []):
                if filter_useful and label not in self.useful_labels:
                    continue
                if label not in nodes_by_label:
                    nodes_by_label[label] = []
                
                # --- FIX IS HERE ---
                # Robustly handle cases where propertyTypes might be None
                property_types = item.get('propertyTypes')
                prop_type = property_types[0] if property_types else 'Unknown'
                # --- END OF FIX ---

                prop_info = f"  - `{item.get('propertyName', 'N/A')}` ({prop_type})"
                if prop_info not in nodes_by_label[label]:
                    nodes_by_label[label].append(prop_info)
        for label, props in sorted(nodes_by_label.items()):
            report.append(f"\n* **Node Label:** `:{label}`")
            report.extend(sorted(props))

        # 2. Relationship Types and Properties
        report.append("\n\n2. Relationship Types and Properties\n" + "-" * 33)
        rels_by_type = {}
        for item in schema_info.get("rel_properties", []):
            rel_type = item.get('relType', '').strip("`")
            if not rel_type or (filter_useful and rel_type not in self.useful_relationships):
                continue
            
            if rel_type not in rels_by_type:
                rels_by_type[rel_type] = []
            
            # --- FIX IS HERE ---
            # Applied the same robust handling here
            property_types = item.get('propertyTypes')
            prop_type = property_types[0] if property_types else 'Unknown'
            # --- END OF FIX ---
            
            prop_info = f"  - `{item.get('propertyName', 'N/A')}` ({prop_type})"
            if prop_info not in rels_by_type[rel_type]:
                rels_by_type[rel_type].append(prop_info)

        if not rels_by_type:
            report.append("No relationship properties found.")
        else:
            for rel_type, props in sorted(rels_by_type.items()):
                report.append(f"\n* **Relationship Type:** `[:{rel_type}]`")
                report.extend(sorted(props))


        # 3. Relationship Schema (Connectivity)
        report.append("\n\n3. Relationship Schema (How Nodes are Connected)\n" + "-" * 47)
        report.append("The following patterns exist in the graph:")
        found_rels = False
        rel_pattern = re.compile(r"\(:(\w+)\)-\[R:(\w+)\]->\(:(\w+)\)")
        for rel_str in sorted(schema_info.get("relationships", [])):
            match = rel_pattern.match(rel_str)
            if not match: continue
            start_label, rel_type, end_label = match.groups()
            if filter_useful:
                if (start_label in self.useful_labels and 
                    end_label in self.useful_labels and 
                    rel_type in self.useful_relationships):
                    report.append(f"- `{rel_str}`")
                    found_rels = True
            else:
                report.append(f"- `{rel_str}`")
                found_rels = True
        if not found_rels:
            report.append("No matching relationships found.")

        report.append("\n\n" + "=" * 20 + "\nEnd of Schema Report.")
        return "\n".join(report)

def main():
    """
    Main function to run the schema extraction and file writing process.
    """
    extractor = None
    try:
        extractor = Neo4jSchemaExtractor(NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)
        schema_data = extractor.get_schema()
        
        if schema_data:
            # --- 1. Generate and save the FULL schema report ---
            full_schema_report = extractor.format_schema_for_llm(schema_data, filter_useful=False)
            if full_schema_report:
                with open(FULL_SCHEMA_FILE_NAME, "w", encoding="utf-8") as f:
                    f.write(full_schema_report)
                print(f"\n✅ Full schema has been written to '{os.path.abspath(FULL_SCHEMA_FILE_NAME)}'")
            
            # --- 2. Generate and save the FILTERED schema report ---
            filtered_schema_report = extractor.format_schema_for_llm(schema_data, filter_useful=True)
            if filtered_schema_report:
                with open(FILTERED_SCHEMA_FILE_NAME, "w", encoding="utf-8") as f:
                    f.write(filtered_schema_report)
                print(f"✅ Filtered (useful) schema has been written to '{os.path.abspath(FILTERED_SCHEMA_FILE_NAME)}'")

    except Exception as e:
        print(f"\nA critical error occurred: {e}")
        traceback.print_exc()
    finally:
        if extractor:
            extractor.close()

if __name__ == "__main__":
    main()