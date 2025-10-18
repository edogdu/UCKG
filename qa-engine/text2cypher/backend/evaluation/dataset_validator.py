import csv
import json
import re
from typing import Any, Dict, List, Tuple

# Make sure to run: pip install neo4j pandas openpyxl
try:
    from neo4j import GraphDatabase
except ImportError:
    # This mock class allows the script to be loaded for validation even if the driver isn't installed.
    class GraphDatabase:
        @staticmethod
        def driver(uri, auth):
            print("Warning: neo4j-driver not installed. Grammar validation will be skipped.")
            return None

import pandas as pd


class DatasetValidator:
    """
    A class to load, handle, and validate a dataset of natural language questions
    and their corresponding Cypher queries against a graph schema.
    """

    def __init__(self, schema_file: str, neo4j_uri: str, neo4j_user: str, neo4j_pass: str):
        """
        Initializes the validator with the schema file and Neo4j credentials.
        """
        try:
            self.schema = self._load_schema(schema_file)
        except FileNotFoundError:
            print(f"Warning: Schema file '{schema_file}' not found. Schema validation will be limited.")
            self.schema = {"nodes": {}, "relationships": set()}

        self.driver = None
        if GraphDatabase and callable(getattr(GraphDatabase, 'driver', None)):
            try:
                self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
                if self.driver:
                    # verify_connectivity() can hang if the server is unreachable. Use a timeout.
                    # This is a conceptual addition; the actual driver doesn't have a simple timeout on verify_connectivity.
                    # For production, you'd handle this more robustly (e.g., in a separate thread).
                    print("Attempting to connect to Neo4j...")
                    self.driver.verify_connectivity()
                    print("Successfully connected to Neo4j.")
            except Exception as e:
                print(f"Error connecting to Neo4j: {e}")
                self.driver = None

    def _load_schema(self, schema_file: str) -> Dict[str, Any]:
        """
        Parses the schema_cache.txt file to extract nodes, properties, and relationships.
        """
        schema = {"nodes": {}, "relationships": set()}
        with open(schema_file, 'r', encoding='utf-8') as f:
            content = f.read()

        node_pattern = re.compile(r'(\w+)\s*{\s*(.*?)\s*}', re.DOTALL)
        rel_pattern = re.compile(r'\(:(\w+)\)\s*-\[:(\w+)\]->\s*\(:(\w+)\)')

        for match in node_pattern.finditer(content):
            node_name, props_str = match.groups()
            props = {p.split(':')[0].strip(): p.split(':')[1].strip() for p in props_str.split(',') if ':' in p}
            schema["nodes"][node_name] = props

        for match in rel_pattern.finditer(content):
            _, rel_type, _ = match.groups()
            schema["relationships"].add(rel_type)

        return schema

    def load_dataset(self, file_path: str) -> List[Dict[str, str]]:
        """
        Loads a dataset from various formats (csv, json, xlsx).
        """
        if file_path.endswith('.csv'):
            with open(file_path, 'r', encoding='utf-8') as f:
                return list(csv.DictReader(f))
        elif file_path.endswith('.json'):
            with open(file_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        elif file_path.endswith('.xlsx'):
            return pd.read_excel(file_path).to_dict('records')
        else:
            raise ValueError("Unsupported file format. Please use csv, json, or xlsx.")

    def validate_cypher_grammar(self, cypher_query: str) -> Tuple[bool, str]:
        """
        Validates the Cypher query's grammar using the EXPLAIN clause.
        """
        if not self.driver:
            return False, "Neo4j driver not available."
        try:
            with self.driver.session() as session:
                session.run(f"EXPLAIN {cypher_query}")
            return True, "Valid Cypher grammar."
        except Exception as e:
            return False, str(e)

    def validate_ner_consistency(self, question: str, cypher_query: str) -> Tuple[bool, str]:
        """
        Validates that string literals (entities) in the Cypher query are present
        in the natural language question.
        """
        cypher_entities = set(re.findall(r"['\"](.*?)['\"]", cypher_query))

        if not cypher_entities:
            return True, "No entities found in Cypher query to validate."

        missing_from_question = {entity for entity in cypher_entities if entity not in question}

        if not missing_from_question:
            return True, f"All entities from Cypher found in question. Entities: {cypher_entities}"
        else:
            return False, f"Entities from Cypher missing from question: {missing_from_question}"

    def validate_schema_compliance(
        self, 
        cypher_query: str, 
        expected_labels: set, 
        expected_rels: set, 
        expected_props: set
    ) -> Tuple[bool, str]:
        """
        Validates that the query's components match the expected sets for this specific entry.
        """
        # Extract actual components from the Cypher query string
        found_labels = set(re.findall(r':(\w+)', cypher_query))
        found_rels = set(re.findall(r'-\[:(\w+)\]->', cypher_query))
        found_props = set(re.findall(r'\w+\.(\w+)', cypher_query))

        # Compare found sets with expected sets
        missing_labels = expected_labels - found_labels
        extra_labels = found_labels - expected_labels

        missing_rels = expected_rels - found_rels
        extra_rels = found_rels - expected_rels

        missing_props = expected_props - found_props
        extra_props = found_props - expected_props
        
        # Build a comprehensive report of any issues
        errors = []
        if missing_labels: errors.append(f"Missing Labels: {missing_labels}")
        if extra_labels: errors.append(f"Unexpected Labels: {extra_labels}")
        if missing_rels: errors.append(f"Missing Relationships: {missing_rels}")
        if extra_rels: errors.append(f"Unexpected Relationships: {extra_rels}")
        if missing_props: errors.append(f"Missing Properties: {missing_props}")
        if extra_props: errors.append(f"Unexpected Properties: {extra_props}")

        if not errors:
            return True, "Schema compliance check passed."
        else:
            return False, "; ".join(errors)

    def run_all_validators(self, dataset: List[Dict[str, str]], output_file_path: str) -> None:
        """
        Runs all validators on the entire dataset and saves a report to a file.
        """
        # Since you mentioned storing printouts to a file in the past,
        # this function will continue to write the detailed validation report for you.
        with open(output_file_path, 'w', encoding='utf-8') as f:
            def log(message: str):
                """Helper function to print to console and write to file."""
                print(message)
                f.write(message + '\n')

            for i, row in enumerate(dataset):
                question = row['NaturalLanguageQuestion']
                query = row['CypherQuery']

                log(f"\n----- Validating Entry #{i+1} -----")
                log(f"Question: {question}")
                log(f"Query: {query}")

                # --- Grammar Validation ---
                is_valid_grammar, grammar_msg = self.validate_cypher_grammar(query)
                log(f"1. Grammar Check: {'PASS' if is_valid_grammar else 'FAIL'} - {grammar_msg}")

                # --- NER Consistency Validation (Hybrid Approach) ---
                is_ner_consistent, ner_msg = self.validate_ner_consistency(question, query)
                log(f"2. NER Check: {'PASS' if is_ner_consistent else 'FAIL'} - {ner_msg}")

                # --- New, More Precise Schema Compliance Validation ---
                try:
                    # The CSV stores these as stringified lists, so we use json.loads to parse them.
                    expected_labels = set(json.loads(row.get('ExpectedNodeLabels', '[]')))
                    expected_rels = set(json.loads(row.get('ExpectedRelationshipTypes', '[]')))
                    expected_props = set(json.loads(row.get('ExpectedProperties', '[]')))
                    
                    is_schema_compliant, schema_msg = self.validate_schema_compliance(
                        query, expected_labels, expected_rels, expected_props
                    )
                    log(f"3. Schema Check: {'PASS' if is_schema_compliant else 'FAIL'} - {schema_msg}")

                except (json.JSONDecodeError, KeyError) as e:
                    log(f"3. Schema Check: FAIL - Could not parse Expected columns. Error: {e}")

    def close(self):
        """Closes the Neo4j driver connection."""
        if self.driver:
            self.driver.close()
            print("\nNeo4j connection closed.")


if __name__ == '__main__':
    # --- Configuration ---
    # IMPORTANT: Replace with your actual Neo4j credentials and file paths.
    NEO4J_URI = "bolt://localhost:7687"
    NEO4J_USER = "neo4j"
    NEO4J_PASSWORD = "abcd90909090" # Change this to your password
    SCHEMA_FILE = 'schema_cache.txt'
    # Make sure to update these file paths to match your system
    DATASET_FILE = r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\dataset\neo4j_evaluation_dataset.csv'
    OUTPUT_FILE = r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\validation_log\validation_report.txt'

    # --- Execution ---
    validator = DatasetValidator(SCHEMA_FILE, NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)

    if validator.driver:
        try:
            dataset = validator.load_dataset(DATASET_FILE)
            print(f"Successfully loaded {len(dataset)} entries from {DATASET_FILE}")
            print(f"Validation report will be saved to {OUTPUT_FILE}")
            validator.run_all_validators(dataset, OUTPUT_FILE)
        except FileNotFoundError as e:
            print(f"Error: {e}. Please make sure the file paths are correct.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        finally:
            validator.close()
    else:
        print("Cannot run validations because the connection to Neo4j failed or driver is not installed.")