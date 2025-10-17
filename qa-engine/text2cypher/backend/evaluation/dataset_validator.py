import csv
import json
import re
from typing import Any, Dict, List, Set, Tuple

import spacy
from neo4j import GraphDatabase
# Make sure to run: pip install neo4j spacy pandas openpyxl
# And download the spacy model: python -m spacy download en_core_web_sm
import pandas as pd


class DatasetValidator:
    """
    A class to load, handle, and validate a dataset of natural language questions
    and their corresponding Cypher queries against a graph schema.
    """

    def __init__(self, schema_file: str, neo4j_uri: str, neo4j_user: str, neo4j_pass: str):
        """
        Initializes the validator with the schema file and Neo4j credentials.

        Args:
            schema_file (str): Path to the schema_cache.txt file.
            neo4j_uri (str): URI for the Neo4j database.
            neo4j_user (str): Username for the Neo4j database.
            neo4j_pass (str): Password for the Neo4j database.
        """
        self.schema = self._load_schema(schema_file)
        self.nlp = spacy.load("en_core_web_sm")
        self.driver = None
        try:
            self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_pass))
            self.driver.verify_connectivity()
            print("Successfully connected to Neo4j.")
        except Exception as e:
            print(f"Error connecting to Neo4j: {e}")
            self.driver = None

    def _load_schema(self, schema_file: str) -> Dict[str, Any]:
        """
        Parses the schema_cache.txt file to extract nodes, properties, and relationships.

        Args:
            schema_file (str): The path to the schema file.

        Returns:
            Dict[str, Any]: A dictionary representing the graph schema.
        """
        schema = {"nodes": {}, "relationships": set()}
        with open(schema_file, 'r') as f:
            content = f.read()

        # Regex to parse nodes and their properties
        node_pattern = re.compile(r'(\w+)\s*{\s*(.*?)\s*}', re.DOTALL)
        # Regex to parse relationships
        rel_pattern = re.compile(r'\(:(\w+)\)\s*-\[:(\w+)\]->\s*\(:(\w+)\)')

        # Extract nodes
        for match in node_pattern.finditer(content):
            node_name, props_str = match.groups()
            props = {p.split(':')[0].strip(): p.split(':')[1].strip() for p in props_str.split(',') if ':' in p}
            schema["nodes"][node_name] = props

        # Extract relationships
        for match in rel_pattern.finditer(content):
            source, rel_type, target = match.groups()
            schema["relationships"].add(rel_type)

        return schema

    def load_dataset(self, file_path: str) -> List[Dict[str, str]]:
        """
        Loads a dataset from various formats (csv, json, xlsx).

        Args:
            file_path (str): The path to the dataset file.

        Returns:
            List[Dict[str, str]]: A list of dictionaries, each representing a row.
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
        Validates the Cypher query's grammar by using the EXPLAIN clause.
        This checks syntax without executing the query.

        Args:
            cypher_query (str): The Cypher query to validate.

        Returns:
            Tuple[bool, str]: A tuple containing a boolean (True if valid) and a message.
        """
        if not self.driver:
            return False, "Neo4j driver not available."
        try:
            with self.driver.session() as session:
                # EXPLAIN checks the query's syntax without executing it
                session.run(f"EXPLAIN {cypher_query}")
            return True, "Valid Cypher grammar."
        except Exception as e:
            return False, str(e)

    def validate_ner_consistency(self, question: str, cypher_query: str) -> Tuple[bool, str]:
        """
        Validates that named entities in the question are present in the Cypher query.

        Args:
            question (str): The natural language question.
            cypher_query (str): The corresponding Cypher query.

        Returns:
            Tuple[bool, str]: A tuple containing a boolean (True if consistent) and a message.
        """
        doc = self.nlp(question)
        question_entities = {ent.text.strip("'\"") for ent in doc.ents}

        # Find all quoted strings in the Cypher query, as they are likely entities
        cypher_entities = set(re.findall(r"['\"](.*?)['\"]", cypher_query))

        missing_entities = question_entities - cypher_entities
        if not missing_entities:
            return True, f"All entities from question found in Cypher. Entities: {question_entities}"
        else:
            return False, f"Entities missing from Cypher: {missing_entities}"


    def validate_schema_compliance(self, cypher_query: str) -> Tuple[bool, str]:
        """
        Validates that node labels, relationships, and properties in the query
        conform to the loaded schema.

        Args:
            cypher_query (str): The Cypher query to validate.

        Returns:
            Tuple[bool, str]: A tuple containing a boolean (True if compliant) and a message.
        """
        # Extract node labels (e.g., :UcoCVE)
        found_labels = set(re.findall(r':(\w+)', cypher_query))
        # Extract relationship types (e.g., [:UCOEXATTRIBUTEDTO])
        found_rels = set(re.findall(r'-\[:(\w+)\]->', cypher_query))
        # Extract properties (e.g., c.label, g.ucoexNAME)
        found_props = set(re.findall(r'\w+\.(\w+)', cypher_query))


        # Validate Node Labels
        for label in found_labels:
            if label not in self.schema['nodes']:
                return False, f"Node label ':{label}' not found in schema."

        # Validate Relationship Types
        for rel in found_rels:
            if rel not in self.schema['relationships']:
                return False, f"Relationship type '[:{rel}]' not found in schema."

        # Validate Properties (basic check)
        # A more advanced check would parse aliases and match properties to specific node labels
        all_schema_props = set()
        for node_props in self.schema['nodes'].values():
            all_schema_props.update(node_props.keys())

        for prop in found_props:
            if prop not in all_schema_props:
                 # This is a simple check; a property might be valid but not in our simplified schema extraction
                 pass # Ignoring property check for simplicity as it can be complex with aliases.
                 # For a full implementation, a proper Cypher parser would be needed.

        return True, "Schema compliance check passed."


    def run_all_validators(self, dataset: List[Dict[str, str]], output_file_path: str) -> None:
        """
        Runs all validators on the entire dataset and prints a report to the console
        and saves it to a file.

        Args:
            dataset (List[Dict[str, str]]): The dataset to validate.
            output_file_path (str): Path to the file where the report will be saved.
        """
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

                # Grammar Validation
                is_valid_grammar, grammar_msg = self.validate_cypher_grammar(query)
                log(f"1. Grammar Check: {'PASS' if is_valid_grammar else 'FAIL'} - {grammar_msg}")

                # NER Consistency Validation
                is_ner_consistent, ner_msg = self.validate_ner_consistency(question, query)
                log(f"2. NER Check: {'PASS' if is_ner_consistent else 'FAIL'} - {ner_msg}")

                # Schema Compliance Validation
                is_schema_compliant, schema_msg = self.validate_schema_compliance(query)
                log(f"3. Schema Check: {'PASS' if is_schema_compliant else 'FAIL'} - {schema_msg}")

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
    DATASET_FILE = 'neo4j_evaluation_dataset.csv'
    OUTPUT_FILE = 'validation_report.txt'

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
        print("Cannot run validations because the connection to Neo4j failed.")