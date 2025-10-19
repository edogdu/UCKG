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

# You will need to install this library: pip install sentence-transformers
try:
    from sentence_transformers import SentenceTransformer, util
    model = SentenceTransformer('all-MiniLM-L6-v2') # This will be downloaded on first run
    SENTENCE_TRANSFORMER_AVAILABLE = True
except ImportError:
    print("Warning: sentence-transformers is not installed. Semantic relevance check will be skipped.")
    print("Please run 'pip install sentence-transformers' to enable it.")
    SENTENCE_TRANSFORMER_AVAILABLE = False

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

    # Add this inside the DatasetValidator class, maybe after __init__
    def _setup_loggers(self, log_directory: str):
        """Sets up file handlers for different validation checks."""
        self.log_files = {
            'schema': open(f"{log_directory}/schema_check.txt", 'w', encoding='utf-8'),
            'execution': open(f"{log_directory}/cypher_check.txt", 'w', encoding='utf-8'),
            'entity': open(f"{log_directory}/entity_check.txt", 'w', encoding='utf-8'),
            'relevance': open(f"{log_directory}/question_cypher_relevance.txt", 'w', encoding='utf-8'),
            'duplication': open(f"{log_directory}/duplication_check.txt", 'w', encoding='utf-8'),
        }

    def _log(self, check_type: str, message: str):
        """Logs a message to the appropriate file."""
        if check_type in self.log_files:
            self.log_files[check_type].write(message + '\n')

    # Also add this to the DatasetValidator class
    def close_loggers(self):
        """Closes all open log files."""
        for f in self.log_files.values():
            f.close()
        print(f"\nAll validation logs have been saved.")

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

    # *** NEW FUNCTION TO CHECK FOR DUPLICATES ***
    def check_for_duplicates(self, dataset: List[Dict[str, str]]) -> bool:
        """
        Checks for duplicate NaturalLanguageQuestion entries in the dataset.
        Logs any duplicates found and returns True if duplicates exist, otherwise False.
        """
        print("\nChecking for duplicate questions...")
        seen_questions = {}
        for i, row in enumerate(dataset):
            # Normalize whitespace and make case-insensitive for better matching
            question = row.get('NaturalLanguageQuestion', '').strip().lower()
            if question:
                if question not in seen_questions:
                    seen_questions[question] = []
                seen_questions[question].append(i + 1) # Use 1-based indexing for entry ID

        # Filter out questions that are not duplicates
        duplicates = {q: locs for q, locs in seen_questions.items() if len(locs) > 1}

        if not duplicates:
            self._log('duplication', "PASS - No duplicate questions found in the dataset.")
            print("PASS - No duplicate questions found.")
            return False
        else:
            self._log('duplication', f"FAIL - Found {len(duplicates)} duplicate questions.")
            print(f"FAIL - Found {len(duplicates)} duplicate questions. See duplication_check.txt for details.")
            for question, entry_ids in duplicates.items():
                self._log('duplication', f"  - Question: '{question}' | Found at entries: {entry_ids}")
            return True

    # Add this method to the DatasetValidator class
    def validate_schema_elements(self, cypher_query: str, entry_id: int) -> bool:
        """
        Checks if all labels, relationships, and properties in a query
        exist in the graph schema loaded from schema_cache.txt.
        """
        # --- ENHANCED ENTITY DETECTION ---
        # 1. FIX: Find labels only within node patterns like (n:Label) or (:Label).
        # This avoids matching colons inside string literals (e.g., in a datetime).
        found_labels = set(re.findall(r'\(\w*:(\w+)', cypher_query))

        # 2. FIX: Find relationship types only within relationship patterns like [r:REL_TYPE] or [:REL_TYPE].
        # This is more precise and direction-agnostic.
        found_rels = set(re.findall(r'\[\w*:(\w+)', cypher_query))

        # 3. FIX: Use the robust, two-part property detection.
        props_dot_notation = set(re.findall(r'\w+\.(\w+)', cypher_query))
        props_map_notation = set(re.findall(r'{\s*(\w+)\s*:', cypher_query))
        found_props = props_dot_notation.union(props_map_notation)

        errors = []
        # Check labels
        for label in found_labels:
            if label not in self.schema['nodes']:
                errors.append(f"Label ':{label}' not in schema.")
        
        # Check relationships
        for rel in found_rels:
            if rel not in self.schema['relationships']:
                errors.append(f"Relationship '-[:{rel}]->' not in schema.")
        
        # Check properties
        for prop in found_props:
            prop_found_in_schema = any(prop in props for props in self.schema['nodes'].values())
            if not prop_found_in_schema:
                errors.append(f"Property '.{prop}' not found on any node in schema.")

        if not errors:
            self._log('schema', f"Entry #{entry_id}: PASS")
            return True
        else:
            self._log('schema', f"Entry #{entry_id}: FAIL - Query: {cypher_query} | Issues: {'; '.join(errors)}")
            return False

    # Add this method to the DatasetValidator class
    def validate_query_executability(self, cypher_query: str, entry_id: int) -> bool:
        """
        Checks if a Cypher query can be executed without error.
        Replaces or appends a 'LIMIT 1' clause to ensure the check is fast.
        """
        if not self.driver:
            self._log('execution', f"Entry #{entry_id}: SKIP - Neo4j driver not available.")
            return False

        # Use regex to find and replace any existing LIMIT clause.
        # The `re.IGNORECASE` flag handles both 'limit' and 'LIMIT'.
        if re.search(r'\bLIMIT\b', cypher_query, re.IGNORECASE):
            # If a LIMIT clause exists, replace it with 'LIMIT 1'
            test_query = re.sub(r'\bLIMIT\b\s+\d+', 'LIMIT 1', cypher_query, flags=re.IGNORECASE)
        else:
            # Otherwise, append 'LIMIT 1'
            test_query = cypher_query + " LIMIT 1"

        try:
            with self.driver.session() as session:
                session.run(test_query)
            self._log('execution', f"Entry #{entry_id}: PASS")
            return True
        except Exception as e:
            error_msg = str(e).replace('\n', ' ')
            self._log('execution', f"Entry #{entry_id}: FAIL - Query: {cypher_query} | Error: {error_msg}")
            return False

    # RENAME the existing `validate_schema_compliance` function to this:
    def validate_expected_entities_match_query(
        self,
        cypher_query: str,
        row: dict,
        entry_id: int
    ) -> bool:
        """
        Validates that the query's components match the expected sets from the dataset file.
        This version uses more robust regex to find properties in both dot notation (n.prop)
        and map notation ({prop: 'value'}).
        """
        try:
            expected_labels = set(json.loads(row.get('ExpectedNodeLabels', '[]')))
            expected_rels = set(json.loads(row.get('ExpectedRelationshipTypes', '[]')))
            expected_props = set(json.loads(row.get('ExpectedProperties', '[]')))
        except (json.JSONDecodeError, KeyError) as e:
            self._log('entity', f"Entry #{entry_id}: FAIL - Could not parse Expected columns. Error: {e}")
            return False

        # --- ENHANCED ENTITY DETECTION ---
        # 1. FIX: Find labels only within node patterns like (n:Label) or (:Label).
        # This avoids matching colons inside string literals (e.g., in a datetime).
        found_labels = set(re.findall(r'\(\w*:(\w+)', cypher_query))

        # 2. FIX: Find relationship types only within relationship patterns like [r:REL_TYPE] or [:REL_TYPE].
        # This is more precise and direction-agnostic.
        found_rels = set(re.findall(r'\[\w*:(\w+)', cypher_query))

        # --- ENHANCED PROPERTY DETECTION (No changes needed here) ---
        # 1. Finds properties in dot notation (e.g., c.label, r.name)
        props_dot_notation = set(re.findall(r'\w+\.(\w+)', cypher_query))
        # 2. Finds properties used as keys inside curly braces (e.g., {label: '...'})
        props_map_notation = set(re.findall(r'{\s*(\w+)\s*:', cypher_query))
        # Combine both sets to get all found properties
        found_props = props_dot_notation.union(props_map_notation)

        if found_labels == expected_labels and found_rels == expected_rels and found_props == expected_props:
            self._log('entity', f"Entry #{entry_id}: PASS")
            return True
        else:
            errors = []
            if expected_labels != found_labels: errors.append(f"Label mismatch: Expected {expected_labels}, Found {found_labels}")
            if expected_rels != found_rels: errors.append(f"Relationship mismatch: Expected {expected_rels}, Found {found_rels}")
            if expected_props != found_props: errors.append(f"Property mismatch: Expected {expected_props}, Found {found_props}")
            self._log('entity', f"Entry #{entry_id}: FAIL - Query: {cypher_query} | Issues: {'; '.join(errors)}")
            return False

    # RENAME the existing `validate_ner_consistency` to this for clarity:
    def validate_semantic_relevance(self, question: str, cypher_query: str, entry_id: int, threshold: float = 0.7) -> bool:
        """
        Validates semantic relevance between the question and the Cypher query
        using a sentence-transformer model.
        """
        if not SENTENCE_TRANSFORMER_AVAILABLE:
            self._log('relevance', f"Entry #{entry_id}: SKIP - sentence-transformers library not available.")
            return False

        # 1. Encode both the question and the query into vector embeddings
        embedding1 = model.encode(question, convert_to_tensor=True)
        embedding2 = model.encode(cypher_query, convert_to_tensor=True)

        # 2. Compute cosine similarity
        cosine_score = util.pytorch_cos_sim(embedding1, embedding2).item()

        # 3. Check if the score is above the threshold
        if cosine_score >= threshold:
            self._log('relevance', f"Entry #{entry_id}: PASS (Similarity: {cosine_score:.4f})")
            return True
        else:
            self._log('relevance', f"Entry #{entry_id}: FAIL - Question: '{question}' | Query: '{cypher_query}' | Similarity: {cosine_score:.4f} is below threshold of {threshold}")
            return False

    # REPLACE the old `run_all_validators` with this one.
    def run_all_validators(self, dataset: List[Dict[str, str]]) -> None:
        """
        Runs all validation stages on the entire dataset and saves reports to separate files.
        """
        total_entries = len(dataset)
        pass_counts = {'schema': 0, 'execution': 0, 'entity': 0, 'relevance': 0}

        print("\nStarting validation process...")

        for i, row in enumerate(dataset):
            entry_id = i + 1
            question = row['NaturalLanguageQuestion']
            query = row['CypherQuery']
            
            print(f"Processing Entry {entry_id}/{total_entries}...")

            # 1. Schema Check
            if self.validate_schema_elements(query, entry_id):
                pass_counts['schema'] += 1
                
            # 2. Cypher Executability Check
            if self.validate_query_executability(query, entry_id):
                pass_counts['execution'] += 1

            # 3. Entity Extraction Check
            if self.validate_expected_entities_match_query(query, row, entry_id):
                pass_counts['entity'] += 1
            
            # 4. Question-Cypher Relevance Check
            if self.validate_semantic_relevance(question, query, entry_id):
                pass_counts['relevance'] += 1

        print("\n----- Validation Summary -----")
        for check_type, count in pass_counts.items():
            print(f"{check_type.capitalize()} Check PASSED: {count}/{total_entries} ({(count/total_entries):.2%})")
        print("----------------------------")

    def close(self):
        """Closes the Neo4j driver connection."""
        if self.driver:
            self.driver.close()
            print("\nNeo4j connection closed.")


# Modify the `if __name__ == '__main__':` block at the bottom
if __name__ == '__main__':
    # --- Configuration ---
    NEO4J_URI = "bolt://localhost:7687"
    NEO4J_USER = "neo4j"
    NEO4J_PASSWORD = "abcd90909090"
    SCHEMA_FILE = 'schema_cache.txt'
    DATASET_FILE = r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\dataset\neo4j_evaluation_dataset.csv'
    # Define the directory for logs
    LOG_DIRECTORY = r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\validation_log'

    # --- Execution ---
    validator = DatasetValidator(SCHEMA_FILE, NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)

    if validator.driver:
        try:
            dataset = validator.load_dataset(DATASET_FILE)
            print(f"Successfully loaded {len(dataset)} entries.")
            
            # Set up the log files
            validator._setup_loggers(LOG_DIRECTORY)
            print(f"Validation reports will be saved to {LOG_DIRECTORY}")
            
            # First, check for duplicates. The script will halt if any are found.
            if validator.check_for_duplicates(dataset):
                print("\nDuplicate questions found. Halting further validation.")
            else:
                # If no duplicates are found, proceed with all other validations.
                validator.run_all_validators(dataset) 

        except FileNotFoundError as e:
            print(f"Error: {e}. Please make sure the file paths are correct.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        finally:
            validator.close_loggers() # Close log files
            validator.close() # Close Neo4j connection
    else:
        print("Cannot run validations because connection to Neo4j failed.")