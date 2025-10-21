import csv
import json
import re
import sys
from typing import Any, Dict, List

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
        """Sets up file handlers for all validation checks."""
        self.log_files = {
            'duplication': open(f"{log_directory}/duplication_check.txt", 'w', encoding='utf-8'),
            'schema': open(f"{log_directory}/schema_check.txt", 'w', encoding='utf-8'),
            'execution': open(f"{log_directory}/cypher_check.txt", 'w', encoding='utf-8'),
            'entity': open(f"{log_directory}/entity_check.txt", 'w', encoding='utf-8'),
            'relevance': open(f"{log_directory}/question_cypher_relevance.txt", 'w', encoding='utf-8'),
            'value': open(f"{log_directory}/value_check.txt", 'w', encoding='utf-8'), # <-- This is the new line
        }

    def _log(self, check_type: str, message: str):
        """Logs a message to the appropriate file."""
        if check_type in self.log_files:
            self.log_files[check_type].write(message + '\n')

    # Also add this to the DatasetValidator class
    def close_loggers(self):
        """Closes all open log files if they were created."""
        if hasattr(self, 'log_files'):
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

    # Helper function to count hops
    def _count_hops(self, cypher_query: str) -> int:
        """Counts the number of relationship traversals '-->' or '<--' in a query."""
        return len(re.findall(r'-->|<--', cypher_query))

    # Helper function to extract literal values
    def _extract_literal_values_from_query(self, cypher_query: str) -> list:
        """
        Extracts string, numeric, and boolean data literals from a Cypher query,
        while attempting to ignore literals used for query syntax (e.g., LIMIT, 
        SKIP, path lengths).
        """
        
        # 1. Create a copy of the query to "clean"
        cleaned_query = cypher_query
        
        # 2. Remove literals associated with LIMIT and SKIP clauses
        # This replaces "LIMIT 10" with "LIMIT "
        cleaned_query = re.sub(r'\b(LIMIT|SKIP)\s+\d+\b', r'\1 ', cleaned_query, flags=re.IGNORECASE)
        
        # 3. NEW: Remove literals from variable-length path definitions
        # This replaces "[*2]", "[*3..5]", or "[*..2]" with "[]"
        cleaned_query = re.sub(r'\[\*.+?\]', '[]', cleaned_query)
        
        # 4. Original regex to find remaining "data" literals
        # This regex finds:
        # 1. Strings in single or double quotes
        # 2. Standalone numbers (integers or floats)
        # 3. The boolean values true/false
        pattern = re.compile(r"""
            (["'])(.*?)\1 |       # Group 1 & 2: Quoted strings
            \b(\d+(?:\.\d+)?)\b |  # Group 3: Numbers (integer or float)
            \b(true|false)\b      # Group 4: Booleans
        """, re.VERBOSE | re.IGNORECASE)

        matches = pattern.findall(cleaned_query)
        
        # The findall returns tuples like ('"', 'value', '', ''). We need to flatten them.
        literals = [group[1] or group[2] or group[3] for group in matches]
        
        # Return unique, sorted literals, filtering out potential empty strings
        return sorted(list(set(l for l in literals if l)))

    # --- UPDATED ENRICHMENT FUNCTION ---
    def enrich_dataset(self, dataset: List[Dict[str, str]]) -> List[Dict[str, str]]:
        """
        Parses Cypher queries to populate all helper columns for the dataset.
        """
        print("\nEnriching dataset...")
        for row in dataset:
            cypher_query = str(row.get('CypherQuery', ''))
            found_labels = set(re.findall(r'\(\w*:(\w+)', cypher_query))
            found_rels = set(re.findall(r'\[\w*:(\w+)', cypher_query))
            props_dot = set(re.findall(r'\w+\.(\w+)', cypher_query))
            props_map = set(re.findall(r'{\s*(\w+)\s*:', cypher_query))
            found_props = props_dot.union(props_map)

            row['ExpectedNodeLabels'] = json.dumps(sorted(list(found_labels)))
            row['ExpectedRelationshipTypes'] = json.dumps(sorted(list(found_rels)))
            row['ExpectedProperties'] = json.dumps(sorted(list(found_props)))
            row['Hops'] = self._count_hops(cypher_query)
            row['ExtractedPropertyValues'] = json.dumps(self._extract_literal_values_from_query(cypher_query))
        print("Dataset enrichment complete.")
        return dataset
    

    # --- VALIDATION FUNCTIONS ---

    def check_for_initial_duplicates(self, dataset: List[Dict[str, str]]) -> bool:
        """
        Strictly checks for duplicate (Question, Cypher) pairs in the raw dataset.
        """
        print("\nRunning initial check for duplicate Question/Cypher pairs...")
        seen_pairs = {}
        for i, row in enumerate(dataset):
            question = str(row.get('NaturalLanguageQuestion', '')).strip().lower()
            query = str(row.get('CypherQuery', '')).strip()
            pair = (question, query)
            if pair not in seen_pairs: seen_pairs[pair] = []
            seen_pairs[pair].append(i + 1)

        duplicates = {p: locs for p, locs in seen_pairs.items() if len(locs) > 1}
        if not duplicates:
            self._log('duplication', "INITIAL CHECK: PASS - No duplicate Question/Cypher pairs found.")
            print("PASS - No duplicate Question/Cypher pairs found.")
            return False
        else:
            self._log('duplication', f"INITIAL CHECK: FAIL - Found {len(duplicates)} duplicate Question/Cypher pairs.")
            print(f"FAIL - Found {len(duplicates)} duplicate pairs. See duplication_check.txt for details.")
            for (q, c), entry_ids in duplicates.items():
                self._log('duplication', f"  - Question: '{q}' | Cypher: '{c}' | Found at entries: {entry_ids}")
            return True

    def validate_extracted_values_in_question(self, question: str, row: dict, entry_id: int) -> bool:
        """
        Checks if literal values from the Cypher query are present in the question.
        This version is more robust, ignoring common non-data literals and values
        found in LIMIT/SKIP clauses, and using flexible word matching.
        """
        # A set of common, non-data literals to ignore during validation.
        # These are often programming constructs, not factual data from the question.
        IGNORE_LIST = {'true', 'false', '1', '0'}

        try:
            extracted_values = json.loads(row.get('ExtractedPropertyValues', '[]'))
        except (json.JSONDecodeError, KeyError):
            self._log('value', f"Entry #{entry_id}: FAIL - Could not parse ExtractedPropertyValues column.")
            return False
        
        # Get the Cypher query to check against for LIMIT/SKIP clauses
        cypher_query = row.get('CypherQuery', '').lower()

        # If there are no values to check, it's an automatic pass.
        if not extracted_values:
            self._log('value', f"Entry #{entry_id}: PASS - No literal values to check.")
            return True

        mismatched_values = []
        # Prepare the question by making it lowercase and splitting it into a set of unique words.
        question_words = set(re.split(r'\s|\W', question.lower()))

        for value in extracted_values:
            value_str = str(value).lower()

            # 1. Skip this value if it's in our ignore list.
            if value_str in IGNORE_LIST:
                continue

            # 2. NEW CHECK: Skip if the value is part of a LIMIT or SKIP clause
            # This prevents flagging syntax numbers (like 'LIMIT 10') as data.
            # We use word boundaries (\b) to ensure we match '10' and not '100'.
            if re.search(r'\b(limit|skip)\s+' + re.escape(value_str) + r'\b', cypher_query):
                continue

            # 3. Use flexible word matching (Original step 2).
            # Split the value into words and check for any intersection with question words.
            value_words = set(re.split(r'\s|\W', value_str))
            
            # The intersection finds any common words between the two sets.
            if not value_words.intersection(question_words):
                mismatched_values.append(str(value))

        if not mismatched_values:
            self._log('value', f"Entry #{entry_id}: PASS")
            return True
        else:
            self._log('value', f"Entry #{entry_id}: FAIL - Values {mismatched_values} from Cypher not in Question: '{question}'")
            return False

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
        """Runs the complete validation suite on the enriched dataset."""
        total_entries = len(dataset)
        pass_counts = {'schema': 0, 'execution': 0, 'entity': 0, 'relevance': 0, 'value': 0}

        print("\nStarting full validation process...")
        for i, row in enumerate(dataset):
            entry_id = i + 1
            question = str(row['NaturalLanguageQuestion'])
            query = str(row['CypherQuery'])
            
            print(f"Processing Entry {entry_id}/{total_entries}...")
            if self.validate_schema_elements(query, entry_id): pass_counts['schema'] += 1
            if self.validate_query_executability(query, entry_id): pass_counts['execution'] += 1
            if self.validate_expected_entities_match_query(query, row, entry_id): pass_counts['entity'] += 1
            if self.validate_semantic_relevance(question, query, entry_id): pass_counts['relevance'] += 1
            if self.validate_extracted_values_in_question(question, row, entry_id): pass_counts['value'] += 1

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
    # Use a different name for the raw input file
    RAW_DATASET_FILE = r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\dataset\neo4j_evaluation_dataset.csv'
    ENRICHED_DATASET_FILE = r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\dataset\neo4j_evaluation_dataset_ENRICHED.csv'
    LOG_DIRECTORY = r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\backend\validation_log'

    # --- Execution ---
    validator = DatasetValidator(SCHEMA_FILE, NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD)

    if validator.driver:
        try:
            # 1. Load the raw dataset
            dataset = validator.load_dataset(RAW_DATASET_FILE)
            print(f"Successfully loaded {len(dataset)} raw entries.")
            
            # 2. Setup loggers for the entire process
            validator._setup_loggers(LOG_DIRECTORY)
            print(f"Validation reports will be saved to {LOG_DIRECTORY}")

            # 3. Perform initial duplicate check as a gatekeeper
            if validator.check_for_initial_duplicates(dataset):
                print("\nDuplicate Question/Cypher pairs found. Halting process. Please clean raw data.")
                sys.exit(1) # Exit the script with an error code

            # 4. Enrich the dataset since it passed the initial check
            dataset = validator.enrich_dataset(dataset)
            
            # 5. Save the enriched dataset
            pd.DataFrame(dataset).to_csv(ENRICHED_DATASET_FILE, index=False)
            print(f"Enriched dataset saved to: {ENRICHED_DATASET_FILE}")

            # 6. Run the full validation suite on the in-memory enriched data
            validator.run_all_validators(dataset)

        except FileNotFoundError as e:
            print(f"Error: {e}. Please make sure file paths are correct.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
        finally:
            validator.close_loggers()
            validator.close()
    else:
        print("Cannot run validations because connection to Neo4j failed.")