import os
import re
import time
from neo4j import GraphDatabase
from logger import get_logger
from prompt_templates import FEW_SHOT_EXAMPLES, PROMPT_TEMPLATE

logger = get_logger()

class Text2Cypher:
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str, llm, schema_path: str = "neo4j_graph_schema.txt"):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.llm = llm
        
        # Resolve schema path relative to this file's directory
        base_dir = os.path.dirname(__file__)
        self.schema_full_path = schema_path if os.path.isabs(schema_path) else os.path.join(base_dir, schema_path)
        
        self.schema = ""
        self.cybersecurity_labels = set()
        self.cybersecurity_relationships = set()

        self._load_schema()

    def _load_schema(self):
        """Loads the graph schema from the specified text file."""
        try:
            with open(self.schema_full_path, "r", encoding="utf-8") as f:
                self.schema = f.read()
            logger.info(f"Successfully loaded schema from '{self.schema_full_path}'")
            
            # Dynamically extract labels and relationships for validation
            self.cybersecurity_labels = set(re.findall(r"Node Label:`:(\w+)`", self.schema))
            self.cybersecurity_relationships = set(re.findall(r"Relationship Type:`:\[(\w+)\]`", self.schema))
            
            if not self.cybersecurity_labels and not self.cybersecurity_relationships:
                 logger.warning("Schema file was loaded, but no node labels or relationship types were extracted. Validation may be affected.")
            else:
                logger.info(f"Extracted {len(self.cybersecurity_labels)} labels and {len(self.cybersecurity_relationships)} relationships for validation.")

        except FileNotFoundError:
            logger.error(f"CRITICAL: Schema file not found at '{self.schema_full_path}'. The application will not function correctly without it.")
            self.schema = "Error: Schema file not found. Please run neo4j_schema_extractor.py."
        except Exception as e:
            logger.error(f"Failed to load or parse schema file: {e}")
            self.schema = f"Error: Could not load schema from file due to: {e}"

    def get_schema(self) -> str:
        """Returns the pre-loaded schema content."""
        return self.schema

    def get_schema_info(self) -> dict:
        """Get detailed schema information for debugging."""
        return {
            "schema_text": self.schema,
            "schema_source": self.schema_full_path,
            "labels_for_validation": list(self.cybersecurity_labels),
            "relationships_for_validation": list(self.cybersecurity_relationships),
            "timestamp": "Schema loaded on application startup."
        }

    def validate_cypher(self, cypher: str) -> tuple[bool, str]:
        """Comprehensive Cypher validation using dynamically loaded schema."""
        
        # 1. Basic checks
        if not cypher or not cypher.strip():
            return False, "Generated Cypher query is empty."
        
        # 2. Check for valid starting keywords
        valid_starters = ['MATCH', 'RETURN', 'WITH', 'UNWIND', 'CALL', 'SHOW']
        if not any(cypher.upper().startswith(starter) for starter in valid_starters):
            return False, f"Query must start with a valid Cypher keyword. Got: {cypher[:50]}"
        
        # 3. Check for placeholder or instruction text
        if "{" in cypher or "}" in cypher:
            return False, "Query contains invalid placeholder characters '{' or '}'."

        # 4. Check against loaded schema (if available)
        if self.cybersecurity_labels or self.cybersecurity_relationships:
            found_labels = set(re.findall(r":(\w+)", cypher))
            found_rels = set(re.findall(r":\[(\w+)\]", cypher))

            if not found_labels.intersection(self.cybersecurity_labels) and not found_rels.intersection(self.cybersecurity_relationships):
                return False, "Query does not use any of the node labels or relationship types defined in the schema."

        # 5. Check for common syntax errors
        if cypher.count('(') != cypher.count(')'):
            return False, "Query has unbalanced parentheses '(' and ')'."
        if cypher.count('[') != cypher.count(']'):
            return False, "Query has unbalanced square brackets '[' and ']'."
        
        return True, "Valid Cypher query."

    def text_to_cypher(self, question: str) -> str:
        if "Error:" in self.schema:
            raise ValueError("Cannot generate Cypher query because the schema could not be loaded.")

        prompt = (
            f"{PROMPT_TEMPLATE}\n\n"
            f"{FEW_SHOT_EXAMPLES}\n\n"
            f"Here is the exact schema of the cybersecurity graph. Use it to construct the query.\n"
            f"SCHEMA:\n---\n{self.schema}\n---\n\n"
            f"Question: {question}\n"
            "Cypher:"
        )
        
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

    def run_cypher(self, cypher_query: str):
        with self.driver.session() as session:
            try:
                result = session.run(cypher_query)
                return [record.data() for record in result]
            except Exception as e:
                logger.error(f"Error running Cypher query: {e}")
                raise

def extract_cypher(text: str) -> str:
    """Extracts a Cypher query from a string, removing markdown code blocks."""
    text = text.strip()
    # Remove markdown ```cypher ... ``` or ``` ... ```
    pattern = r"```(?:cypher)?\s*\n?(.*?)\n?```"
    matches = re.findall(pattern, text, re.DOTALL | re.IGNORECASE)
    
    if matches:
        query = matches[0]
    else:
        # If no markdown, assume the whole text is the query
        query = text

    # Clean up any residual keywords or explanations
    if query.lower().startswith("cypher:"):
        query = query[7:].strip()
        
    return query.strip()