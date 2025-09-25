import re
from neo4j import GraphDatabase

class Text2Cypher:
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str, llm):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.llm = llm
        
        # Define cybersecurity-specific node labels to focus on
        self.cybersecurity_labels = {
            "UcoCVE", "UcoVulnerability", "UcoexCPE", "UcoCWE", "UcoexCAPEC", 
            "UcoexMITREATTACK", "UcoexMITRED3FEND", "UcoexSOFTWARE", "UcoexGROUPS", 
            "UcoexMITIGATIONS", "UcoexCAMPAIGNS", "UcoexTACTICS", "UcoexObservedExample"
        }
        
        # Define cybersecurity-specific relationship types
        self.cybersecurity_relationships = {
            "UCOHASWEAKNESS", "UCOHASCVE_ID", "UCOHASVULNERABILITY", "UCOEXHASCPE",
            "UCOEXHASMITREATTACK", "UCOEXGROUPUSESTECHNIQUE", "UCOEXCAMPAIGNUSESTECHNIQUE",
            "UCOEXSOFTWAREUSESTECHNIQUE", "UCOEXMITIGATES", "UCOEXGROUPUSESSOFTWARE",
            "UCOEXCAMPAIGNUSESSOFTWARE", "UCOEXATTRIBUTEDTO", "UCOEXHASRELATEDWEAKNESS",
            "UCOEXHASTAXONOMYMAPPING", "UCOHASOBSERVEDEXAMPLE"
        }

    def get_cybersecurity_schema(self) -> str:
        """Get schema information focused only on cybersecurity node labels and relationships"""
        with self.driver.session() as session:
            # Get cybersecurity node labels with their properties
            cybersecurity_schema = {}
            
            for label in self.cybersecurity_labels:
                try:
                    result = session.run(f"MATCH (n:{label}) RETURN keys(n) as properties LIMIT 1")
                    record = result.single()
                    if record:
                        properties = sorted(record["properties"])
                        cybersecurity_schema[label] = properties
                except Exception as e:
                    cybersecurity_schema[label] = ["error retrieving properties"]
            
            # Get cybersecurity relationship types with their properties
            cybersecurity_rels = {}
            for rel_type in self.cybersecurity_relationships:
                try:
                    result = session.run(f"MATCH ()-[r:{rel_type}]->() RETURN keys(r) as properties LIMIT 1")
                    record = result.single()
                    if record:
                        properties = sorted(record["properties"])
                        cybersecurity_rels[rel_type] = properties
                except Exception as e:
                    cybersecurity_rels[rel_type] = ["error retrieving properties"]
            
            # Build schema string
            labels_str = ""
            for label in sorted(cybersecurity_schema.keys()):
                props = cybersecurity_schema.get(label, [])
                props_str = ", ".join(props) if props else "no properties"
                labels_str += f"- {label}: [{props_str}]\n"
            
            rels_str = ""
            for rel_type in sorted(cybersecurity_rels.keys()):
                props = cybersecurity_rels.get(rel_type, [])
                props_str = ", ".join(props) if props else "no properties"
                rels_str += f"- {rel_type}: [{props_str}]\n"
            
            return (
                "CYBERSECURITY KNOWLEDGE GRAPH SCHEMA:\n\n"
                "Node Labels and Properties:\n" + labels_str +
                "\nRelationship Types and Properties:\n" + rels_str
            )

    def get_schema_info(self) -> dict:
        """Get detailed schema information for debugging"""
        schema_text = self.get_cybersecurity_schema()
        return {
            "schema_text": schema_text,
            "timestamp": "Current cybersecurity schema information"
        }

    def get_schema(self) -> str:
        """Get cybersecurity-focused schema"""
        return self.get_cybersecurity_schema()

    def validate_cypher(self, cypher: str, schema: str = None) -> tuple[bool, str]:
        """Comprehensive Cypher validation with cybersecurity focus"""
        errors = []
        
        # 1. Basic checks
        if not cypher or cypher.strip() == "":
            return False, "Generated Cypher query is empty"
        
        # 2. Check for valid starting keywords
        valid_starters = ['MATCH', 'RETURN', 'WITH', 'UNWIND', 'CALL']
        if not any(cypher.upper().startswith(starter) for starter in valid_starters):
            return False, f"Query must start with valid Cypher keyword. Got: {cypher[:50]}"
        
        # 3. Check for cybersecurity node labels or relationships
        has_cybersecurity_labels = any(f":{label}" in cypher for label in self.cybersecurity_labels)
        has_cybersecurity_relationships = any(f":{rel}" in cypher for rel in self.cybersecurity_relationships)
        
        if not has_cybersecurity_labels and not has_cybersecurity_relationships:
            # If no cybersecurity labels or relationships found, warn but don't fail
            errors.append("Warning: No cybersecurity node labels or relationships detected in query")
        
        # 4. Check for common syntax errors
        if '{{' in cypher or '}}' in cypher:
            return False, "Invalid syntax: Found {{ or }} - use proper node syntax (n:Label)"
        
        # 5. Check for balanced parentheses and brackets
        if cypher.count('(') != cypher.count(')') or cypher.count('[') != cypher.count(']'):
            return False, "Unbalanced parentheses or brackets"
        
        # 6. Check for proper node syntax (should have :Label)
        node_pattern = r'\([^:]+\)'
        if re.search(node_pattern, cypher):
            return False, "Nodes should have labels: (n:Label) not (n)"
        
        # 7. Check for proper relationship syntax
        rel_pattern = r'\[[^:]+[^]]*\]'
        if re.search(rel_pattern, cypher):
            return False, "Relationships should have types: [:TYPE] not []"
        
        # 8. Check for common LLM mistakes
        if 'year:{year:' in cypher or 'year:{"year":' in cypher:
            return False, "Invalid node syntax: Use WHERE clause for filtering, not property nodes"
        
        return True, "Valid Cypher query"

    def text_to_cypher(self, question: str, schema: str = None) -> str:
        schema_block = schema or self.get_cybersecurity_schema()
        
        # Cybersecurity-specific few-shot examples with correct properties and relationships
        few_shot_examples = """
EXAMPLES FOR CYBERSECURITY KNOWLEDGE GRAPH (PROPERTY AND RELATIONSHIP QUERIES):

SINGLE NODE PROPERTY QUERIES:
1. "Show all CVEs with HIGH severity" 
   → MATCH (cve:UcoCVE) WHERE cve.ucobaseSeverity = 'HIGH' RETURN cve LIMIT 10

2. "Find CVEs with exploitability score greater than 8" 
   → MATCH (cve:UcoCVE) WHERE cve.ucoexploitabilityScore > 8.0 RETURN cve

3. "Show CVEs that require user interaction" 
   → MATCH (cve:UcoCVE) WHERE cve.ucouserInteractionRequired = true RETURN cve

4. "Find CWE weaknesses with 'password' in the name" 
   → MATCH (cwe:UcoCWE) WHERE cwe.ucocweName CONTAINS 'password' RETURN cwe

5. "Show CWE weaknesses with 'Draft' status" 
   → MATCH (cwe:UcoCWE) WHERE cwe.ucostatus = 'Draft' RETURN cwe

6. "Find CAPEC patterns with 'High' severity" 
   → MATCH (capec:UcoexCAPEC) WHERE capec.ucoexSeverity = 'High' RETURN capec

7. "Find CWE weaknesses by specific ID" 
   → MATCH (cwe:UcoCWE) WHERE cwe.ucocweID = 'CWE-13' RETURN cwe

8. "Find CAPEC patterns by specific ID" 
   → MATCH (capec:UcoexCAPEC) WHERE capec.ucoexCAPEC_id = '16' RETURN capec

RELATIONSHIP-BASED QUERIES:
9. "Find CAPEC patterns related to CWE-404" 
   → MATCH (capec:UcoexCAPEC)-[:UCOEXHASRELATEDWEAKNESS]->(cwe:UcoCWE) WHERE cwe.ucocweID = 'CWE-404' RETURN capec

10. "Show CVEs that affect Microsoft Windows platforms" 
    → MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) WHERE cpe.cpeName CONTAINS 'microsoft:windows' RETURN cve

11. "Find groups using specific MITRE techniques" 
    → MATCH (group:UcoexGROUPS)-[:UCOEXGROUPUSESTECHNIQUE]->(technique:UcoexMITREATTACK) WHERE technique.ucoexNAME CONTAINS 'T1078' RETURN group

12. "Show software used by specific threat groups" 
    → MATCH (group:UcoexGROUPS)-[:UCOEXGROUPUSESSOFTWARE]->(software:UcoexSOFTWARE) WHERE group.ucoexNAME = 'Gallmaker' RETURN software

13. "Find CVEs related to Adobe products" 
    → MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) WHERE cpe.cpeName CONTAINS 'adobe' RETURN cve

14. "Show CAPEC patterns that can lead to CWE-81" 
    → MATCH (capec:UcoexCAPEC)-[:UCOEXHASRELATEDWEAKNESS]->(cwe:UcoCWE) WHERE cwe.ucocweID = 'CWE-81' RETURN capec

15. "Find groups using Socksbot software" 
    → MATCH (group:UcoexGROUPS)-[:UCOEXGROUPUSESSOFTWARE]->(software:UcoexSOFTWARE) WHERE software.ucoexNAME = 'Socksbot' RETURN group

16. "Show techniques used by Gallmaker group" 
    → MATCH (group:UcoexGROUPS)-[:UCOEXGROUPUSESTECHNIQUE]->(technique:UcoexMITREATTACK) WHERE group.ucoexNAME = 'Gallmaker' RETURN technique

17. "Find CVEs affecting specific CPE entries" 
    → MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) WHERE cpe.cpeName = 'cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*:*' RETURN cve

18. "Show CAPEC patterns related to authentication weaknesses" 
    → MATCH (capec:UcoexCAPEC)-[:UCOEXHASRELATEDWEAKNESS]->(cwe:UcoCWE) WHERE cwe.ucocweName CONTAINS 'authentication' RETURN capec

19. "Find campaigns using particular attack techniques" 
    → MATCH (campaign:UcoexCAMPAIGNS)-[:UCOEXCAMPAIGNUSESTECHNIQUE]->(technique:UcoexMITREATTACK) WHERE technique.ucoexNAME CONTAINS 'T1078' RETURN campaign

20. "Show CVEs with their related CWE weaknesses" 
    → MATCH (cve:UcoCVE)-[:UCOHASWEAKNESS]->(cwe:UcoCWE) RETURN cve, cwe LIMIT 10
"""
        
        prompt = (
            "You are a Neo4j Cypher expert specializing in CYBERSECURITY KNOWLEDGE GRAPHS. "
            "Generate ONLY valid Cypher queries using the exact schema names and properties provided.\n\n"
            
            "CRITICAL RULES - FOLLOW THESE EXACTLY:\n"
            "1. Use ONLY cybersecurity node labels: UcoCVE, UcoVulnerability, UcoexCPE, UcoCWE, UcoexCAPEC, UcoexMITREATTACK, UcoexMITRED3FEND, UcoexSOFTWARE, UcoexGROUPS, UcoexMITIGATIONS, UcoexCAMPAIGNS, UcoexTACTICS, UcoexObservedExample\n"
            "2. Use cybersecurity relationship types: UCOHASWEAKNESS, UCOHASCVE_ID, UCOHASVULNERABILITY, UCOEXHASCPE, UCOEXHASMITREATTACK, UCOEXGROUPUSESTECHNIQUE, UCOEXCAMPAIGNUSESTECHNIQUE, UCOEXSOFTWAREUSESTECHNIQUE, UCOEXMITIGATES, UCOEXGROUPUSESSOFTWARE, UCOEXCAMPAIGNUSESSOFTWARE, UCOEXATTRIBUTEDTO, UCOEXHASRELATEDWEAKNESS, UCOEXHASTAXONOMYMAPPING, UCOHASOBSERVEDEXAMPLE\n"
            "3. Use exact property names from the schema - check the [property1, property2, ...] lists\n"
            "4. Match nodes first, then filter by properties: MATCH (n:Label) WHERE n.property = 'value'\n"
            "5. Don't use property values as nodes: WRONG: (year:{year:\"2023\"}) CORRECT: (n:Label) WHERE n.year = \"2023\"\n"
            "6. Return ONLY the Cypher query, no explanations, no markdown, no code blocks\n"
            "7. Focus on SPECIFIC PROPERTY QUERIES (not semantic search - that's for GraphRAG)\n"
            "8. For text searches, use CONTAINS or = operators with exact property names\n"
            "9. Use LIMIT clauses for large result sets\n"
            "10. Prefer exact property matches over semantic similarity\n\n"
            
            "QUERY TYPES TO FOCUS ON:\n"
            "- Finding nodes by specific property values (severity, status, ID, etc.)\n"
            "- Filtering by exact property matches (domain, abstraction, structure, etc.)\n"
            "- Searching for specific text in properties (names, descriptions, etc.)\n"
            "- Following relationships between specific node types (CWE→CAPEC, CVE→CPE, Group→Technique, etc.)\n"
            "- Finding related nodes through relationships (e.g., 'Find CAPEC patterns related to CWE-521')\n"
            "- Counting nodes with specific properties\n\n"
            
            f"{few_shot_examples}\n\n"
            f"CYBERSECURITY SCHEMA:\n{schema_block}\n\n"
            f"Question: {question}\n"
            "Cypher:"
        )
        
        # Retry mechanism for better reliability
        max_retries = 3
        for attempt in range(max_retries):
            try:
                llm_output = self.llm.invoke(prompt)
                cypher = extract_cypher(llm_output)
                
                # Comprehensive validation
                is_valid, error_msg = self.validate_cypher(cypher, schema_block)
                if not is_valid:
                    raise ValueError(f"Validation failed: {error_msg}")
                
                return cypher
                
            except Exception as e:
                if attempt == max_retries - 1:  # Last attempt
                    raise e
                # Add a small delay before retry
                import time
                time.sleep(0.5)
                continue

    def run_cypher(self, cypher_query: str):
        with self.driver.session() as session:
            result = session.run(cypher_query)
            return [record.data() for record in result]

def extract_cypher(text: str) -> str:
    text = re.sub(r'(?i)^\s*cypher\s*', '', text).strip()
    pattern = r"```(?:cypher)?\n?(.*?)```"
    matches = re.findall(pattern, text, re.DOTALL)
    query = matches[0] if matches else text
    return query.strip()
