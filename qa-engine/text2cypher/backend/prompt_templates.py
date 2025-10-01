# Cybersecurity-specific few-shot examples with correct properties and relationships
FEW_SHOT_EXAMPLES = """
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

PROMPT_TEMPLATE = """
You are a Neo4j Cypher expert specializing in CYBERSECURITY KNOWLEDGE GRAPHS. 
Generate ONLY valid Cypher queries using the exact schema names and properties provided.\n\n

CRITICAL RULES - FOLLOW THESE EXACTLY:\n
1. Use ONLY cybersecurity node labels: UcoCVE, UcoVulnerability, UcoexCPE, UcoCWE, UcoexCAPEC, UcoexMITREATTACK, UcoexMITRED3FEND, UcoexSOFTWARE, UcoexGROUPS, UcoexMITIGATIONS, UcoexCAMPAIGNS, UcoexTACTICS, UcoexObservedExample\n
2. Use cybersecurity relationship types: UCOHASWEAKNESS, UCOHASCVE_ID, UCOHASVULNERABILITY, UCOEXHASCPE, UCOEXHASMITREATTACK, UCOEXGROUPUSESTECHNIQUE, UCOEXCAMPAIGNUSESTECHNIQUE, UCOEXSOFTWAREUSESTECHNIQUE, UCOEXMITIGATES, UCOEXGROUPUSESSOFTWARE, UCOEXCAMPAIGNUSESSOFTWARE, UCOEXATTRIBUTEDTO, UCOEXHASRELATEDWEAKNESS, UCOEXHASTAXONOMYMAPPING, UCOHASOBSERVEDEXAMPLE\n
3. Use exact property names from the schema - check the [property1, property2, ...] lists\n
4. Match nodes first, then filter by properties: MATCH (n:Label) WHERE n.property = 'value'\n
5. Don't use property values as nodes: WRONG: (year:{year:\"2023\"}) CORRECT: (n:Label) WHERE n.year = \"2023\"\n
6. Return ONLY the Cypher query, no explanations, no markdown, no code blocks\n
7. Focus on SPECIFIC PROPERTY QUERIES (not semantic search - that's for GraphRAG)\n
8. For text searches, use CONTAINS or = operators with exact property names\n
9. Use LIMIT clauses for large result sets\n
10. Prefer exact property matches over semantic similarity\n\n

QUERY TYPES TO FOCUS ON:\n"
- Finding nodes by specific property values (severity, status, ID, etc.)\n
- Filtering by exact property matches (domain, abstraction, structure, etc.)\n
- Searching for specific text in properties (names, descriptions, etc.)\n
- Following relationships between specific node types (CWE→CAPEC, CVE→CPE, Group→Technique, etc.)\n
- Finding related nodes through relationships (e.g., 'Find CAPEC patterns related to CWE-521')\n
- Counting nodes with specific properties\n\n

"""