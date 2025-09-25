# Cybersecurity Knowledge Graph Text-to-Cypher Implementation

## Overview
This implementation is specifically designed for cybersecurity knowledge graphs built with unified cybersecurity ontologies (UCO). It focuses on cybersecurity-specific node labels and relationships, providing specialized text-to-cypher conversion for security queries.

## Cybersecurity Node Labels
The system focuses on these cybersecurity-specific node labels:

### Core Vulnerability & Weakness Data
- **UcoCVE**: Common Vulnerabilities and Exposures
- **UcoVulnerability**: Vulnerability information
- **UcoexCPE**: Common Platform Enumeration
- **UcoCWE**: Common Weakness Enumeration

### Attack & Threat Intelligence
- **UcoexCAPEC**: Common Attack Pattern Enumeration and Classification
- **UcoexMITREATTACK**: MITRE ATT&CK techniques
- **UcoexTACTICS**: MITRE ATT&CK tactics

### Defense & Mitigation
- **UcoexMITRED3FEND**: MITRE D3FEND countermeasures
- **UcoexMITIGATIONS**: Security mitigations

### Threat Actors & Tools
- **UcoexGROUPS**: Threat actor groups
- **UcoexSOFTWARE**: Malware and tools
- **UcoexCAMPAIGNS**: Attack campaigns

### Examples & Observations
- **UcoexObservedExample**: Observed attack examples

## Cybersecurity Relationships
Key relationship types for cybersecurity queries:

### Vulnerability Relationships
- **UCOHASCVE_ID**: Links to CVE identifiers
- **UCOHASVULNERABILITY**: Links to vulnerability data
- **UCOEXHASCPE**: Links to platform enumeration

### Weakness & Attack Relationships
- **UCOHASWEAKNESS**: Links to CWE weaknesses
- **UCOEXHASRELATEDWEAKNESS**: Links CAPEC to CWE
- **UCOEXHASTAXONOMYMAPPING**: Links to MITRE ATT&CK

### Threat Actor Relationships
- **UCOEXGROUPUSESTECHNIQUE**: Groups using attack techniques
- **UCOEXCAMPAIGNUSESTECHNIQUE**: Campaigns using techniques
- **UCOEXSOFTWAREUSESTECHNIQUE**: Software using techniques
- **UCOEXGROUPUSESSOFTWARE**: Groups using software
- **UCOEXCAMPAIGNUSESSOFTWARE**: Campaigns using software
- **UCOEXATTRIBUTEDTO**: Attribution relationships

### Mitigation Relationships
- **UCOEXMITIGATES**: Links attacks to mitigations

## Query Examples

### 1. Vulnerability Queries
```cypher
-- Show all CVE vulnerabilities
MATCH (cve:UcoCVE) RETURN cve LIMIT 10

-- Find CVEs with high severity
MATCH (cve:UcoCVE) WHERE cve.ucobaseSeverity = 'HIGH' RETURN cve

-- Find CVEs affecting specific platform
MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) 
WHERE cpe.cpeName CONTAINS 'microsoft:windows' 
RETURN cve, cpe
```

### 2. Weakness Queries
```cypher
-- Show CWE weaknesses related to SQL injection
MATCH (cwe:UcoCWE) WHERE cwe.ucocweName CONTAINS 'SQL' RETURN cwe

-- Find CAPEC patterns for specific CWE
MATCH (capec:UcoexCAPEC)-[:UCOEXHASRELATEDWEAKNESS]->(cwe:UcoCWE) 
WHERE cwe.ucocweID = 'CWE-89' 
RETURN capec, cwe
```

### 3. Attack Technique Queries
```cypher
-- Show MITRE ATT&CK techniques used by specific group
MATCH (group:UcoexGROUPS)-[:UCOEXGROUPUSESTECHNIQUE]->(attack:UcoexMITREATTACK) 
WHERE group.ucoexNAME = 'APT29' 
RETURN group, attack

-- Find software used in campaigns
MATCH (campaign:UcoexCAMPAIGNS)-[:UCOEXCAMPAIGNUSESSOFTWARE]->(software:UcoexSOFTWARE) 
RETURN campaign, software
```

### 4. Mitigation Queries
```cypher
-- Show mitigations for specific attack technique
MATCH (attack:UcoexMITREATTACK)-[:UCOEXMITIGATES]->(mitigation:UcoexMITIGATIONS) 
WHERE attack.ucoexNAME = 'T1078' 
RETURN attack, mitigation
```

## Usage

### Basic Usage
```python
from text2cypher import Text2Cypher

# Initialize with your LLM
t2c = Text2Cypher(neo4j_uri, neo4j_user, neo4j_password, llm)

# Convert text to Cypher
question = "Show all CVE vulnerabilities with high severity"
cypher = t2c.text_to_cypher(question)

# Execute the query
results = t2c.run_cypher(cypher)
```

### Schema Information
```python
# Get cybersecurity-focused schema
schema = t2c.get_cybersecurity_schema()

# Get schema info for debugging
schema_info = t2c.get_schema_info()
```

## Key Features

### 1. Cybersecurity Focus
- Only uses cybersecurity node labels and relationships
- Ignores generic ontology labels (Resource, Class, etc.)
- Specialized prompt for security queries

### 2. Few-Shot Learning
- Includes 10 cybersecurity-specific examples
- Covers common security query patterns
- Helps LLM understand security domain

### 3. Validation
- Validates generated Cypher queries
- Checks for cybersecurity node labels
- Ensures proper syntax and structure

### 4. Property-Aware
- Uses exact property names from schema
- Supports filtering by security-specific properties
- Handles security data types correctly

## Query Types Supported

### Property Queries
- Finding nodes by specific properties
- Filtering by security attributes
- Text search in security descriptions

### Relationship Queries
- Finding related security entities
- Following attack chains
- Identifying threat actor connections

### Complex Queries
- Multi-hop security relationships
- Attack pattern analysis
- Vulnerability-to-mitigation mapping

## Best Practices

### 1. Use Specific Properties
```cypher
-- Good: Use specific CVE properties
MATCH (cve:UcoCVE) WHERE cve.ucobaseSeverity = 'HIGH' RETURN cve

-- Avoid: Generic queries without specific properties
MATCH (cve:UcoCVE) RETURN cve
```

### 2. Use LIMIT for Large Results
```cypher
-- Good: Limit results for performance
MATCH (cve:UcoCVE) RETURN cve LIMIT 100

-- Avoid: Unbounded queries
MATCH (cve:UcoCVE) RETURN cve
```

### 3. Follow Security Relationships
```cypher
-- Good: Use security-specific relationships
MATCH (capec:UcoexCAPEC)-[:UCOEXHASRELATEDWEAKNESS]->(cwe:UcoCWE)

-- Avoid: Generic relationships
MATCH (capec:UcoexCAPEC)-[:RELATED_TO]->(cwe:UcoCWE)
```

## Testing

Run the test script to validate functionality:
```bash
python test_cybersecurity_queries.py
```

This will test:
- Schema extraction
- Query generation
- Validation
- Real Neo4j connectivity

## Integration with GraphRAG

This text-to-cypher implementation is designed to complement GraphRAG:

- **Text-to-Cypher**: For specific property queries and relationship traversal
- **GraphRAG**: For semantic similarity search and natural language understanding

Use text-to-cypher for:
- Finding specific CVEs by ID or properties
- Following attack chains and relationships
- Querying specific security attributes

Use GraphRAG for:
- Semantic search across security descriptions
- Finding similar attack patterns
- Natural language security analysis 