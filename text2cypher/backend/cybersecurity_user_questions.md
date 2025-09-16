# Cybersecurity Knowledge Graph - Realistic User Questions

Based on the actual properties of each node type, here are realistic user questions that the text-to-cypher system should handle:

## UcoCVE (Common Vulnerabilities and Exposures)

### Severity & Impact Queries
- "Show all CVEs with HIGH severity"
- "Find CVEs with MEDIUM severity"
- "Show CVEs with LOW severity"
- "Find CVEs with exploitability score greater than 8"
- "Show CVEs with impact score less than 3"
- "Find CVEs with exploitability score of 10"

### Status & Vector Queries
- "Show CVEs with 'Deferred' status"
- "Find CVEs with 'Active' status"
- "Show CVEs with vector string containing 'AV:N'"
- "Find CVEs with vector string containing 'AC:L'"
- "Show CVEs with specific vector string 'AV:N/AC:L/Au:N/C:P/I:N/A:N'"

### Privilege & Interaction Queries
- "Show CVEs that can obtain all privileges"
- "Find CVEs that require user interaction"
- "Show CVEs that don't require user interaction"

### Specific CVE Queries
- "Find CVE with ID CVE-2007-3012"
- "Show CVE by label CVE-2007-3012"
- "Find CVEs with label containing 'CVE-2007'"

## UcoVulnerability

### Date-Based Queries
- "Show vulnerabilities published in 2024"
- "Find vulnerabilities published in 2023"
- "Show vulnerabilities last modified in 2025"
- "Find vulnerabilities published between 2020 and 2025"

### Summary Queries
- "Find vulnerabilities with 'FileMaker' in summary"
- "Show vulnerabilities with 'Web Companion' in summary"
- "Find vulnerabilities with 'XML' in summary"

## UcoexCPE (Common Platform Enumeration)

### Product Queries
- "Show CPE entries for Microsoft products"
- "Find CPE entries for Adobe products"
- "Show CPE entries for Oracle products"
- "Find CPE entries containing 'adgrafix'"
- "Show CPE entries for 'check_it_out'"

### Dictionary Queries
- "Show CPE entries found in dictionary"
- "Find CPE entries not found in dictionary"

## UcoexCAPEC (Common Attack Pattern Enumeration)

### Severity & Likelihood Queries
- "Show CAPEC patterns with 'High' severity"
- "Find CAPEC patterns with 'Medium' likelihood"
- "Show CAPEC patterns with 'Low' likelihood"

### ID & Name Queries
- "Find CAPEC pattern with ID 16"
- "Show CAPEC pattern named 'Dictionary-based Password Attack'"
- "Find CAPEC patterns with 'password' in name"

### Abstraction Queries
- "Ç"
- "Find CAPEC patterns with 'Standard' abstraction"
- "Show CAPEC patterns with 'Meta' abstraction"

### Related Weaknesses Queries
- "Find CAPEC patterns related to CWE-521"
- "Show CAPEC patterns related to CWE-654"
- "Find CAPEC patterns related to CWE-307"

## UcoexGROUPS (Threat Actor Groups)

### Domain Queries
- "Show threat groups in enterprise-attack domain"
- "Find threat groups in mobile domain"
- "Show threat groups in ics domain"

### Name Queries
- "Find threat group named 'Gallmaker'"
- "Show threat groups with 'APT' in name"
- "Find threat groups with 'Lazarus' in name"

## UcoCWE (Common Weakness Enumeration)

### ID & Name Queries
- "Find CWE weakness with ID CWE-13"
- "Show CWE weaknesses with 'password' in name"
- "Find CWE weaknesses with 'SQL' in name"
- "Show CWE weaknesses with 'injection' in name"

### Status & Structure Queries
- "Show CWE weaknesses with 'Draft' status"
- "Find CWE weaknesses with 'Stable' status"
- "Show CWE weaknesses with 'Simple' structure"
- "Find CWE weaknesses with 'Compound' structure"

### Abstraction Queries
- "Show CWE weaknesses with 'Variant' abstraction"
- "Find CWE weaknesses with 'Base' abstraction"
- "Show CWE weaknesses with 'Class' abstraction"

### Time Queries
- "Show CWE weaknesses introduced in 2006"
- "Find CWE weaknesses introduced in 2007"
- "Show CWE weaknesses introduced between 2006 and 2010"

## UcoexSOFTWARE (Malware and Tools)

### Name Queries
- "Find software named 'Socksbot'"
- "Show software with 'bot' in name"
- "Find software with 'malware' in name"
- "Show software with 'backdoor' in name"

### Domain Queries
- "Show software in enterprise-attack domain"
- "Find software in mobile domain"
- "Show software in ics domain"

## UcoexMITREATTACK, UcoexMITIGATIONS, UcoexTACTICS, UcoexCAMPAIGNS

### Name Queries
- "Find MITRE technique named 'Operation MidnightEclipse'"
- "Show campaigns with 'Operation' in name"
- "Find tactics with 'Initial Access' in name"

### Domain Queries
- "Show MITRE techniques in enterprise-attack domain"
- "Find campaigns in mobile domain"
- "Show tactics in ics domain"

## UcoexMITRED3FEND (Defense Countermeasures)

### Label Queries
- "Find D3FEND technique labeled 'Disk Erasure'"
- "Show D3FEND techniques with 'Encryption' in label"
- "Find D3FEND techniques with 'Authentication' in label"

## UcoexObservedExample

### Description Queries
- "Find observed examples with 'Dynamic variable evaluation' in description"
- "Show observed examples with 'file inclusion' in description"
- "Find observed examples with 'path traversal' in description"

## Relationship-Based Queries

### CVE to CPE Relationships
- "Show CVEs that affect Microsoft Windows platforms"
- "Find CVEs related to Adobe products"
- "Show CVEs affecting specific CPE entries"

### CAPEC to CWE Relationships
- "Find CAPEC patterns related to CWE-521"
- "Show CAPEC patterns that can lead to CWE-654"
- "Find CAPEC patterns related to authentication weaknesses"

### Group to Technique Relationships
- "Show techniques used by Gallmaker group"
- "Find groups using specific MITRE techniques"
- "Show campaigns using particular attack techniques"

### Software to Group Relationships
- "Show software used by specific threat groups"
- "Find groups using Socksbot software"
- "Show campaigns using particular malware"

## Property-Specific Queries

### Boolean Properties
- "Show CVEs where user interaction is required"
- "Find CVEs that can obtain all privileges"
- "Show CPE entries found in dictionary"

### Numeric Properties
- "Find CVEs with exploitability score > 8"
- "Show CVEs with impact score < 3"
- "Find CVEs with exploitability score = 10"

### Date Properties
- "Show vulnerabilities published in 2024"
- "Find CWE weaknesses introduced in 2006"
- "Show vulnerabilities last modified in 2025"

### Text Properties
- "Find CVEs with 'HIGH' severity"
- "Show CWE weaknesses with 'Draft' status"
- "Find CAPEC patterns with 'Detailed' abstraction"

## Complex Queries (Combining Properties)

### Multi-Property Filters
- "Show CVEs with HIGH severity that don't require user interaction"
- "Find CAPEC patterns with High severity and Medium likelihood"
- "Show CWE weaknesses with Draft status and Simple structure"

### Relationship + Property Queries
- "Find CVEs affecting Microsoft products with HIGH severity"
- "Show CAPEC patterns related to CWE-521 with High severity"
- "Find threat groups in enterprise domain using specific techniques"

## Count and Statistical Queries

### Counting by Properties
- "Count CVEs with HIGH severity"
- "Count CWE weaknesses with Draft status"
- "Count CAPEC patterns with Detailed abstraction"

### Counting Relationships
- "Count CVEs affecting Microsoft products"
- "Count CAPEC patterns related to CWE-521"
- "Count techniques used by Gallmaker group"

These questions focus on specific property queries that are perfect for text-to-cypher conversion, while leaving semantic similarity searches to your GraphRAG implementation. 