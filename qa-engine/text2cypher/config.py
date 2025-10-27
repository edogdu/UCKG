"""
Configuration constants for Text2Cypher cybersecurity knowledge graph.
Contains excluded labels, relationships, and other domain-specific constants.
"""

# Generic UCO ontology labels to exclude (not cybersecurity domain)
EXCLUDED_LABELS = {
    # Generic UCO ontology labels
    "Resource", "Entity", "UcoObject", "UcoThing", "UcoCore", "UcoIdentity",
    "UcoLocation", "UcoTime", "UcoObservable", "UcoAction", "UcoFacet",
    "UcoRole", "UcoCo", "UcoItem", "UcoItemList", "UcoMarkingDefinition",
    "UcoRelationship", "UcoAssertion", "UcoAttributedName", "UcoBundle",
    "UcoContent", "UcoHash", "UcoMessageThread", "UcoThread",
    "UcoAccount", "UcoApplication", "UcoBrowser", "UcoCalendarEntry",
    "UcoComputerSpecification", "UcoContact", "UcoDevice", "UcoDigitalAccount",
    "UcoEmailAccount", "UcoEmailAddress", "UcoEmailMessage", "UcoFile",
    "UcoForum", "UcoGeoLocationEntry", "UcoIPAddress", "UcoLatLongCoordinates",
    "UcoMessage", "UcoMobileAccount", "UcoNetworkConnection", "UcoNetworkInterface",
    "UcoNetworkRoute", "UcoOnlineService", "UcoOperatingSystem", "UcoPathRelation",
    "UcoPhoneAccount", "UcoProfile", "UcoRasterPicture", "UcoSIMCard",
    "UcoSMSMessage", "UcoTablet", "UcoURL", "UcoUserAccount", "UcoUserSession",
    "UcoVector", "UcoWifiAddress", "UcoWindowsRegistryKey", "UcoWindowsRegistryValue",
    "UcoX509Certificate", "UcoX509V3Certificate", "UcoYaraRule",
    
    # Ontology metadata labels (OWL/RDF)
    "Ontology", "Class", "Property", "DatatypeProperty", "ObjectProperty",
    "AnnotationProperty", "NamedIndividual", "Restriction", "Union", "Intersection",
    "Complement", "OneOf", "AllValuesFrom", "SomeValuesFrom", "HasValue",
    "MinCardinality", "MaxCardinality", "ExactCardinality", "HasSelf",
    "DataRange", "DataOneOf", "DataComplementOf", "DataIntersectionOf",
    "DataUnionOf", "DatatypeRestriction", "FacetRestriction", "DataHasValue",
    "DataMinCardinality", "DataMaxCardinality", "DataExactCardinality",
    "DataAllValuesFrom", "DataSomeValuesFrom", "DataMinLength", "DataMaxLength",
    "DataExactLength", "DataMinInclusive", "DataMaxInclusive", "DataMinExclusive",
    "DataMaxExclusive", "DataPattern", "DataLanguage", "DataLength",
    
    # Additional ontology metadata
    "Axiom", "FunctionalProperty", "IrreflexiveProperty", "SymmetricProperty",
    "TransitiveProperty", "InverseFunctionalProperty", "ReflexiveProperty",
    "AsymmetricProperty", "DisjointWith", "EquivalentClass", "EquivalentProperty",
    "InverseOf", "SubClassOf", "SubPropertyOf", "Domain", "Range",
    "Annotation", "AnnotationProperty", "OntologyProperty", "DeprecatedClass",
    "DeprecatedProperty", "Nothing", "Thing", "TopObjectProperty", "TopDataProperty",
    "BottomObjectProperty", "BottomDataProperty", "OWLClass", "OWLObjectProperty",
    "OWLDatatypeProperty", "OWLAnnotationProperty", "OWLNamedIndividual",
    "OWLOntology", "OWLAxiom", "OWLDeclaration", "OWLImports", "OWLVersionInfo",
    "OWLVersionIRI", "OWLPriorVersion", "OWLBackwardCompatibleWith", "OWLIncompatibleWith",
    "RDFProperty", "RDFClass", "RDFResource", "RDFList", "RDFAlt", "RDFBag", "RDFSeq",
    "RDFStatement", "RDFSubject", "RDFPredicate", "RDFObject", "RDFType", "RDFValue",
    "RDFFirst", "RDFRest", "RDFNil", "RDFXMLLiteral", "RDFPlainLiteral", "RDFLangString",
    
    # Graph configuration and metadata
    "_GraphConfig", "_GraphMeta", "_GraphSchema", "_GraphIndex", "_GraphConstraint"
}

# Generic ontology relationships to exclude (not cybersecurity domain)
EXCLUDED_RELATIONSHIPS = {
    # Generic UCO ontology relationships
    "UCOHASPROPERTY", "UCOHASFACET", "UCOHASROLE", "UCOHASIDENTITY",
    "UCOHASLOCATION", "UCOHASOBSERVABLE", "UCOHASACTION", "UCOHASRELATIONSHIP",
    "UCOHASASSERTION", "UCOHASATTRIBUTEDNAME", "UCOHASBUNDLE", "UCOHASCONTENT",
    "UCOHASHASH", "UCOHASMESSAGETHREAD", "UCOHASTHREAD", "UCOHASACCOUNT",
    "UCOHASAPPLICATION", "UCOHASBROWSER", "UCOHASCALENDARENTRY", "UCOHASCOMPUTERSPECIFICATION",
    "UCOHASCONTACT", "UCOHASDEVICE", "UCOHASDIGITALACCOUNT", "UCOHASEMAILACCOUNT",
    "UCOHASEMAILADDRESS", "UCOHASEMAILMESSAGE", "UCOHASFILE", "UCOHASFORUM",
    "UCOHASGEOLOCATIONENTRY", "UCOHASIPADDRESS", "UCOHASLATLONGCOORDINATES",
    "UCOHASMESSAGE", "UCOHASMOBILEACCOUNT", "UCOHASNETWORKCONNECTION",
    "UCOHASNETWORKINTERFACE", "UCOHASNETWORKROUTE", "UCOHASONLINESERVICE",
    "UCOHASOPERATINGSYSTEM", "UCOHASPATHRELATION", "UCOHASPHONEACCOUNT",
    "UCOHASPROFILE", "UCOHASRASTERPICTURE", "UCOHASSIMCARD", "UCOHASSMSMESSAGE",
    "UCOHASTABLET", "UCOHASURL", "UCOHASUSERACCOUNT", "UCOHASUSERSESSION",
    "UCOHASVECTOR", "UCOHASWIFIADDRESS", "UCOHASWINDOWSREGISTRYKEY",
    "UCOHASWINDOWSREGISTRYVALUE", "UCOHASX509CERTIFICATE", "UCOHASX509V3CERTIFICATE",
    "UCOHASYARARULE", "UCOHASCO", "UCOHASITEM", "UCOHASITEMLIST",
    "UCOHASMARKINGDEFINITION",
    
    # Generic ontology relationships (OWL/RDF)
    "RDFTYPE", "RDFSUBCLASSOF", "RDFSUBPROPERTYOF", "RDFDOMAIN", "RDFRANGE",
    "RDFEQUIVALENTCLASS", "RDFEQUIVALENTPROPERTY", "RDFINVERSEOF", "RDFDISJOINTWITH",
    "RDFUNIONOF", "RDFINTERSECTIONOF", "RDFCOMPLEMENTOF", "RDFONEOF",
    "RDFALLVALUESFROM", "RDFSOMEVALUESFROM", "RDFHASVALUE", "RDFMINCARDINALITY",
    "RDFMAXCARDINALITY", "RDFEXACTCARDINALITY", "RDFHASSELF", "RDFDATARANGE",
    "RDFDATAONEOF", "RDFDATACOMPLEMENTOF", "RDFDATAINTERSECTIONOF", "RDFDATAUNIONOF",
    "RDFDATATYPERESTRICTION", "RDFFACETRESTRICTION", "RDFDATAHASVALUE",
    "RDFDATAMINCARDINALITY", "RDFDATAMAXCARDINALITY", "RDFDATAEXACTCARDINALITY",
    "RDFDATAALLVALUESFROM", "RDFDATASOMEVALUESFROM", "RDFDATAMINLENGTH",
    "RDFDATAMAXLENGTH", "RDFDATAEXACTLENGTH", "RDFDATAMININCLUSIVE",
    "RDFDATAMAXINCLUSIVE", "RDFDATAMINEXCLUSIVE", "RDFDATAMAXEXCLUSIVE",
    "RDFDATAPATTERN", "RDFDATALANGUAGE", "RDFDATALENGTH",
    
    # Additional ontology relationships
    "ANNOTATEDPROPERTY", "ANNOTATEDSOURCE", "ANNOTATEDTARGET", "EQUIVALENTCLASS",
    "EQUIVALENTPROPERTY", "FIRST", "INVERSEOF", "ONCLASS", "ONEOF", "ONPROPERTY",
    "REST", "SOMEVALUESFROM", "SUBCLASSOF", "SUBPROPERTYOF", "UNIONOF",
    "VERSIONIRI", "IMPORTS", "PRIORVERSION", "BACKWARDCOMPATIBLEWITH", "INCOMPATIBLEWITH",
    "DECLARATION", "ANNOTATION", "ANNOTATIONPROPERTY", "ONTOLOGYPROPERTY",
    "DEPRECATEDCLASS", "DEPRECATEDPROPERTY", "NOTHING", "THING", "TOPOBJECTPROPERTY",
    "TOPDATAPROPERTY", "BOTTOMOBJECTPROPERTY", "BOTTOMDATAPROPERTY", "OWLCLASS",
    "OWLOBJECTPROPERTY", "OWLDATATYPEPROPERTY", "OWLANNOTATIONPROPERTY",
    "OWLNAMEDINDIVIDUAL", "OWLONTOLOGY", "OWLAXIOM", "OWLDECLARATION",
    "OWLIMPORTS", "OWLVERSIONINFO", "OWLVERSIONIRI", "OWLPRIORVERSION",
    "OWLBACKWARDCOMPATIBLEWITH", "OWLINCOMPATIBLEWITH", "RDFPROPERTY", "RDFCLASS",
    "RDFRESOURCE", "RDFLIST", "RDFALT", "RDFBAG", "RDFSEQ", "RDFSTATEMENT",
    "RDFSUBJECT", "RDFPREDICATE", "RDFOBJECT", "RDFTYPE", "RDFVALUE", "RDFFIRST",
    "RDFREST", "RDFNIL", "RDFXMLLITERAL", "RDFPLAINLITERAL", "RDFLANGSTRING"
}

# Properties to exclude from schema output
EXCLUDED_PROPERTIES = {"embedding", "embedding_processed"}

# Common label mapping for LLM corrections
LABEL_MAPPINGS = {
    # CVE-related fixes
    '(cve:CVE)': '(cve:UcoCVE)',
    '(CVE)': '(UcoCVE)',
    ':CVE': ':UcoCVE',
    
    # CWE-related fixes  
    '(cwe:CWE)': '(cwe:UcoCWE)',
    '(CWE)': '(UcoCWE)',
    ':CWE': ':UcoCWE',
    
    # CAPEC-related fixes
    '(capec:CAPEC)': '(capec:UcoexCAPEC)',
    '(CAPEC)': '(UcoexCAPEC)',
    ':CAPEC': ':UcoexCAPEC',
    
    # CPE-related fixes
    '(cpe:CPE)': '(cpe:UcoexCPE)',
    '(CPE)': '(UcoexCPE)',
    ':CPE': ':UcoexCPE',
    
    # Groups-related fixes
    '(groups:GROUPS)': '(groups:UcoexGROUPS)',
    '(GROUPS)': '(UcoexGROUPS)',
    ':GROUPS': ':UcoexGROUPS',
    
    # Software-related fixes
    '(software:SOFTWARE)': '(software:UcoexSOFTWARE)',
    '(SOFTWARE)': '(UcoexSOFTWARE)',
    ':SOFTWARE': ':UcoexSOFTWARE',
}

# Default query limit
DEFAULT_QUERY_LIMIT = 1000

# Schema cache filename
SCHEMA_CACHE_FILENAME = "schema_cache.txt"

# Schema extraction configuration
SCHEMA_EXTRACTION_CONFIG = {
    "default_output_file": "schema.txt",
    "default_format": "text",  # "text", "json", "both"
    "property_sample_size": 50,  # Number of nodes to sample for type inference
    "max_properties_per_label": 10,  # Maximum properties to extract per label
    "include_metadata": True,  # Include extraction metadata in output
    "validate_schema": True,  # Run schema validation after extraction
}

# Semantic mapping for cybersecurity domain elements (only nodes/relationships that exist in schema)
CYBERSECURITY_SEMANTICS = {
    # Node Labels with semantic descriptions (from actual schema)
    "UcoCVE": "Common Vulnerabilities and Exposures - security vulnerabilities with unique identifiers (e.g., CVE-2023-1234)",
    "UcoCWE": "Common Weakness Enumeration - software weakness types and categories (e.g., CWE-79 for XSS)",
    "UcoExploitTarget": "Target systems or applications that can be exploited by vulnerabilities",
    "UcoVulnerability": "Generic vulnerability information with publication and modification dates",
    "UcoexCAMPAIGNS": "Cybersecurity campaigns - coordinated attack activities by threat groups",
    "UcoexCAPEC": "Common Attack Pattern Enumeration and Classification - attack patterns and techniques used by adversaries",
    "UcoexCPE": "Common Platform Enumeration - software and hardware products with standardized names (e.g., microsoft:windows)",
    "UcoexGROUPS": "Threat actor groups and organizations conducting cyber attacks",
    "UcoexMITIGATIONS": "Defensive techniques and countermeasures against attacks",
    "UcoexMITREATTACK": "MITRE ATT&CK framework techniques, tactics, and procedures used by adversaries",
    "UcoexMITRED3FEND": "MITRE D3FEND framework defensive techniques and countermeasures",
    "UcoexObservedExample": "Real-world examples of vulnerabilities and attacks being observed",
    "UcoexSOFTWARE": "Software applications and tools used in cybersecurity contexts",
    "UcoexTACTICS": "MITRE ATT&CK tactics - high-level adversary goals and objectives",
    
    # Relationship Types with semantic descriptions (from actual schema)
    "UCOEXHASCPE": "Vulnerability affects specific software/hardware products - connects CVEs to CPEs",
    "UCOHASOBSERVEDEXAMPLE": "Weakness has real-world observed examples - connects CWEs to observed examples",
    "UCOHASVULNERABILITY": "Exploit target has specific vulnerability - connects targets to vulnerabilities",
    "UCOHASWEAKNESS": "Exploit target has specific weakness - connects targets to CWEs",
    "UCOHASCVE_ID": "Vulnerability has specific CVE identifier - connects vulnerabilities to CVEs",
    "UCOEXATTRIBUTEDTO": "Campaign is attributed to specific threat group - connects campaigns to groups",
    "UCOEXCAMPAIGNUSESSOFTWARE": "Campaign uses specific software/tools - connects campaigns to software",
    "UCOEXCAMPAIGNUSESTECHNIQUE": "Campaign employs specific attack technique - connects campaigns to techniques",
    "UCOEXHASRELATEDWEAKNESS": "Attack pattern exploits specific weakness - connects CAPECs to CWEs",
    "UCOEXHASTAXONOMYMAPPING": "Attack pattern maps to specific MITRE technique - connects CAPECs to techniques",
    "UCOEXGROUPUSESSOFTWARE": "Threat group uses specific software/tools - connects groups to software",
    "UCOEXGROUPUSESTECHNIQUE": "Threat group employs specific attack technique - connects groups to techniques",
    "UCOEXMITIGATES": "Mitigation technique counters specific attack - connects mitigations to techniques",
    "UCOEXHASMITREATTACK": "D3FEND technique relates to specific MITRE technique - connects D3FEND to techniques",
    "UCOEXEXAMPLEOBSERVEDIN": "Observed example is found in specific CVE - connects examples to CVEs",
    "UCOEXSOFTWAREUSESTECHNIQUE": "Software uses specific attack technique - connects software to techniques"
}

# Prompt templates and examples
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

9. "Find CVE by specific ID" 
   → MATCH (cve:UcoCVE) WHERE cve.label = 'CVE-2005-2938' RETURN cve

RELATIONSHIP-BASED QUERIES:
10. "Find CAPEC patterns related to CWE-404" 
    → MATCH (capec:UcoexCAPEC)-[:UCOEXHASRELATEDWEAKNESS]->(cwe:UcoCWE) WHERE cwe.ucocweID = 'CWE-404' RETURN capec

11. "Show CVEs that affect Microsoft Windows platforms" 
    → MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) WHERE cpe.cpeName CONTAINS 'microsoft:windows' RETURN cve

12. "Find groups using specific MITRE techniques" 
    → MATCH (group:UcoexGROUPS)-[:UCOEXGROUPUSESTECHNIQUE]->(technique:UcoexMITREATTACK) WHERE technique.ucoexNAME CONTAINS 'T1078' RETURN group

13. "Show software used by specific threat groups" 
    → MATCH (group:UcoexGROUPS)-[:UCOEXGROUPUSESSOFTWARE]->(software:UcoexSOFTWARE) WHERE group.ucoexNAME = 'Gallmaker' RETURN software

14. "Find CVEs related to Adobe products" 
    → MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) WHERE cpe.cpeName CONTAINS 'adobe' RETURN cve

15. "Show CAPEC patterns that can lead to CWE-81" 
    → MATCH (capec:UcoexCAPEC)-[:UCOEXHASRELATEDWEAKNESS]->(cwe:UcoCWE) WHERE cwe.ucocweID = 'CWE-81' RETURN capec

16. "Find groups using Socksbot software" 
    → MATCH (group:UcoexGROUPS)-[:UCOEXGROUPUSESSOFTWARE]->(software:UcoexSOFTWARE) WHERE software.ucoexNAME = 'Socksbot' RETURN group

17. "Show techniques used by Gallmaker group" 
    → MATCH (group:UcoexGROUPS)-[:UCOEXGROUPUSESTECHNIQUE]->(technique:UcoexMITREATTACK) WHERE group.ucoexNAME = 'Gallmaker' RETURN technique

18. "Find CVEs affecting specific CPE entries" 
    → MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) WHERE cpe.cpeName = 'cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*:*' RETURN cve

19. "Show CAPEC patterns related to authentication weaknesses" 
    → MATCH (capec:UcoexCAPEC)-[:UCOEXHASRELATEDWEAKNESS]->(cwe:UcoCWE) WHERE cwe.ucocweName CONTAINS 'authentication' RETURN capec

20. "Find campaigns using particular attack techniques" 
    → MATCH (campaign:UcoexCAMPAIGNS)-[:UCOEXCAMPAIGNUSESTECHNIQUE]->(technique:UcoexMITREATTACK) WHERE technique.ucoexNAME CONTAINS 'T1078' RETURN campaign

21. "Show CVEs with their related CPE entries" 
    → MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) RETURN cve, cpe LIMIT 10

22. "Find CPE associated with specific CVE" 
    → MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) WHERE cve.label = 'CVE-2005-2938' RETURN cpe

23. "Show all cybersecurity relationships" 
    → MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) RETURN cve, cpe LIMIT 10

24. "Find all CAPEC patterns" 
    → MATCH (capec:UcoexCAPEC) RETURN capec LIMIT 10

25. "Show me all relationships" 
    → MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) RETURN cve, cpe LIMIT 10

26. "Find all connections" 
    → MATCH (cve:UcoCVE)-[:UCOHASWEAKNESS]->(cwe:UcoCWE) RETURN cve, cwe LIMIT 10

27. "Show me everything" 
    → MATCH (cve:UcoCVE) RETURN cve LIMIT 10

28. "Find relationships between nodes" 
    → MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE) RETURN cve, cpe LIMIT 10
"""

# Prompt building components
PROMPT_RULES = (
    "You are a Neo4j Cypher expert for a Cybersecurity Knowledge Graph.\n\n"
    "Hard constraints (must follow):\n"
    "- Use EXACT labels and relationship types from the schema.\n"
    "- Prefer explicit labels and relationships (e.g., (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE)).\n"
    "- Use only valid connections shown in RELATIONSHIPS.\n"
    "- Use exact property names as shown in the node property dictionaries.\n"
    "- Return ONLY the Cypher query. No markdown, no commentary.\n"
    "- Add LIMIT if large results are expected.\n"
    "- Map generic terms to exact labels: CVE→UcoCVE, CWE→UcoCWE, CAPEC→UcoexCAPEC, CPE→UcoexCPE.\n\n"
    "CYPHER SYNTAX RULES (CRITICAL):\n"
    "- For aggregation, use: RETURN count(n) AS count, n.property\n"
    "- For grouping, use WITH clause: WITH n.property AS prop, count(n) AS cnt RETURN prop, cnt\n"
    "- NO SQL syntax: Do NOT use GROUP BY, HAVING, or JOIN\n"
    "- For distinct values: RETURN DISTINCT n.property\n"
    "- For ordering: ORDER BY n.property DESC\n"
    "- String matching: CONTAINS (not LIKE), = for exact match\n"
    "- Comparison: >, <, >=, <=, <> (not !=)\n"
)

PROMPT_GUIDE = (
    "Writing guide:\n"
    "- MATCH nodes, WHERE property filters, RETURN projection.\n"
    "- Avoid generic nodes (n); always label nodes.\n"
    "- Avoid generic relationships []; always specify a type.\n"
    "- Use CONTAINS or = for string filters.\n\n"
)

# Error handling prompts
EMPTY_RESULTS_PROMPT = """You are a cybersecurity knowledge graph assistant. The user asked: "{question}"

The generated Cypher query was: {cypher}

This query returned no results. Provide a helpful response that:
1. Acknowledges that no results were found
2. Suggests possible reasons why (e.g., too specific filters, data might not exist)
3. Offers alternative approaches or broader queries
4. Be encouraging and helpful

Keep the response concise and professional.
"""

QUERY_ERROR_PROMPT = """You are a cybersecurity knowledge graph assistant. The user asked: "{question}"

An error occurred: {error}

Provide a helpful response that:
1. Acknowledges the error occurred
2. Explains what might have gone wrong in simple terms
3. Suggests how to rephrase the question
4. Offers to help with a different approach

Keep the response encouraging and helpful.
"""