import re
from neo4j import GraphDatabase

class Text2Cypher:
    def __init__(self, neo4j_uri: str, neo4j_user: str, neo4j_password: str, llm):
        self.driver = GraphDatabase.driver(neo4j_uri, auth=(neo4j_user, neo4j_password))
        self.llm = llm
        
        # Define ontology metadata and generic labels to EXCLUDE (not cybersecurity domain)
        self.excluded_labels = {
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
        
        # Define generic ontology relationships to EXCLUDE (not cybersecurity domain)
        self.excluded_relationships = {
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

    def get_cybersecurity_schema(self) -> str:
        """Get rich schema information with properties + valid edge signatures (V2 approach)"""
        node_props = self._fetch_node_properties()
        rel_props = self._fetch_relationship_properties()
        rel_signatures = self._fetch_relationship_signatures()

        # --- format for prompt -------------------------------------------------------
        label_lines = "".join(
            f"- {lbl}: [{', '.join(props) if props else 'no properties'}]\n"
            for lbl, props in sorted(node_props.items())
        )

        rel_lines = "".join(
            f"- {rel}: [{', '.join(props) if props else 'no properties'}] paths: "
            f"{', '.join(sorted(rel_signatures[rel])) if rel_signatures[rel] else 'unknown'}\n"
            for rel, props in sorted(rel_props.items())
        )

        return (
            "CYBERSECURITY KNOWLEDGE GRAPH SCHEMA (v2):\n\n"
            "Node Labels and Properties:\n" + label_lines +
            "\nRelationship Types, Properties, and Signatures:\n" + rel_lines
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
        
        # 3. Check for excluded ontology metadata (warn if found)
        has_excluded_labels = any(f":{label}" in cypher for label in self.excluded_labels)
        has_excluded_relationships = any(f":{rel}" in cypher for rel in self.excluded_relationships)
        
        if has_excluded_labels or has_excluded_relationships:
            errors.append("Warning: Query contains ontology metadata labels/relationships that should be excluded")
        
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
        
        # 9. Check for invalid relationship usage (semantic validation)
        # UCOHASWEAKNESS connects UcoExploitTarget->UcoCWE, not UcoCVE->UcoCWE
        if 'UcoCVE)-[:UCOHASWEAKNESS]->(cwe:UcoCWE' in cypher:
            return False, "Invalid relationship: UCOHASWEAKNESS connects UcoExploitTarget->UcoCWE, not UcoCVE->UcoCWE"
        
        return True, "Valid Cypher query"

    def text_to_cypher(self, question: str, schema: str = None) -> str:
        schema_block = schema or self.get_cybersecurity_schema()
        
        # Print schema block for debugging
        print("=" * 80)
        print("SCHEMA BLOCK SENT TO LLM:")
        print("=" * 80)
        print(schema_block)
        print("=" * 80)
        
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
        
        prompt = (
            "You are a Neo4j Cypher expert specializing in CYBERSECURITY KNOWLEDGE GRAPHS. "
            "Generate ONLY valid Cypher queries using the exact schema names and properties provided.\n\n"
            
            "CRITICAL RULES - FOLLOW THESE EXACTLY:\n"
            "1. Use ONLY cybersecurity node labels: UcoCVE, UcoVulnerability, UcoexCPE, UcoCWE, UcoexCAPEC, UcoexMITREATTACK, UcoexMITRED3FEND, UcoexSOFTWARE, UcoexGROUPS, UcoexMITIGATIONS, UcoexCAMPAIGNS, UcoexTACTICS, UcoexObservedExample\n"
            "2. Use cybersecurity relationship types: UCOHASWEAKNESS, UCOHASCVE_ID, UCOHASVULNERABILITY, UCOEXHASCPE, UCOEXHASMITREATTACK, UCOEXGROUPUSESTECHNIQUE, UCOEXCAMPAIGNUSESTECHNIQUE, UCOEXSOFTWAREUSESTECHNIQUE, UCOEXMITIGATES, UCOEXGROUPUSESSOFTWARE, UCOEXCAMPAIGNUSESSOFTWARE, UCOEXATTRIBUTEDTO, UCOEXHASRELATEDWEAKNESS, UCOEXHASTAXONOMYMAPPING, UCOHASOBSERVEDEXAMPLE\n"
            "3. Use exact property names from the schema - check the [property1, property2, ...] lists\n"
            "4. Match nodes first, then filter by properties: MATCH (n:Label) WHERE n.property = 'value'\n"
            "5. Don't use property values as nodes: WRONG: (year:{year:\"2023\"}) CORRECT: (n:Label) WHERE n.year = \"2023\"\n"
            "6. Return ONLY the Cypher query, no explanations, no markdown, no code blocks, no text before or after\n"
            "7. Focus on SPECIFIC PROPERTY QUERIES (not semantic search - that's for GraphRAG)\n"
            "8. For text searches, use CONTAINS or = operators with exact property names\n"
            "9. Use LIMIT clauses for large result sets\n"
            "10. Prefer exact property matches over semantic similarity\n"
            "11. NEVER use generic nodes like (n) or (n1), (n2) - always use specific labels like (cve:UcoCVE)\n"
            "12. NEVER use generic relationships like [r] or [] - always use specific types like [:UCOEXHASCPE]\n"
            "13. For 'show all' or 'find everything' queries, pick a specific node type from the schema\n\n"
            
            "QUERY TYPES TO FOCUS ON:\n"
            "- Finding nodes by specific property values (severity, status, ID, etc.)\n"
            "- Filtering by exact property matches (domain, abstraction, structure, etc.)\n"
            "- Searching for specific text in properties (names, descriptions, etc.)\n"
            "- Following relationships between specific node types (CWE→CAPEC, CVE→CPE, Group→Technique, etc.)\n"
            "- Finding related nodes through relationships (e.g., 'Find CAPEC patterns related to CWE-521')\n"
            "- Counting nodes with specific properties\n\n"
            "HANDLING GENERIC QUERIES:\n"
            "- For 'show all relationships' → pick a specific relationship like CVE→CPE\n"
            "- For 'find connections' → pick a specific connection like CVE→CWE\n"
            "- For 'show everything' → pick a specific node type like UcoCVE\n"
            "- For 'find relationships between nodes' → pick specific node types and relationship\n\n"
            
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
            return result

    # ---- V2 helper methods for rich schema extraction ----
    
    def _fetch_node_properties(self) -> dict:
        """Return mapping label -> sorted list of property names (excluding ontology metadata)."""
        node_props = {}
        with self.driver.session() as session:
            # Get all node labels from database
            result = session.run("CALL db.labels()")
            all_labels = [record['label'] for record in result]
            
            # Filter out excluded labels (ontology metadata)
            cybersecurity_labels = [label for label in all_labels if label not in self.excluded_labels]
            
            for lbl in cybersecurity_labels:
                try:
                    # Get all distinct property keys for this label
                    res = session.run(
                        f"MATCH (n:{lbl}) RETURN DISTINCT keys(n) AS props LIMIT 10"
                    )
                    all_props = set()
                    for record in res:
                        if record["props"]:
                            all_props.update(record["props"])
                    node_props[lbl] = sorted(all_props) if all_props else []
                except Exception as e:
                    print(f"Warning: Could not get properties for {lbl}: {e}")
                    node_props[lbl] = []
        return node_props

    def _fetch_relationship_properties(self) -> dict:
        """Return mapping rel-type -> sorted list of property names (excluding ontology metadata)."""
        rel_props = {}
        with self.driver.session() as session:
            # Get all relationship types from database
            result = session.run("CALL db.relationshipTypes()")
            all_relationships = [record['relationshipType'] for record in result]
            
            # Filter out excluded relationships (ontology metadata)
            cybersecurity_relationships = [rel for rel in all_relationships if rel not in self.excluded_relationships]
            
            for rel in cybersecurity_relationships:
                try:
                    # Get all distinct property keys for this relationship type
                    res = session.run(
                        f"MATCH ()-[r:{rel}]->() RETURN DISTINCT keys(r) AS props LIMIT 10"
                    )
                    all_props = set()
                    for record in res:
                        if record["props"]:
                            all_props.update(record["props"])
                    rel_props[rel] = sorted(all_props) if all_props else []
                except Exception as e:
                    print(f"Warning: Could not get properties for {rel}: {e}")
                    rel_props[rel] = []
        return rel_props

    def _fetch_relationship_signatures(self) -> dict:
        """Return mapping rel-type -> set of "startLabel->endLabel" signatures."""
        from collections import defaultdict
        sigs = defaultdict(set)
        with self.driver.session() as session:
            record = session.run("CALL db.schema.visualization()").single()
            if record is None:
                return sigs
            nodes = record.get("nodes")
            rels = record.get("relationships")
            if not isinstance(nodes, list) or not isinstance(rels, list):
                return sigs

        # Map node element_id to the first non-excluded label it carries
        id_to_label = {}
        for n in nodes:
            # Extract element_id from Neo4j Node object
            node_id = n.element_id if hasattr(n, 'element_id') else str(n)
            # Extract labels from Neo4j Node object
            labels = list(n.labels) if hasattr(n, 'labels') else []
            # Find first label that's not in excluded_labels
            label_match = next((l for l in labels if l not in self.excluded_labels), None)
            if label_match is not None:
                id_to_label[node_id] = label_match

        for r in rels:
            # Extract relationship type from Neo4j Relationship object
            rel_type = r.type if hasattr(r, 'type') else str(r)
            # Skip excluded relationships (ontology metadata)
            if rel_type in self.excluded_relationships:
                continue
            
            # Extract start and end nodes from Neo4j Relationship object
            start_node = r.start_node if hasattr(r, 'start_node') else None
            end_node = r.end_node if hasattr(r, 'end_node') else None
            
            if start_node and end_node:
                start_id = start_node.element_id if hasattr(start_node, 'element_id') else str(start_node)
                end_id = end_node.element_id if hasattr(end_node, 'element_id') else str(end_node)
                
                start_label = id_to_label.get(start_id)
                end_label = id_to_label.get(end_id)
                if start_label and end_label:
                    sigs[rel_type].add(f"{start_label}->{end_label}")

        return sigs

def extract_cypher(text: str) -> str:
    text = re.sub(r'(?i)^\s*cypher\s*', '', text).strip()
    
    # Try to extract from code blocks first
    pattern = r"```(?:cypher)?\n?(.*?)```"
    matches = re.findall(pattern, text, re.DOTALL)
    if matches:
        return matches[0].strip()
    
    # If no code blocks, look for lines that start with MATCH, RETURN, etc.
    lines = text.split('\n')
    cypher_lines = []
    for line in lines:
        line = line.strip()
        if line and (line.upper().startswith(('MATCH', 'RETURN', 'WITH', 'UNWIND', 'CALL', 'CREATE', 'DELETE', 'SET', 'REMOVE', 'MERGE'))):
            cypher_lines.append(line)
    
    if cypher_lines:
        return '\n'.join(cypher_lines)
    
    # Fallback to original text
    return text.strip()
