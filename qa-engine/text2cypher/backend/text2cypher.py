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
        
        prompt = (
            f"{PROMPT_TEMPLATE}\n\n"
            
            f"{FEW_SHOT_EXAMPLES}\n\n"
            f"CYBERSECURITY SCHEMA:\n{schema_block}\n\n"
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
