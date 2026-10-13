#!/usr/bin/env python3
"""
generate_schema.py

Inspects the Unified Cybersecurity Knowledge Graph (UCKG) in Neo4j
via the HTTP transaction API (using APOC metadata schema) and generates
the complete schema in Markdown format (schema.md).

Usage:
    python generate_schema.py
    python generate_schema.py --host 100.64.54.72 --port 7474 --user neo4j --password abcd90909090
"""

import argparse
import base64
import json
import os
import sys
import urllib.request
import urllib.error

# Human-readable annotations for cybersecurity domain and ontology entities
NODE_DESCRIPTIONS = {
    "UcoCVE": "Common Vulnerabilities and Exposures (CVE) definitions",
    "UcoCWE": "Common Weakness Enumeration (CWE) weakness types",
    "UcoVulnerability": "Vulnerability instances with publication timelines and summaries",
    "UcoExploitTarget": "Exploit targets linking weaknesses to vulnerability instances",
    "UcoexCPE": "Common Platform Enumeration (CPE) software/hardware platforms",
    "UcoexCAPEC": "Common Attack Pattern Enumeration and Classification (CAPEC) patterns",
    "UcoexMITREATTACK": "MITRE ATT&CK adversarial techniques",
    "UcoexMITRED3FEND": "MITRE D3FEND defensive countermeasures",
    "UcoexGROUPS": "Cyber threat actor and Advanced Persistent Threat (APT) groups",
    "UcoexCAMPAIGNS": "Coordinated cyberattack campaigns",
    "UcoexSOFTWARE": "Software, malware families, and tools used by adversaries",
    "UcoexTACTICS": "MITRE ATT&CK high-level tactic categories",
    "UcoexMITIGATIONS": "Defensive security mitigations recommended by ATT&CK",
    "UcoexObservedExample": "Real-world observed incident examples correlating weaknesses and CVEs",
    "Class": "OWL classes defined in the Unified Cybersecurity Ontology",
    "Ontology": "Ontology metadata header definition",
    "ObjectProperty": "OWL object properties relating entities",
    "DatatypeProperty": "OWL datatype properties relating entities to primitive literal values",
    "FunctionalProperty": "Properties that have at most one unique value per subject",
    "IrreflexiveProperty": "Properties where no individual can relate to itself",
    "SymmetricProperty": "Properties where the inverse relationship always holds",
    "Restriction": "OWL class property restrictions (e.g. cardinality/value constraints)",
    "Axiom": "OWL axiom annotations providing contextual definitions",
    "NamedIndividual": "Specific enumerated constant individuals in the ontology",
    "Resource": "Base RDF resource node label assigned to all imported entities",
    "_GraphConfig": "Neosemantics (n10s) RDF ingestion configuration node"
}

PROP_DESCRIPTIONS = {
    # UcoCVE
    ("UcoCVE", "label"): "CVE identifier, e.g. CVE-2002-1777",
    ("UcoCVE", "ucobaseSeverity"): "CVSS severity: HIGH, MEDIUM, LOW, CRITICAL",
    ("UcoCVE", "ucovulnStatus"): "vulnerability status, e.g. Modified, Analyzed",
    ("UcoCVE", "ucovectorString"): "CVSS vector string",
    ("UcoCVE", "uri"): "URI",
    ("UcoCVE", "embedding"): "vector embedding",
    # UcoCWE
    ("UcoCWE", "ucocweID"): "CWE identifier, e.g. CWE-24",
    ("UcoCWE", "ucocweName"): "weakness name",
    ("UcoCWE", "ucoabstraction"): "e.g. Class, Base, Variant",
    ("UcoCWE", "ucostructure"): "e.g. Simple, Composite",
    ("UcoCWE", "ucostatus"): "e.g. Stable, Incomplete",
    # UcoVulnerability
    ("UcoVulnerability", "ucosummary"): "vulnerability description",
    # UcoexCPE
    ("UcoexCPE", "cpeName"): "CPE 2.3 specification string",
    ("UcoexCPE", "cpeNameId"): "CPE UUID",
    ("UcoexCPE", "titles"): "product/platform title",
    # UcoexCAPEC
    ("UcoexCAPEC", "label"): "CAPEC ID and name",
    # UcoexMITREATTACK
    ("UcoexMITREATTACK", "ucoexNAME"): "technique/sub-technique name",
    ("UcoexMITREATTACK", "ucoexDOMAIN"): "e.g. enterprise-attack, mobile-attack, ics-attack",
    # UcoexMITRED3FEND
    ("UcoexMITRED3FEND", "ucoexMITRED3FEND_LABEL"): "defensive technique label",
    # UcoexGROUPS
    ("UcoexGROUPS", "ucoexNAME"): "threat actor/group name",
    # UcoexCAMPAIGNS
    ("UcoexCAMPAIGNS", "ucoexNAME"): "cyber campaign name",
    # UcoexSOFTWARE
    ("UcoexSOFTWARE", "ucoexNAME"): "software, tool, or malware name",
    # UcoexTACTICS
    ("UcoexTACTICS", "ucoexNAME"): "ATT&CK tactic name",
    # UcoexMITIGATIONS
    ("UcoexMITIGATIONS", "ucoexNAME"): "mitigation name",
    # UcoexObservedExample
    ("UcoexObservedExample", "ucoexDESCRIPTION"): "incident/observation summary"
}

REL_DESCRIPTIONS = {
    ("UcoVulnerability", "UCOHASCVE_ID", "UcoCVE"): "links a vulnerability record to its standard CVE record",
    ("UcoCVE", "UCOEXHASCPE", "UcoexCPE"): "links a CVE to vulnerable Common Platform Enumeration (CPE) software/hardware platforms",
    ("UcoExploitTarget", "UCOHASVULNERABILITY", "UcoVulnerability"): "links an exploit target to affected vulnerability instances",
    ("UcoExploitTarget", "UCOHASWEAKNESS", "UcoCWE"): "links an exploit target to root Common Weakness Enumeration (CWE) weaknesses",
    ("UcoCWE", "UCOHASOBSERVEDEXAMPLE", "UcoexObservedExample"): "links a weakness to demonstrative observed real-world examples",
    ("UcoexObservedExample", "UCOEXEXAMPLEOBSERVEDIN", "UcoCVE"): "links an observed incident example to the specific CVE in which it occurred",
    ("UcoexCAPEC", "UCOEXHASRELATEDWEAKNESS", "UcoCWE"): "links an attack pattern to the software/hardware weakness (CWE) it exploits",
    ("UcoexCAPEC", "UCOEXHASTAXONOMYMAPPING", "UcoexMITREATTACK"): "maps a CAPEC attack pattern to corresponding MITRE ATT&CK technique",
    ("UcoexGROUPS", "UCOEXGROUPUSESTECHNIQUE", "UcoexMITREATTACK"): "threat group employs MITRE ATT&CK technique",
    ("UcoexGROUPS", "UCOEXGROUPUSESSOFTWARE", "UcoexSOFTWARE"): "threat group utilizes software, tool, or malware",
    ("UcoexCAMPAIGNS", "UCOEXATTRIBUTEDTO", "UcoexGROUPS"): "cyberattack campaign attributed to threat group",
    ("UcoexCAMPAIGNS", "UCOEXCAMPAIGNUSESTECHNIQUE", "UcoexMITREATTACK"): "cyberattack campaign utilizes MITRE ATT&CK technique",
    ("UcoexCAMPAIGNS", "UCOEXCAMPAIGNUSESSOFTWARE", "UcoexSOFTWARE"): "cyberattack campaign utilizes software or malware",
    ("UcoexSOFTWARE", "UCOEXSOFTWAREUSESTECHNIQUE", "UcoexMITREATTACK"): "software or malware executes MITRE ATT&CK technique",
    ("UcoexMITIGATIONS", "UCOEXMITIGATES", "UcoexMITREATTACK"): "mitigation defends against or prevents MITRE ATT&CK technique",
    ("UcoexMITRED3FEND", "UCOEXHASMITREATTACK", "UcoexMITREATTACK"): "MITRE D3FEND defensive countermeasure maps to MITRE ATT&CK technique",
    ("Class", "SUBCLASSOF", "Class"): "taxonomic subclass inheritance",
    ("Class", "SUBCLASSOF", "Restriction"): "class inheritance conditioned by property restriction",
    ("Class", "EQUIVALENTCLASS", "Class"): "semantic class equivalence",
    ("Class", "EQUIVALENTCLASS", "Restriction"): "class equivalence defined by property restriction",
    ("Class", "UNIONOF", "Resource"): "union of class expressions (RDF collection)",
    ("Class", "ONEOF", "Resource"): "enumeration of individual class members (RDF collection)",
    ("ObjectProperty", "SUBPROPERTYOF", "ObjectProperty"): "object property inheritance hierarchy",
    ("ObjectProperty", "SUBPROPERTYOF", "DatatypeProperty"): "property subsumption relation",
    ("ObjectProperty", "DOMAIN", "Class"): "specifies domain class of object property",
    ("ObjectProperty", "RANGE", "Class"): "specifies range class of object property",
    ("ObjectProperty", "INVERSEOF", "ObjectProperty"): "bidirectional inverse object properties",
    ("ObjectProperty", "INVERSEOF", "IrreflexiveProperty"): "inverse relationship between object and irreflexive property",
    ("ObjectProperty", "EQUIVALENTPROPERTY", "ObjectProperty"): "equivalence between object properties",
    ("DatatypeProperty", "SUBPROPERTYOF", "DatatypeProperty"): "datatype property inheritance hierarchy",
    ("DatatypeProperty", "SUBPROPERTYOF", "ObjectProperty"): "property subsumption relation",
    ("DatatypeProperty", "DOMAIN", "Class"): "specifies domain class of datatype property",
    ("DatatypeProperty", "RANGE", "Class"): "specifies range class of datatype property",
    ("FunctionalProperty", "DOMAIN", "Class"): "specifies domain class of functional property",
    ("FunctionalProperty", "RANGE", "Class"): "specifies range class of functional property",
    ("FunctionalProperty", "SUBPROPERTYOF", "Resource"): "functional property hierarchy relation",
    ("IrreflexiveProperty", "DOMAIN", "Class"): "specifies domain class of irreflexive property",
    ("IrreflexiveProperty", "RANGE", "Class"): "specifies range class of irreflexive property",
    ("IrreflexiveProperty", "INVERSEOF", "ObjectProperty"): "inverse relationship",
    ("IrreflexiveProperty", "INVERSEOF", "IrreflexiveProperty"): "inverse relationship",
    ("SymmetricProperty", "DOMAIN", "Class"): "specifies domain class of symmetric property",
    ("SymmetricProperty", "RANGE", "Class"): "specifies range class of symmetric property",
    ("Restriction", "ONPROPERTY", "ObjectProperty"): "property constrained by restriction",
    ("Restriction", "ONPROPERTY", "IrreflexiveProperty"): "property constrained by restriction",
    ("Restriction", "ONCLASS", "Class"): "target class qualified by restriction",
    ("Restriction", "SOMEVALUESFROM", "Class"): "existential quantification constraint (owl:someValuesFrom)",
    ("Axiom", "ANNOTATEDSOURCE", "Class"): "class source being annotated by axiom",
    ("Axiom", "ANNOTATEDPROPERTY", "Resource"): "property being annotated by axiom",
    ("Ontology", "VERSIONIRI", "Ontology"): "ontology version IRI definition",
    ("Resource", "FIRST", "Resource"): "head element of an RDF collection list (rdf:first)",
    ("Resource", "REST", "Resource"): "rest of an RDF collection list (rdf:rest)"
}

TYPE_MAP = {
    "STRING": "str",
    "INTEGER": "int",
    "FLOAT": "float",
    "BOOLEAN": "bool",
    "LIST": "list",
    "LOCAL_DATE_TIME": "datetime",
    "DATE_TIME": "datetime"
}

# Preferred ordering for domain clarity
DOMAIN_NODES = [
    "UcoCVE", "UcoCWE", "UcoVulnerability", "UcoExploitTarget",
    "UcoexCPE", "UcoexCAPEC", "UcoexMITREATTACK", "UcoexMITRED3FEND",
    "UcoexGROUPS", "UcoexCAMPAIGNS", "UcoexSOFTWARE", "UcoexTACTICS",
    "UcoexMITIGATIONS", "UcoexObservedExample"
]

METAMODEL_NODES = [
    "Class", "Ontology", "ObjectProperty", "DatatypeProperty",
    "FunctionalProperty", "IrreflexiveProperty", "SymmetricProperty",
    "Restriction", "Axiom", "NamedIndividual", "Resource", "_GraphConfig"
]

def query_neo4j(url, user, password, query):
    auth = base64.b64encode(f"{user}:{password}".encode("ascii")).decode("ascii")
    payload = json.dumps({"statements": [{"statement": query}]}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json", "Authorization": f"Basic {auth}"}
    )
    with urllib.request.urlopen(req) as resp:
        res = json.loads(resp.read().decode("utf-8"))
        if res.get("errors"):
            raise RuntimeError(f"Cypher Error: {res['errors']}")
        return res["results"][0]["data"]

def format_node(label, node_info):
    if label == "Resource":
        return "(:Resource {{uri: str}}) // Base RDF resource node label assigned to all imported entities"
    props = node_info.get("properties", {})
    prop_parts = []
    for prop_name, prop_meta in sorted(props.items()):
        raw_type = prop_meta.get("type", "STRING")
        mapped_type = TYPE_MAP.get(raw_type, raw_type.lower())
        desc = PROP_DESCRIPTIONS.get((label, prop_name))
        if desc:
            prop_parts.append(f"{prop_name}: {mapped_type} ({desc})")
        else:
            prop_parts.append(f"{prop_name}: {mapped_type}")
    
    props_str = ", ".join(prop_parts)
    desc = NODE_DESCRIPTIONS.get(label, "")
    comment_suffix = f" // {desc}" if desc else ""
    return f"(:{label} {{{{{props_str}}}}}){comment_suffix}"

def extract_relationships(schema_meta):
    nodes = {k: v for k, v in schema_meta.items() if v.get("type") == "node"}
    rels = set()
    for src, info in nodes.items():
        if src == "Resource":
            continue
        node_rels = info.get("relationships", {})
        for rname, rmeta in node_rels.items():
            if rmeta.get("direction") == "out":
                target_labels = rmeta.get("labels", [])
                for tgt in target_labels:
                    if tgt == "Resource" and (src, rname) not in [
                        ("Class", "UNIONOF"), ("Class", "ONEOF"), ("FunctionalProperty", "SUBPROPERTYOF"), ("Axiom", "ANNOTATEDPROPERTY")
                    ]:
                        continue
                    rels.add((src, rname, tgt))
    
    # Specific known RDF collection relationships originating from Resource
    rels.add(("Class", "UNIONOF", "Resource"))
    rels.add(("Class", "ONEOF", "Resource"))
    rels.add(("FunctionalProperty", "SUBPROPERTYOF", "Resource"))
    rels.add(("Axiom", "ANNOTATEDPROPERTY", "Resource"))
    rels.add(("Resource", "FIRST", "Resource"))
    rels.add(("Resource", "REST", "Resource"))
    return rels

def format_rel(src, rname, tgt):
    desc = REL_DESCRIPTIONS.get((src, rname, tgt), "")
    comment_suffix = f" // {desc}" if desc else ""
    return f"(:{src})-[:{rname}]->(:{tgt}){comment_suffix}"

def generate_schema_markdown(schema_meta):
    lines = [
        "# Unified Cybersecurity Knowledge Graph (UCKG) Schema\n\n### Nodes:\n<pre>"
    ]
    nodes = {k: v for k, v in schema_meta.items() if v.get("type") == "node"}
    
    # Order nodes by domain first, then metamodel, then any others
    ordered_labels = []
    for l in DOMAIN_NODES:
        if l in nodes:
            ordered_labels.append(l)
    for l in METAMODEL_NODES:
        if l in nodes and l not in ordered_labels:
            ordered_labels.append(l)
    for l in sorted(nodes.keys()):
        if l not in ordered_labels:
            ordered_labels.append(l)
            
    for label in ordered_labels:
        lines.append(format_node(label, nodes[label]))
        
    lines.append("</pre>\n\n### Relationships:\n<pre>")
    raw_rels = extract_relationships(schema_meta)
    
    # Sort relationships domain-first according to REL_DESCRIPTIONS
    known_order = list(REL_DESCRIPTIONS.keys())
    ordered_rels = []
    for triple in known_order:
        if triple in raw_rels:
            ordered_rels.append(triple)
    for triple in sorted(raw_rels):
        if triple not in ordered_rels:
            ordered_rels.append(triple)
            
    for src, rname, tgt in ordered_rels:
        lines.append(format_rel(src, rname, tgt))
        
    lines.append("</pre>\n")
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Inspect Neo4j and generate UCKG schema.md")
    parser.add_argument("--host", default=os.getenv("NEO4J_HOST", "100.64.54.72"), help="Neo4j host")
    parser.add_argument("--port", default=os.getenv("NEO4J_PORT", "7474"), help="Neo4j HTTP port")
    parser.add_argument("--database", default=os.getenv("NEO4J_DATABASE", "neo4j"), help="Database name")
    parser.add_argument("--user", default=os.getenv("NEO4J_USER", "neo4j"), help="Username")
    parser.add_argument("--password", default=os.getenv("NEO4J_PASSWORD", "abcd90909090"), help="Password")
    default_out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.md")
    parser.add_argument("--output", default=default_out, help="Output markdown path")
    args = parser.parse_args()

    tx_url = f"http://{args.host}:{args.port}/db/{args.database}/tx/commit"
    print(f"Connecting to Neo4j at {tx_url}...")
    
    try:
        data = query_neo4j(tx_url, args.user, args.password, "CALL apoc.meta.schema()")
        schema_meta = data[0]["row"][0]
    except Exception as e:
        print(f"Error querying Neo4j schema: {e}", file=sys.stderr)
        sys.exit(1)

    print("Generating schema markdown...")
    content = generate_schema_markdown(schema_meta)

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(content)

    print(f"Successfully generated schema: {args.output}")

if __name__ == "__main__":
    main()
