# Unified Cybersecurity Knowledge Graph (UCKG) Schema

Nodes:
(:UcoCVE {{label: str (CVE identifier, e.g. CVE-2002-1777), ucobaseSeverity: str (CVSS severity: HIGH, MEDIUM, LOW, CRITICAL), ucovulnStatus: str (vulnerability status, e.g. Modified, Analyzed), ucovectorString: str (CVSS vector string), ucoexploitabilityScore: str, ucoimpactScore: str, ucoevaluatorSolution: str, ucoobtainAllPrivilege: str, ucouserInteractionRequired: str, uri: str (URI), embedding: list (vector embedding), embedding_processed: bool}}) // Common Vulnerabilities and Exposures (CVE) definitions
(:UcoCWE {{ucocweID: str (CWE identifier, e.g. CWE-24), ucocweName: str (weakness name), ucocweSummary: str, ucocweExtendedSummary: str, ucodescription: str, ucoabstraction: str (e.g. Class, Base, Variant), ucostructure: str (e.g. Simple, Composite), ucostatus: str (e.g. Stable, Incomplete), ucolikelihoodOfExploit: str, ucocommonConsequences: str, ucodemonstrativeExamples: str, ucodetectionMethods: str, ucopotentialMitigations: str, ucorelatedAttackPatterns: str, ucoreferences: str, ucoapplicablePlatform: str, ucomodesOfIntroduction: str, ucomappingNotes: str, ucotimeOfIntroduction: datetime, uri: str, embedding: list, embedding_processed: bool}}) // Common Weakness Enumeration (CWE) weakness types
(:UcoVulnerability {{ucosummary: str (vulnerability description), ucopublishedDateTime: datetime, ucolastModifiedDateTime: datetime, uri: str, embedding: list, embedding_processed: bool}}) // Vulnerability instances with publication timelines and summaries
(:UcoExploitTarget {{uri: str}}) // Exploit targets linking weaknesses to vulnerability instances
(:UcoexCPE {{cpeName: str (CPE 2.3 specification string), cpeNameId: str (CPE UUID), titles: str (product/platform title), dictionary_found: bool, lastModified: datetime, uri: str, embedding: list, embedding_processed: bool}}) // Common Platform Enumeration (CPE) software/hardware platforms
(:UcoexCAPEC {{label: str (CAPEC ID and name), ucoexCAPEC_id: str, ucoexCAPEC_name: str, ucoexDescription: str, ucoexExtendedDescription: list, ucoexAbstraction: str, ucoexSeverity: str, ucoexLikelihood: str, ucoexPrerequisites: list, ucoexSkills_Required: list, ucoexResources_Required: list, ucoexConsequences: list, ucoexMitigations: list, ucoexExecutionFlowTechnique: list, ucoexExample: list, ucoexRelatedAttPattern: list, ucoexRelatedWeaknesses: list, ucoexTaxonomyMappingATTACK: list, uri: str, embedding: list, embedding_processed: bool}}) // Common Attack Pattern Enumeration and Classification (CAPEC) patterns
(:UcoexMITREATTACK {{ucoexNAME: str (technique/sub-technique name), ucoexDESCRIPTION: str, ucoexDOMAIN: str (e.g. enterprise-attack, mobile-attack, ics-attack), ucoexURL: str, no_text_content: bool, uri: str, embedding: list, embedding_processed: bool}}) // MITRE ATT&CK adversarial techniques
(:UcoexMITRED3FEND {{ucoexMITRED3FEND_LABEL: str (defensive technique label), ucoexMITRED3FEND_DEFINITION: str, uri: str, embedding: list, embedding_processed: bool}}) // MITRE D3FEND defensive countermeasures
(:UcoexGROUPS {{ucoexNAME: str (threat actor/group name), ucoexDESCRIPTION: str, ucoexDOMAIN: str, ucoexURL: str, uri: str, embedding: list, embedding_processed: bool}}) // Cyber threat actor and Advanced Persistent Threat (APT) groups
(:UcoexCAMPAIGNS {{ucoexNAME: str (cyber campaign name), ucoexDESCRIPTION: str, ucoexDOMAIN: str, ucoexURL: str, uri: str, embedding: list, embedding_processed: bool}}) // Coordinated cyberattack campaigns
(:UcoexSOFTWARE {{ucoexNAME: str (software, tool, or malware name), ucoexDESCRIPTION: str, ucoexDOMAIN: str, ucoexURL: str, uri: str, embedding: list, embedding_processed: bool}}) // Software, malware families, and tools used by adversaries
(:UcoexTACTICS {{ucoexNAME: str (ATT&CK tactic name), ucoexDESCRIPTION: str, ucoexDOMAIN: str, ucoexURL: str, uri: str, embedding: list, embedding_processed: bool}}) // MITRE ATT&CK high-level tactic categories
(:UcoexMITIGATIONS {{ucoexNAME: str (mitigation name), ucoexDESCRIPTION: str, ucoexDOMAIN: str, ucoexURL: str, uri: str, embedding: list, embedding_processed: bool}}) // Defensive security mitigations recommended by ATT&CK
(:UcoexObservedExample {{ucoexDESCRIPTION: str (incident/observation summary), uri: str, embedding: list, embedding_processed: bool}}) // Real-world observed incident examples correlating weaknesses and CVEs
(:Class {{uri: str, comment: str, seeAlso: str}}) // OWL classes defined in the Unified Cybersecurity Ontology
(:Ontology {{uri: str}}) // Ontology metadata header definition
(:ObjectProperty {{uri: str, comment: str, seeAlso: str}}) // OWL object properties relating entities
(:DatatypeProperty {{uri: str}}) // OWL datatype properties relating entities to primitive literal values
(:FunctionalProperty {{uri: str}}) // Properties that have at most one unique value per subject
(:IrreflexiveProperty {{uri: str}}) // Properties where no individual can relate to itself
(:SymmetricProperty {{uri: str}}) // Properties where the inverse relationship always holds
(:Restriction {{uri: str, minQualifiedCardinality: int}}) // OWL class property restrictions (e.g. cardinality/value constraints)
(:Axiom {{uri: str, annotatedTarget: str, comment: str}}) // OWL axiom annotations providing contextual definitions
(:NamedIndividual {{uri: str}}) // Specific enumerated constant individuals in the ontology
(:Resource {{uri: str}}) // Base RDF resource node label assigned to all imported entities
(:_GraphConfig {{_applyNeo4jNaming: bool, _classLabel: str, _classNamePropName: str, _dataTypePropertyLabel: str, _domainRel: str, _handleMultival: int, _handleRDFTypes: int, _handleVocabUris: int, _keepCustomDataTypes: bool, _keepLangTag: bool, _multivalPropList: list, _objectPropertyLabel: str, _rangeRel: str, _relNamePropName: str, _subClassOfRel: str, _subPropertyOfRel: str}}) // Neosemantics (n10s) RDF ingestion configuration node

Relationships:
(:UcoVulnerability)-[:UCOHASCVE_ID]->(:UcoCVE) // links a vulnerability record to its standard CVE record
(:UcoCVE)-[:UCOEXHASCPE]->(:UcoexCPE) // links a CVE to vulnerable Common Platform Enumeration (CPE) software/hardware platforms
(:UcoExploitTarget)-[:UCOHASVULNERABILITY]->(:UcoVulnerability) // links an exploit target to affected vulnerability instances
(:UcoExploitTarget)-[:UCOHASWEAKNESS]->(:UcoCWE) // links an exploit target to root Common Weakness Enumeration (CWE) weaknesses
(:UcoCWE)-[:UCOHASOBSERVEDEXAMPLE]->(:UcoexObservedExample) // links a weakness to demonstrative observed real-world examples
(:UcoexObservedExample)-[:UCOEXEXAMPLEOBSERVEDIN]->(:UcoCVE) // links an observed incident example to the specific CVE in which it occurred
(:UcoexCAPEC)-[:UCOEXHASRELATEDWEAKNESS]->(:UcoCWE) // links an attack pattern to the software/hardware weakness (CWE) it exploits
(:UcoexCAPEC)-[:UCOEXHASTAXONOMYMAPPING]->(:UcoexMITREATTACK) // maps a CAPEC attack pattern to corresponding MITRE ATT&CK technique
(:UcoexGROUPS)-[:UCOEXGROUPUSESTECHNIQUE]->(:UcoexMITREATTACK) // threat group employs MITRE ATT&CK technique
(:UcoexGROUPS)-[:UCOEXGROUPUSESSOFTWARE]->(:UcoexSOFTWARE) // threat group utilizes software, tool, or malware
(:UcoexCAMPAIGNS)-[:UCOEXATTRIBUTEDTO]->(:UcoexGROUPS) // cyberattack campaign attributed to threat group
(:UcoexCAMPAIGNS)-[:UCOEXCAMPAIGNUSESTECHNIQUE]->(:UcoexMITREATTACK) // cyberattack campaign utilizes MITRE ATT&CK technique
(:UcoexCAMPAIGNS)-[:UCOEXCAMPAIGNUSESSOFTWARE]->(:UcoexSOFTWARE) // cyberattack campaign utilizes software or malware
(:UcoexSOFTWARE)-[:UCOEXSOFTWAREUSESTECHNIQUE]->(:UcoexMITREATTACK) // software or malware executes MITRE ATT&CK technique
(:UcoexMITIGATIONS)-[:UCOEXMITIGATES]->(:UcoexMITREATTACK) // mitigation defends against or prevents MITRE ATT&CK technique
(:UcoexMITRED3FEND)-[:UCOEXHASMITREATTACK]->(:UcoexMITREATTACK) // MITRE D3FEND defensive countermeasure maps to MITRE ATT&CK technique
(:Class)-[:SUBCLASSOF]->(:Class) // taxonomic subclass inheritance
(:Class)-[:SUBCLASSOF]->(:Restriction) // class inheritance conditioned by property restriction
(:Class)-[:EQUIVALENTCLASS]->(:Class) // semantic class equivalence
(:Class)-[:EQUIVALENTCLASS]->(:Restriction) // class equivalence defined by property restriction
(:Class)-[:UNIONOF]->(:Resource) // union of class expressions (RDF collection)
(:Class)-[:ONEOF]->(:Resource) // enumeration of individual class members (RDF collection)
(:ObjectProperty)-[:SUBPROPERTYOF]->(:ObjectProperty) // object property inheritance hierarchy
(:ObjectProperty)-[:SUBPROPERTYOF]->(:DatatypeProperty) // property subsumption relation
(:ObjectProperty)-[:DOMAIN]->(:Class) // specifies domain class of object property
(:ObjectProperty)-[:RANGE]->(:Class) // specifies range class of object property
(:ObjectProperty)-[:INVERSEOF]->(:ObjectProperty) // bidirectional inverse object properties
(:ObjectProperty)-[:INVERSEOF]->(:IrreflexiveProperty) // inverse relationship between object and irreflexive property
(:ObjectProperty)-[:EQUIVALENTPROPERTY]->(:ObjectProperty) // equivalence between object properties
(:DatatypeProperty)-[:SUBPROPERTYOF]->(:DatatypeProperty) // datatype property inheritance hierarchy
(:DatatypeProperty)-[:SUBPROPERTYOF]->(:ObjectProperty) // property subsumption relation
(:DatatypeProperty)-[:DOMAIN]->(:Class) // specifies domain class of datatype property
(:DatatypeProperty)-[:RANGE]->(:Class) // specifies range class of datatype property
(:FunctionalProperty)-[:DOMAIN]->(:Class) // specifies domain class of functional property
(:FunctionalProperty)-[:RANGE]->(:Class) // specifies range class of functional property
(:FunctionalProperty)-[:SUBPROPERTYOF]->(:Resource) // functional property hierarchy relation
(:IrreflexiveProperty)-[:DOMAIN]->(:Class) // specifies domain class of irreflexive property
(:IrreflexiveProperty)-[:RANGE]->(:Class) // specifies range class of irreflexive property
(:IrreflexiveProperty)-[:INVERSEOF]->(:ObjectProperty) // inverse relationship
(:IrreflexiveProperty)-[:INVERSEOF]->(:IrreflexiveProperty) // inverse relationship
(:SymmetricProperty)-[:DOMAIN]->(:Class) // specifies domain class of symmetric property
(:SymmetricProperty)-[:RANGE]->(:Class) // specifies range class of symmetric property
(:Restriction)-[:ONPROPERTY]->(:ObjectProperty) // property constrained by restriction
(:Restriction)-[:ONPROPERTY]->(:IrreflexiveProperty) // property constrained by restriction
(:Restriction)-[:ONCLASS]->(:Class) // target class qualified by restriction
(:Restriction)-[:SOMEVALUESFROM]->(:Class) // existential quantification constraint (owl:someValuesFrom)
(:Axiom)-[:ANNOTATEDSOURCE]->(:Class) // class source being annotated by axiom
(:Axiom)-[:ANNOTATEDPROPERTY]->(:Resource) // property being annotated by axiom
(:Ontology)-[:VERSIONIRI]->(:Ontology) // ontology version IRI definition
(:Resource)-[:FIRST]->(:Resource) // head element of an RDF collection list (rdf:first)
(:Resource)-[:REST]->(:Resource) // rest of an RDF collection list (rdf:rest)
