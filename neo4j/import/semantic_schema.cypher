// ═══════════════════════════════════════════════════════════════════════════
// UCKG Semantic Schema  —  authoritative Cypher definitions  (version: v3)
//
// This file is the single source of truth for all semantic metadata in UCKG.
// Load into Neo4j via:
//
//   python3 schema/semantic_schema.py update
//
// All statements use MERGE — safe to re-run; later executions override earlier
// definitions in place.
//
// Sections
//   1. UCKGMeta_Schema       — schema singleton / version node
//   2. UCKGMeta_Node         — one node per entity type  (14 nodes)
//   3. UCKGMeta_Property     — one node per property per entity type (81 nodes)
//   4. UCKGMeta_Relationship — one node per relationship type (16 nodes)
//   5. META_CONNECTS_TO      — schema-level topology edges (16 edges)
//   6. UCKGMeta_TraversalPath — documented multi-hop patterns (7 nodes)
// ═══════════════════════════════════════════════════════════════════════════


// ── 1. Schema singleton ───────────────────────────────────────────────────
MERGE (s:UCKGMeta_Schema {version: 'v3'})
SET   s.notes                 = 'UCKG semantic schema v3. Covers 14 node types, 16 relationship triples, 81 properties, and 7 traversal paths. All definitions are ground-truthed against schema_cache.txt (44/44 aligned).',
      s.embedding_corpus_size = 66,
      s.last_loaded           = datetime();


// ── 2. Node type metadata ─────────────────────────────────────────────────

MERGE (n:UCKGMeta_Node {semantic: 'CVE'})
SET   n.physical_label       = 'UcoCVE',
      n.purpose               = 'Canonical CVE disclosure entry. Primary vulnerability identifier node.',
      n.description           = 'A CVE node identifies a specific publicly known vulnerability uniquely by its label property (e.g. CVE-2021-44228). It carries CVSS v2/v3 scoring: base severity, exploitability subscore, impact subscore, and the raw vector string. The vulnerability status (ucovulnStatus) tracks NVD analysis completeness.',
      n.key_identifier        = 'label',
      n.key_identifier_example = 'CVE-2021-44228',
      n.nl_template           = '{ID}, which is a vulnerability',
      n.triggers              = ['find CVE', 'vulnerability identifier', 'CVE score', 'severity rating', 'exploitability', 'impact score', 'CVSS vector', 'vulnerability status'];
MATCH (s:UCKGMeta_Schema {version:'v3'}), (n:UCKGMeta_Node {semantic:'CVE'})
MERGE (s)-[:META_HAS_NODE]->(n);

MERGE (n:UCKGMeta_Node {semantic: 'Vulnerability'})
SET   n.physical_label       = 'UcoVulnerability',
      n.purpose               = 'Vulnerability concept node carrying temporal metadata and free-text summary.',
      n.description           = 'Bridges ExploitTarget and CVE: ExploitTarget→Vulnerability→CVE→CPE. Temporal properties (ucopublishedDateTime, ucolastModifiedDateTime) and the free-text summary (ucosummary) live here, not on UcoCVE.',
      n.key_identifier        = 'uri',
      n.key_identifier_example = 'http://uckg.org/vulnerability/...',
      n.nl_template           = '{ID}, which is a vulnerability record',
      n.triggers              = ['vulnerability published', 'disclosed in', 'vulnerability description', 'when was vulnerability found', 'vulnerability summary', 'modified date'];
MATCH (s:UCKGMeta_Schema {version:'v3'}), (n:UCKGMeta_Node {semantic:'Vulnerability'})
MERGE (s)-[:META_HAS_NODE]->(n);

MERGE (n:UCKGMeta_Node {semantic: 'Weakness'})
SET   n.physical_label       = 'UcoCWE',
      n.purpose               = 'Common Weakness Enumeration entry — abstract weakness category.',
      n.description           = 'Identified by ucocweID (e.g. CWE-79). Carries name, summary, abstraction level (Variant/Base/Class/Pillar), exploitation likelihood, detection methods, and potential mitigations text. Links to ObservedExamples and ExploitTargets.',
      n.key_identifier        = 'ucocweID',
      n.key_identifier_example = 'CWE-79',
      n.nl_template           = '{ID}, which is a software weakness',
      n.triggers              = ['weakness', 'CWE', 'software weakness', 'vulnerability class', 'cross-site scripting', 'buffer overflow', 'injection', 'weakness category', 'likelihood of exploit'];
MATCH (s:UCKGMeta_Schema {version:'v3'}), (n:UCKGMeta_Node {semantic:'Weakness'})
MERGE (s)-[:META_HAS_NODE]->(n);

MERGE (n:UCKGMeta_Node {semantic: 'ExploitTarget'})
SET   n.physical_label       = 'UcoExploitTarget',
      n.purpose               = 'Abstract pivot node linking a CWE weakness to a Vulnerability.',
      n.description           = 'Acts as intermediary in the chain: CWE→ExploitTarget→Vulnerability→CVE→CPE. Has no descriptive properties (only uri). To traverse from a CWE to its CVEs you must pass through ExploitTarget→Vulnerability.',
      n.key_identifier        = 'uri',
      n.key_identifier_example = 'http://uckg.org/exploittarget/...',
      n.nl_template           = 'exploit target {ID}',
      n.triggers              = ['weakness causes vulnerability', 'CWE linked to CVE', 'exploit target', 'vulnerability root cause'];
MATCH (s:UCKGMeta_Schema {version:'v3'}), (n:UCKGMeta_Node {semantic:'ExploitTarget'})
MERGE (s)-[:META_HAS_NODE]->(n);

MERGE (n:UCKGMeta_Node {semantic: 'Campaign'})
SET   n.physical_label       = 'UcoexCAMPAIGNS',
      n.purpose               = 'MITRE ATT&CK Campaign — a coordinated set of malicious activities over time.',
      n.description           = 'Named threat campaigns (e.g. Operation APT29). Can be attributed to groups, use techniques, and deploy software. Primary key: ucoexNAME.',
      n.key_identifier        = 'ucoexNAME',
      n.key_identifier_example = 'Operation Wocao',
      n.nl_template           = '{ID}, which is a threat campaign',
      n.triggers              = ['campaign', 'operation', 'attack campaign', 'threat campaign', 'attributed to group', 'campaign uses', 'coordinated attack'];
MATCH (s:UCKGMeta_Schema {version:'v3'}), (n:UCKGMeta_Node {semantic:'Campaign'})
MERGE (s)-[:META_HAS_NODE]->(n);

MERGE (n:UCKGMeta_Node {semantic: 'Group'})
SET   n.physical_label       = 'UcoexGROUPS',
      n.purpose               = 'MITRE ATT&CK threat actor group (APT / intrusion set).',
      n.description           = 'Named threat actor groups (e.g. APT29, Lazarus Group). Can use techniques directly, employ software, and be attributed campaigns. Primary key: ucoexNAME.',
      n.key_identifier        = 'ucoexNAME',
      n.key_identifier_example = 'APT29',
      n.nl_template           = '{ID}, which is a threat actor group',
      n.triggers              = ['threat group', 'APT group', 'threat actor', 'hacker group', 'intrusion set', 'group uses', 'attributed to group', 'nation-state actor'];
MATCH (s:UCKGMeta_Schema {version:'v3'}), (n:UCKGMeta_Node {semantic:'Group'})
MERGE (s)-[:META_HAS_NODE]->(n);

MERGE (n:UCKGMeta_Node {semantic: 'Technique'})
SET   n.physical_label       = 'UcoexMITREATTACK',
      n.purpose               = 'MITRE ATT&CK technique or sub-technique describing adversary behavior.',
      n.description           = 'Covers both parent techniques (e.g. T1566 Phishing) and sub-techniques (e.g. T1566.001). Core pivot connecting groups, campaigns, software, mitigations, D3FEND controls, and CAPEC patterns. Primary key: ucoexNAME.',
      n.key_identifier        = 'ucoexNAME',
      n.key_identifier_example = 'Phishing',
      n.nl_template           = '{ID}, which is an adversary technique',
      n.triggers              = ['technique', 'ATT&CK technique', 'adversary behavior', 'attack technique', 'sub-technique', 'TTP', 'how do attackers'];
MATCH (s:UCKGMeta_Schema {version:'v3'}), (n:UCKGMeta_Node {semantic:'Technique'})
MERGE (s)-[:META_HAS_NODE]->(n);

MERGE (n:UCKGMeta_Node {semantic: 'Tactic'})
SET   n.physical_label       = 'UcoexTACTICS',
      n.purpose               = 'MITRE ATT&CK tactic — high-level adversary goal or attack phase.',
      n.description           = 'Represents the 14 ATT&CK enterprise tactics (Initial Access, Execution, Persistence, etc.). Groups multiple techniques sharing the same adversary objective. Primary key: ucoexNAME.',
      n.key_identifier        = 'ucoexNAME',
      n.key_identifier_example = 'Initial Access',
      n.nl_template           = '{ID}, which is an attack tactic',
      n.triggers              = ['tactic', 'attack phase', 'adversary objective', 'kill chain phase', 'initial access', 'persistence', 'lateral movement', 'exfiltration'];
MATCH (s:UCKGMeta_Schema {version:'v3'}), (n:UCKGMeta_Node {semantic:'Tactic'})
MERGE (s)-[:META_HAS_NODE]->(n);

MERGE (n:UCKGMeta_Node {semantic: 'Software'})
SET   n.physical_label       = 'UcoexSOFTWARE',
      n.purpose               = 'MITRE ATT&CK Software — malware or tools used by threat actors.',
      n.description           = 'Covers both malware (Emotet, Cobalt Strike) and tools (Mimikatz, PsExec). A software item can be used by multiple groups and campaigns and can employ specific ATT&CK techniques. Primary key: ucoexNAME.',
      n.key_identifier        = 'ucoexNAME',
      n.key_identifier_example = 'Mimikatz',
      n.nl_template           = '{ID}, which is a threat software tool',
      n.triggers              = ['software', 'malware', 'tool', 'ransomware', 'trojan', 'backdoor', 'exploit kit', 'remote access tool', 'RAT'];
MATCH (s:UCKGMeta_Schema {version:'v3'}), (n:UCKGMeta_Node {semantic:'Software'})
MERGE (s)-[:META_HAS_NODE]->(n);

MERGE (n:UCKGMeta_Node {semantic: 'Mitigation'})
SET   n.physical_label       = 'UcoexMITIGATIONS',
      n.purpose               = 'MITRE ATT&CK mitigation — security control that reduces technique effectiveness.',
      n.description           = 'Models the ATT&CK mitigation catalogue. Each mitigation links to techniques via UCOEXMITIGATES. Primary key: ucoexNAME (e.g. Multi-factor Authentication).',
      n.key_identifier        = 'ucoexNAME',
      n.key_identifier_example = 'Multi-factor Authentication',
      n.nl_template           = '{ID}, which is a security mitigation',
      n.triggers              = ['mitigation', 'defense', 'countermeasure', 'control', 'remediation', 'how to prevent', 'how to mitigate', 'security recommendation'];
MATCH (s:UCKGMeta_Schema {version:'v3'}), (n:UCKGMeta_Node {semantic:'Mitigation'})
MERGE (s)-[:META_HAS_NODE]->(n);

MERGE (n:UCKGMeta_Node {semantic: 'AttackPattern'})
SET   n.physical_label       = 'UcoexCAPEC',
      n.purpose               = 'CAPEC attack pattern — abstract method used to exploit software weaknesses.',
      n.description           = 'CAPEC entries at varying abstraction levels (Meta, Standard, Detailed). Identified by ucoexCAPEC_id (e.g. CAPEC-66). Maps to related CWEs (UCOEXHASRELATEDWEAKNESS) and ATT&CK techniques (UCOEXHASTAXONOMYMAPPING). Carries prerequisites, execution flow, severity, and likelihood.',
      n.key_identifier        = 'ucoexCAPEC_id',
      n.key_identifier_example = 'CAPEC-66',
      n.nl_template           = '{ID}, which is an attack pattern',
      n.triggers              = ['attack pattern', 'CAPEC', 'common attack', 'how to exploit', 'attack method', 'exploitation technique'];
MATCH (s:UCKGMeta_Schema {version:'v3'}), (n:UCKGMeta_Node {semantic:'AttackPattern'})
MERGE (s)-[:META_HAS_NODE]->(n);

MERGE (n:UCKGMeta_Node {semantic: 'D3FENDControl'})
SET   n.physical_label       = 'UcoexMITRED3FEND',
      n.purpose               = 'MITRE D3FEND defensive technique — countermeasure against ATT&CK techniques.',
      n.description           = 'Models defensive techniques from the MITRE D3FEND knowledge base. Each control has a label (ucoexMITRED3FEND_LABEL) and formal definition. Links to ATT&CK techniques via UCOEXHASMITREATTACK.',
      n.key_identifier        = 'ucoexMITRED3FEND_LABEL',
      n.key_identifier_example = 'Network Traffic Filtering',
      n.nl_template           = '{ID}, which is a D3FEND defensive control',
      n.triggers              = ['D3FEND', 'defensive technique', 'defense control', 'countermeasure', 'how to defend', 'network defense'];
MATCH (s:UCKGMeta_Schema {version:'v3'}), (n:UCKGMeta_Node {semantic:'D3FENDControl'})
MERGE (s)-[:META_HAS_NODE]->(n);

MERGE (n:UCKGMeta_Node {semantic: 'ObservedExample'})
SET   n.physical_label       = 'UcoexObservedExample',
      n.purpose               = 'Real-world exploitation event linking a CWE weakness to a CVE.',
      n.description           = 'Attached to CWE nodes via UCOHASOBSERVEDEXAMPLE and to CVE nodes via UCOEXEXAMPLEOBSERVEDIN. Creates the full evidence chain: CWE → ObservedExample → CVE.',
      n.key_identifier        = 'uri',
      n.key_identifier_example = 'http://uckg.org/observedexample/...',
      n.nl_template           = 'an observed exploitation example',
      n.triggers              = ['observed example', 'real world example', 'weakness in practice', 'CVE observed', 'exploitation example'];
MATCH (s:UCKGMeta_Schema {version:'v3'}), (n:UCKGMeta_Node {semantic:'ObservedExample'})
MERGE (s)-[:META_HAS_NODE]->(n);

MERGE (n:UCKGMeta_Node {semantic: 'CPE'})
SET   n.physical_label       = 'UcoexCPE',
      n.purpose               = 'CPE entry — standardised identifier for a specific software platform or product version.',
      n.description           = 'Linked to CVE nodes via UCOEXHASCPE (this CVE affects this CPE). The cpeName holds the full CPE URI (e.g. cpe:/a:apache:log4j:2.14.1). The titles property provides human-readable names.',
      n.key_identifier        = 'cpeName',
      n.key_identifier_example = 'cpe:/a:apache:log4j:2.14.1',
      n.nl_template           = '{ID}, which is a software platform',
      n.triggers              = ['affected platform', 'affected product', 'CPE', 'platform version', 'software version', 'product affected', 'vendor product'];
MATCH (s:UCKGMeta_Schema {version:'v3'}), (n:UCKGMeta_Node {semantic:'CPE'})
MERGE (s)-[:META_HAS_NODE]->(n);


// ── 3. Property metadata ──────────────────────────────────────────────────
// Format per entry:
//   MERGE property node  →  SET description + example  →  link to node

// ── CVE (10 properties) ──
MERGE (p:UCKGMeta_Property {semantic:'cveId', belongs_to:'CVE'})
SET p.physical='label', p.type='string', p.description='Canonical CVE identifier (CVE-YYYY-NNNNN). Primary lookup key.', p.example='CVE-2021-44228', p.query_pattern='MATCH (c:UcoCVE {label:\'CVE-2021-44228\'}) RETURN c';
MATCH (n:UCKGMeta_Node {semantic:'CVE'}),(p:UCKGMeta_Property {semantic:'cveId',belongs_to:'CVE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'baseSeverity', belongs_to:'CVE'})
SET p.physical='ucobaseSeverity', p.type='string', p.description='CVSS base severity: CRITICAL, HIGH, MEDIUM, or LOW.', p.example='CRITICAL', p.query_pattern='MATCH (c:UcoCVE {ucobaseSeverity:\'CRITICAL\'}) RETURN c';
MATCH (n:UCKGMeta_Node {semantic:'CVE'}),(p:UCKGMeta_Property {semantic:'baseSeverity',belongs_to:'CVE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'exploitabilityScore', belongs_to:'CVE'})
SET p.physical='ucoexploitabilityScore', p.type='string (numeric)', p.description='CVSS exploitability subscore (e.g. "3.9"). How easy the vulnerability is to exploit.', p.example='3.9', p.query_pattern='MATCH (c:UcoCVE) WHERE toFloat(c.ucoexploitabilityScore)>3.0 RETURN c';
MATCH (n:UCKGMeta_Node {semantic:'CVE'}),(p:UCKGMeta_Property {semantic:'exploitabilityScore',belongs_to:'CVE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'impactScore', belongs_to:'CVE'})
SET p.physical='ucoimpactScore', p.type='string (numeric)', p.description='CVSS impact subscore (e.g. "5.9"). Potential damage from a successful exploit.', p.example='5.9', p.query_pattern='MATCH (c:UcoCVE) WHERE toFloat(c.ucoimpactScore)>5.0 RETURN c';
MATCH (n:UCKGMeta_Node {semantic:'CVE'}),(p:UCKGMeta_Property {semantic:'impactScore',belongs_to:'CVE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'vectorString', belongs_to:'CVE'})
SET p.physical='ucovectorString', p.type='string', p.description='CVSS vector string encoding all base metric values.', p.example='AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H', p.query_pattern='MATCH (c:UcoCVE) WHERE c.ucovectorString CONTAINS \'AV:N\' RETURN c';
MATCH (n:UCKGMeta_Node {semantic:'CVE'}),(p:UCKGMeta_Property {semantic:'vectorString',belongs_to:'CVE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'vulnStatus', belongs_to:'CVE'})
SET p.physical='ucovulnStatus', p.type='string', p.description='NVD analysis status (Analyzed, Modified, Awaiting Analysis, Rejected).', p.example='Analyzed', p.query_pattern='MATCH (c:UcoCVE {ucovulnStatus:\'Analyzed\'}) RETURN c';
MATCH (n:UCKGMeta_Node {semantic:'CVE'}),(p:UCKGMeta_Property {semantic:'vulnStatus',belongs_to:'CVE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'evaluatorSolution', belongs_to:'CVE'})
SET p.physical='ucoevaluatorSolution', p.type='string', p.description='Free-text evaluator solution note by NVD analysts.', p.example='Update to version 2.15.0 or later.', p.query_pattern='MATCH (c:UcoCVE) WHERE c.ucoevaluatorSolution IS NOT NULL RETURN c.label, c.ucoevaluatorSolution';
MATCH (n:UCKGMeta_Node {semantic:'CVE'}),(p:UCKGMeta_Property {semantic:'evaluatorSolution',belongs_to:'CVE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'obtainAllPrivilege', belongs_to:'CVE'})
SET p.physical='ucoobtainAllPrivilege', p.type='string (boolean)', p.description='CVSS v2 flag: does exploitation yield full privilege escalation.', p.example='false', p.query_pattern='MATCH (c:UcoCVE {ucoobtainAllPrivilege:\'true\'}) RETURN c';
MATCH (n:UCKGMeta_Node {semantic:'CVE'}),(p:UCKGMeta_Property {semantic:'obtainAllPrivilege',belongs_to:'CVE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'userInteractionRequired', belongs_to:'CVE'})
SET p.physical='ucouserInteractionRequired', p.type='string (boolean)', p.description='CVSS v2 flag: is user interaction required for exploitation.', p.example='false', p.query_pattern='MATCH (c:UcoCVE {ucouserInteractionRequired:\'false\'}) RETURN c';
MATCH (n:UCKGMeta_Node {semantic:'CVE'}),(p:UCKGMeta_Property {semantic:'userInteractionRequired',belongs_to:'CVE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'uri', belongs_to:'CVE'})
SET p.physical='uri', p.type='string', p.description='Canonical RDF/ontology URI for this CVE node.', p.example='http://uckg.org/cve/CVE-2021-44228', p.query_pattern='MATCH (c:UcoCVE) WHERE c.uri CONTAINS \'CVE-2021-44228\' RETURN c';
MATCH (n:UCKGMeta_Node {semantic:'CVE'}),(p:UCKGMeta_Property {semantic:'uri',belongs_to:'CVE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

// ── Vulnerability (4 properties) ──
MERGE (p:UCKGMeta_Property {semantic:'publishedDate', belongs_to:'Vulnerability'})
SET p.physical='ucopublishedDateTime', p.type='datetime', p.description='Date/time the vulnerability was first published in NVD. Use for timeline queries.', p.example='2021-12-10T10:15:00', p.query_pattern='MATCH (v:UcoVulnerability) WHERE v.ucopublishedDateTime >= datetime(\'2021-01-01\') RETURN v';
MATCH (n:UCKGMeta_Node {semantic:'Vulnerability'}),(p:UCKGMeta_Property {semantic:'publishedDate',belongs_to:'Vulnerability'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'lastModifiedDate', belongs_to:'Vulnerability'})
SET p.physical='ucolastModifiedDateTime', p.type='datetime', p.description='Date/time the vulnerability record was last modified in NVD.', p.example='2022-01-15T12:00:00', p.query_pattern='MATCH (v:UcoVulnerability) WHERE v.ucolastModifiedDateTime >= datetime(\'2022-01-01\') RETURN v';
MATCH (n:UCKGMeta_Node {semantic:'Vulnerability'}),(p:UCKGMeta_Property {semantic:'lastModifiedDate',belongs_to:'Vulnerability'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'summary', belongs_to:'Vulnerability'})
SET p.physical='ucosummary', p.type='string', p.description='Free-text description of the vulnerability. Use for keyword/text search.', p.example='Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in...', p.query_pattern='MATCH (v:UcoVulnerability) WHERE toLower(v.ucosummary) CONTAINS \'remote code execution\' RETURN v';
MATCH (n:UCKGMeta_Node {semantic:'Vulnerability'}),(p:UCKGMeta_Property {semantic:'summary',belongs_to:'Vulnerability'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'uri', belongs_to:'Vulnerability'})
SET p.physical='uri', p.type='string', p.description='Canonical RDF/ontology URI for this Vulnerability node.', p.example='http://uckg.org/vulnerability/...', p.query_pattern='MATCH (v:UcoVulnerability) RETURN v.uri';
MATCH (n:UCKGMeta_Node {semantic:'Vulnerability'}),(p:UCKGMeta_Property {semantic:'uri',belongs_to:'Vulnerability'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

// ── Weakness / CWE (15 properties) ──
MERGE (p:UCKGMeta_Property {semantic:'cweId', belongs_to:'Weakness'})
SET p.physical='ucocweID', p.type='string', p.description='CWE identifier string (e.g. CWE-79). Primary lookup key.', p.example='CWE-79', p.query_pattern='MATCH (w:UcoCWE {ucocweID:\'CWE-79\'}) RETURN w';
MATCH (n:UCKGMeta_Node {semantic:'Weakness'}),(p:UCKGMeta_Property {semantic:'cweId',belongs_to:'Weakness'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'cweName', belongs_to:'Weakness'})
SET p.physical='ucocweName', p.type='string', p.description='Human-readable name of the weakness.', p.example='Improper Neutralization of Input During Web Page Generation (Cross-site Scripting)', p.query_pattern='MATCH (w:UcoCWE) WHERE toLower(w.ucocweName) CONTAINS \'injection\' RETURN w';
MATCH (n:UCKGMeta_Node {semantic:'Weakness'}),(p:UCKGMeta_Property {semantic:'cweName',belongs_to:'Weakness'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'summary', belongs_to:'Weakness'})
SET p.physical='ucocweSummary', p.type='string', p.description='Short summary of the weakness.', p.example='The software does not neutralize user-controllable input before placing it in output...', p.query_pattern='MATCH (w:UcoCWE) WHERE w.ucocweSummary IS NOT NULL RETURN w.ucocweID, w.ucocweSummary';
MATCH (n:UCKGMeta_Node {semantic:'Weakness'}),(p:UCKGMeta_Property {semantic:'summary',belongs_to:'Weakness'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'description', belongs_to:'Weakness'})
SET p.physical='ucodescription', p.type='string', p.description='Detailed description from the CWE specification.', p.example='The product receives input from an upstream component...', p.query_pattern='MATCH (w:UcoCWE) WHERE w.ucodescription IS NOT NULL RETURN w';
MATCH (n:UCKGMeta_Node {semantic:'Weakness'}),(p:UCKGMeta_Property {semantic:'description',belongs_to:'Weakness'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'abstraction', belongs_to:'Weakness'})
SET p.physical='ucoabstraction', p.type='string', p.description='CWE abstraction level: Pillar, Class, Base, or Variant.', p.example='Base', p.query_pattern='MATCH (w:UcoCWE {ucoabstraction:\'Base\'}) RETURN w';
MATCH (n:UCKGMeta_Node {semantic:'Weakness'}),(p:UCKGMeta_Property {semantic:'abstraction',belongs_to:'Weakness'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'likelihoodOfExploit', belongs_to:'Weakness'})
SET p.physical='ucolikelihoodOfExploit', p.type='string', p.description='Estimated exploitation likelihood: High, Medium, or Low.', p.example='High', p.query_pattern='MATCH (w:UcoCWE {ucolikelihoodOfExploit:\'High\'}) RETURN w';
MATCH (n:UCKGMeta_Node {semantic:'Weakness'}),(p:UCKGMeta_Property {semantic:'likelihoodOfExploit',belongs_to:'Weakness'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'status', belongs_to:'Weakness'})
SET p.physical='ucostatus', p.type='string', p.description='CWE entry status (Draft, Stable, Incomplete, Deprecated).', p.example='Stable', p.query_pattern='MATCH (w:UcoCWE {ucostatus:\'Stable\'}) RETURN w';
MATCH (n:UCKGMeta_Node {semantic:'Weakness'}),(p:UCKGMeta_Property {semantic:'status',belongs_to:'Weakness'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'applicablePlatform', belongs_to:'Weakness'})
SET p.physical='ucoapplicablePlatform', p.type='string', p.description='Platforms/languages where this weakness applies (e.g. Language Independent, C, PHP).', p.example='Language Independent', p.query_pattern='MATCH (w:UcoCWE) WHERE w.ucoapplicablePlatform CONTAINS \'PHP\' RETURN w';
MATCH (n:UCKGMeta_Node {semantic:'Weakness'}),(p:UCKGMeta_Property {semantic:'applicablePlatform',belongs_to:'Weakness'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'commonConsequences', belongs_to:'Weakness'})
SET p.physical='ucocommonConsequences', p.type='string', p.description='Common consequences if this weakness is exploited.', p.example='Confidentiality, Integrity — Read/Modify application data', p.query_pattern='MATCH (w:UcoCWE) WHERE w.ucocommonConsequences CONTAINS \'Confidentiality\' RETURN w';
MATCH (n:UCKGMeta_Node {semantic:'Weakness'}),(p:UCKGMeta_Property {semantic:'commonConsequences',belongs_to:'Weakness'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'potentialMitigations', belongs_to:'Weakness'})
SET p.physical='ucopotentialMitigations', p.type='string', p.description='Mitigations recommended by the CWE specification.', p.example='Use a vetted library or framework...', p.query_pattern='MATCH (w:UcoCWE) WHERE w.ucopotentialMitigations IS NOT NULL RETURN w.ucocweID, w.ucopotentialMitigations';
MATCH (n:UCKGMeta_Node {semantic:'Weakness'}),(p:UCKGMeta_Property {semantic:'potentialMitigations',belongs_to:'Weakness'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'detectionMethods', belongs_to:'Weakness'})
SET p.physical='ucodetectionMethods', p.type='string', p.description='Recommended methods for detecting this weakness (Static Analysis, Fuzzing, etc.).', p.example='Static Analysis, Automated Testing', p.query_pattern='MATCH (w:UcoCWE) WHERE w.ucodetectionMethods CONTAINS \'Static Analysis\' RETURN w';
MATCH (n:UCKGMeta_Node {semantic:'Weakness'}),(p:UCKGMeta_Property {semantic:'detectionMethods',belongs_to:'Weakness'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'extendedSummary', belongs_to:'Weakness'})
SET p.physical='ucocweExtendedSummary', p.type='string', p.description='Extended summary providing additional context beyond the basic summary.', p.example='...', p.query_pattern='MATCH (w:UcoCWE) WHERE w.ucocweExtendedSummary IS NOT NULL RETURN w';
MATCH (n:UCKGMeta_Node {semantic:'Weakness'}),(p:UCKGMeta_Property {semantic:'extendedSummary',belongs_to:'Weakness'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'modesOfIntroduction', belongs_to:'Weakness'})
SET p.physical='ucomodesOfIntroduction', p.type='string', p.description='When/how this weakness is typically introduced (Implementation, Design, Architecture).', p.example='Implementation', p.query_pattern='MATCH (w:UcoCWE) WHERE w.ucomodesOfIntroduction CONTAINS \'Implementation\' RETURN w';
MATCH (n:UCKGMeta_Node {semantic:'Weakness'}),(p:UCKGMeta_Property {semantic:'modesOfIntroduction',belongs_to:'Weakness'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'structure', belongs_to:'Weakness'})
SET p.physical='ucostructure', p.type='string', p.description='CWE structural nature: Simple, Composite, or Chain.', p.example='Simple', p.query_pattern='MATCH (w:UcoCWE {ucostructure:\'Composite\'}) RETURN w';
MATCH (n:UCKGMeta_Node {semantic:'Weakness'}),(p:UCKGMeta_Property {semantic:'structure',belongs_to:'Weakness'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'uri', belongs_to:'Weakness'})
SET p.physical='uri', p.type='string', p.description='Canonical RDF/ontology URI for this CWE node.', p.example='http://uckg.org/cwe/CWE-79', p.query_pattern='MATCH (w:UcoCWE) WHERE w.uri IS NOT NULL RETURN w.uri';
MATCH (n:UCKGMeta_Node {semantic:'Weakness'}),(p:UCKGMeta_Property {semantic:'uri',belongs_to:'Weakness'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

// ── ExploitTarget (1 property) ──
MERGE (p:UCKGMeta_Property {semantic:'uri', belongs_to:'ExploitTarget'})
SET p.physical='uri', p.type='string', p.description='Canonical RDF/ontology URI — the only property on ExploitTarget nodes.', p.example='http://uckg.org/exploittarget/...', p.query_pattern='MATCH (et:UcoExploitTarget) RETURN et.uri LIMIT 5';
MATCH (n:UCKGMeta_Node {semantic:'ExploitTarget'}),(p:UCKGMeta_Property {semantic:'uri',belongs_to:'ExploitTarget'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

// ── Campaign / Group / Technique / Tactic / Software / Mitigation (5 each) ──
// (name, description, domain, url, uri — repeated for each ATT&CK entity type)
MERGE (p:UCKGMeta_Property {semantic:'name', belongs_to:'Campaign'}) SET p.physical='ucoexNAME', p.type='string', p.description='Campaign name (e.g. Operation Wocao). Primary lookup key.', p.example='Operation Wocao', p.query_pattern='MATCH (c:UcoexCAMPAIGNS {ucoexNAME:\'Operation Wocao\'}) RETURN c';
MATCH (n:UCKGMeta_Node {semantic:'Campaign'}),(p:UCKGMeta_Property {semantic:'name',belongs_to:'Campaign'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'description', belongs_to:'Campaign'}) SET p.physical='ucoexDESCRIPTION', p.type='string', p.description='Detailed campaign description including goals, attribution, and timeline.', p.example='Operation Wocao was a cyber espionage campaign...', p.query_pattern='MATCH (c:UcoexCAMPAIGNS) WHERE toLower(c.ucoexDESCRIPTION) CONTAINS \'espionage\' RETURN c';
MATCH (n:UCKGMeta_Node {semantic:'Campaign'}),(p:UCKGMeta_Property {semantic:'description',belongs_to:'Campaign'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'domain', belongs_to:'Campaign'}) SET p.physical='ucoexDOMAIN', p.type='string', p.description='ATT&CK domain (enterprise-attack, ics-attack, mobile-attack).', p.example='enterprise-attack', p.query_pattern='MATCH (c:UcoexCAMPAIGNS {ucoexDOMAIN:\'enterprise-attack\'}) RETURN c';
MATCH (n:UCKGMeta_Node {semantic:'Campaign'}),(p:UCKGMeta_Property {semantic:'domain',belongs_to:'Campaign'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'url', belongs_to:'Campaign'}) SET p.physical='ucoexURL', p.type='string', p.description='Reference URL on the MITRE ATT&CK website.', p.example='https://attack.mitre.org/campaigns/C0014/', p.query_pattern='MATCH (c:UcoexCAMPAIGNS) WHERE c.ucoexURL IS NOT NULL RETURN c.ucoexNAME, c.ucoexURL';
MATCH (n:UCKGMeta_Node {semantic:'Campaign'}),(p:UCKGMeta_Property {semantic:'url',belongs_to:'Campaign'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'uri', belongs_to:'Campaign'}) SET p.physical='uri', p.type='string', p.description='Canonical RDF/ontology URI for this campaign node.', p.example='http://uckg.org/campaign/...', p.query_pattern='MATCH (c:UcoexCAMPAIGNS) WHERE c.uri IS NOT NULL RETURN c';
MATCH (n:UCKGMeta_Node {semantic:'Campaign'}),(p:UCKGMeta_Property {semantic:'uri',belongs_to:'Campaign'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'name', belongs_to:'Group'}) SET p.physical='ucoexNAME', p.type='string', p.description='Threat group name (e.g. APT29, Lazarus Group). Primary lookup key.', p.example='APT29', p.query_pattern='MATCH (g:UcoexGROUPS {ucoexNAME:\'APT29\'}) RETURN g';
MATCH (n:UCKGMeta_Node {semantic:'Group'}),(p:UCKGMeta_Property {semantic:'name',belongs_to:'Group'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'description', belongs_to:'Group'}) SET p.physical='ucoexDESCRIPTION', p.type='string', p.description='Group description including origin, motivation, and known activities.', p.example='APT29 is attributed to the Russian Foreign Intelligence Service...', p.query_pattern='MATCH (g:UcoexGROUPS) WHERE toLower(g.ucoexDESCRIPTION) CONTAINS \'russia\' RETURN g';
MATCH (n:UCKGMeta_Node {semantic:'Group'}),(p:UCKGMeta_Property {semantic:'description',belongs_to:'Group'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'domain', belongs_to:'Group'}) SET p.physical='ucoexDOMAIN', p.type='string', p.description='ATT&CK domain.', p.example='enterprise-attack', p.query_pattern='MATCH (g:UcoexGROUPS {ucoexDOMAIN:\'enterprise-attack\'}) RETURN g';
MATCH (n:UCKGMeta_Node {semantic:'Group'}),(p:UCKGMeta_Property {semantic:'domain',belongs_to:'Group'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'url', belongs_to:'Group'}) SET p.physical='ucoexURL', p.type='string', p.description='Reference URL on MITRE ATT&CK.', p.example='https://attack.mitre.org/groups/G0016/', p.query_pattern='MATCH (g:UcoexGROUPS) WHERE g.ucoexURL IS NOT NULL RETURN g.ucoexNAME, g.ucoexURL';
MATCH (n:UCKGMeta_Node {semantic:'Group'}),(p:UCKGMeta_Property {semantic:'url',belongs_to:'Group'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'uri', belongs_to:'Group'}) SET p.physical='uri', p.type='string', p.description='Canonical RDF/ontology URI for this group node.', p.example='http://uckg.org/group/...', p.query_pattern='MATCH (g:UcoexGROUPS) WHERE g.uri IS NOT NULL RETURN g';
MATCH (n:UCKGMeta_Node {semantic:'Group'}),(p:UCKGMeta_Property {semantic:'uri',belongs_to:'Group'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'name', belongs_to:'Technique'}) SET p.physical='ucoexNAME', p.type='string', p.description='Technique name as in ATT&CK (e.g. Phishing, Valid Accounts). Primary lookup key.', p.example='Phishing', p.query_pattern='MATCH (t:UcoexMITREATTACK) WHERE toLower(t.ucoexNAME) CONTAINS \'phishing\' RETURN t';
MATCH (n:UCKGMeta_Node {semantic:'Technique'}),(p:UCKGMeta_Property {semantic:'name',belongs_to:'Technique'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'description', belongs_to:'Technique'}) SET p.physical='ucoexDESCRIPTION', p.type='string', p.description='Detailed description of the adversary technique from ATT&CK.', p.example='Adversaries may send phishing messages to gain access to victim systems...', p.query_pattern='MATCH (t:UcoexMITREATTACK) WHERE toLower(t.ucoexDESCRIPTION) CONTAINS \'credential\' RETURN t';
MATCH (n:UCKGMeta_Node {semantic:'Technique'}),(p:UCKGMeta_Property {semantic:'description',belongs_to:'Technique'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'domain', belongs_to:'Technique'}) SET p.physical='ucoexDOMAIN', p.type='string', p.description='ATT&CK domain this technique belongs to.', p.example='enterprise-attack', p.query_pattern='MATCH (t:UcoexMITREATTACK {ucoexDOMAIN:\'enterprise-attack\'}) RETURN t';
MATCH (n:UCKGMeta_Node {semantic:'Technique'}),(p:UCKGMeta_Property {semantic:'domain',belongs_to:'Technique'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'url', belongs_to:'Technique'}) SET p.physical='ucoexURL', p.type='string', p.description='Reference URL on MITRE ATT&CK.', p.example='https://attack.mitre.org/techniques/T1566/', p.query_pattern='MATCH (t:UcoexMITREATTACK) WHERE t.ucoexURL IS NOT NULL RETURN t.ucoexNAME, t.ucoexURL';
MATCH (n:UCKGMeta_Node {semantic:'Technique'}),(p:UCKGMeta_Property {semantic:'url',belongs_to:'Technique'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'uri', belongs_to:'Technique'}) SET p.physical='uri', p.type='string', p.description='Canonical RDF/ontology URI for this technique node.', p.example='http://uckg.org/technique/...', p.query_pattern='MATCH (t:UcoexMITREATTACK) WHERE t.uri IS NOT NULL RETURN t';
MATCH (n:UCKGMeta_Node {semantic:'Technique'}),(p:UCKGMeta_Property {semantic:'uri',belongs_to:'Technique'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'name', belongs_to:'Tactic'}) SET p.physical='ucoexNAME', p.type='string', p.description='Tactic name (Initial Access, Persistence, Lateral Movement, etc.). Primary lookup key.', p.example='Initial Access', p.query_pattern='MATCH (tac:UcoexTACTICS {ucoexNAME:\'Initial Access\'}) RETURN tac';
MATCH (n:UCKGMeta_Node {semantic:'Tactic'}),(p:UCKGMeta_Property {semantic:'name',belongs_to:'Tactic'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'description', belongs_to:'Tactic'}) SET p.physical='ucoexDESCRIPTION', p.type='string', p.description='Description of the tactic from MITRE ATT&CK.', p.example='The adversary is trying to get into your network...', p.query_pattern='MATCH (tac:UcoexTACTICS) WHERE tac.ucoexDESCRIPTION IS NOT NULL RETURN tac';
MATCH (n:UCKGMeta_Node {semantic:'Tactic'}),(p:UCKGMeta_Property {semantic:'description',belongs_to:'Tactic'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'domain', belongs_to:'Tactic'}) SET p.physical='ucoexDOMAIN', p.type='string', p.description='ATT&CK domain (enterprise-attack, ics-attack, mobile-attack).', p.example='enterprise-attack', p.query_pattern='MATCH (tac:UcoexTACTICS {ucoexDOMAIN:\'enterprise-attack\'}) RETURN tac';
MATCH (n:UCKGMeta_Node {semantic:'Tactic'}),(p:UCKGMeta_Property {semantic:'domain',belongs_to:'Tactic'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'url', belongs_to:'Tactic'}) SET p.physical='ucoexURL', p.type='string', p.description='Reference URL on MITRE ATT&CK.', p.example='https://attack.mitre.org/tactics/TA0001/', p.query_pattern='MATCH (tac:UcoexTACTICS) WHERE tac.ucoexURL IS NOT NULL RETURN tac.ucoexNAME, tac.ucoexURL';
MATCH (n:UCKGMeta_Node {semantic:'Tactic'}),(p:UCKGMeta_Property {semantic:'url',belongs_to:'Tactic'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'uri', belongs_to:'Tactic'}) SET p.physical='uri', p.type='string', p.description='Canonical RDF/ontology URI for this tactic node.', p.example='http://uckg.org/tactic/...', p.query_pattern='MATCH (tac:UcoexTACTICS) WHERE tac.uri IS NOT NULL RETURN tac';
MATCH (n:UCKGMeta_Node {semantic:'Tactic'}),(p:UCKGMeta_Property {semantic:'uri',belongs_to:'Tactic'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'name', belongs_to:'Software'}) SET p.physical='ucoexNAME', p.type='string', p.description='Software name (Mimikatz, Emotet, Cobalt Strike). Primary lookup key.', p.example='Mimikatz', p.query_pattern='MATCH (s:UcoexSOFTWARE {ucoexNAME:\'Mimikatz\'}) RETURN s';
MATCH (n:UCKGMeta_Node {semantic:'Software'}),(p:UCKGMeta_Property {semantic:'name',belongs_to:'Software'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'description', belongs_to:'Software'}) SET p.physical='ucoexDESCRIPTION', p.type='string', p.description='Software description including capabilities and typical use.', p.example='Mimikatz is a credential dumper capable of obtaining plaintext Windows account logins...', p.query_pattern='MATCH (s:UcoexSOFTWARE) WHERE toLower(s.ucoexDESCRIPTION) CONTAINS \'credential\' RETURN s';
MATCH (n:UCKGMeta_Node {semantic:'Software'}),(p:UCKGMeta_Property {semantic:'description',belongs_to:'Software'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'domain', belongs_to:'Software'}) SET p.physical='ucoexDOMAIN', p.type='string', p.description='ATT&CK domain this software belongs to.', p.example='enterprise-attack', p.query_pattern='MATCH (s:UcoexSOFTWARE {ucoexDOMAIN:\'enterprise-attack\'}) RETURN s';
MATCH (n:UCKGMeta_Node {semantic:'Software'}),(p:UCKGMeta_Property {semantic:'domain',belongs_to:'Software'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'url', belongs_to:'Software'}) SET p.physical='ucoexURL', p.type='string', p.description='Reference URL on MITRE ATT&CK.', p.example='https://attack.mitre.org/software/S0002/', p.query_pattern='MATCH (s:UcoexSOFTWARE) WHERE s.ucoexURL IS NOT NULL RETURN s.ucoexNAME, s.ucoexURL';
MATCH (n:UCKGMeta_Node {semantic:'Software'}),(p:UCKGMeta_Property {semantic:'url',belongs_to:'Software'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'uri', belongs_to:'Software'}) SET p.physical='uri', p.type='string', p.description='Canonical RDF/ontology URI for this software node.', p.example='http://uckg.org/software/...', p.query_pattern='MATCH (s:UcoexSOFTWARE) WHERE s.uri IS NOT NULL RETURN s';
MATCH (n:UCKGMeta_Node {semantic:'Software'}),(p:UCKGMeta_Property {semantic:'uri',belongs_to:'Software'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

MERGE (p:UCKGMeta_Property {semantic:'name', belongs_to:'Mitigation'}) SET p.physical='ucoexNAME', p.type='string', p.description='Mitigation name from ATT&CK (e.g. Multi-factor Authentication). Primary lookup key.', p.example='Multi-factor Authentication', p.query_pattern='MATCH (m:UcoexMITIGATIONS {ucoexNAME:\'Multi-factor Authentication\'}) RETURN m';
MATCH (n:UCKGMeta_Node {semantic:'Mitigation'}),(p:UCKGMeta_Property {semantic:'name',belongs_to:'Mitigation'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'description', belongs_to:'Mitigation'}) SET p.physical='ucoexDESCRIPTION', p.type='string', p.description='Description of the mitigation and how it reduces risk.', p.example='Use multi-factor authentication for user and privileged accounts...', p.query_pattern='MATCH (m:UcoexMITIGATIONS) WHERE m.ucoexDESCRIPTION IS NOT NULL RETURN m.ucoexNAME, m.ucoexDESCRIPTION';
MATCH (n:UCKGMeta_Node {semantic:'Mitigation'}),(p:UCKGMeta_Property {semantic:'description',belongs_to:'Mitigation'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'domain', belongs_to:'Mitigation'}) SET p.physical='ucoexDOMAIN', p.type='string', p.description='ATT&CK domain.', p.example='enterprise-attack', p.query_pattern='MATCH (m:UcoexMITIGATIONS {ucoexDOMAIN:\'enterprise-attack\'}) RETURN m';
MATCH (n:UCKGMeta_Node {semantic:'Mitigation'}),(p:UCKGMeta_Property {semantic:'domain',belongs_to:'Mitigation'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'url', belongs_to:'Mitigation'}) SET p.physical='ucoexURL', p.type='string', p.description='Reference URL on MITRE ATT&CK.', p.example='https://attack.mitre.org/mitigations/M1032/', p.query_pattern='MATCH (m:UcoexMITIGATIONS) WHERE m.ucoexURL IS NOT NULL RETURN m.ucoexNAME, m.ucoexURL';
MATCH (n:UCKGMeta_Node {semantic:'Mitigation'}),(p:UCKGMeta_Property {semantic:'url',belongs_to:'Mitigation'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'uri', belongs_to:'Mitigation'}) SET p.physical='uri', p.type='string', p.description='Canonical RDF/ontology URI for this mitigation node.', p.example='http://uckg.org/mitigation/...', p.query_pattern='MATCH (m:UcoexMITIGATIONS) WHERE m.uri IS NOT NULL RETURN m';
MATCH (n:UCKGMeta_Node {semantic:'Mitigation'}),(p:UCKGMeta_Property {semantic:'uri',belongs_to:'Mitigation'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

// ── AttackPattern / CAPEC (10 properties) ──
MERGE (p:UCKGMeta_Property {semantic:'capecId', belongs_to:'AttackPattern'}) SET p.physical='ucoexCAPEC_id', p.type='string', p.description='CAPEC identifier (e.g. CAPEC-66). Primary lookup key.', p.example='CAPEC-66', p.query_pattern='MATCH (ap:UcoexCAPEC {ucoexCAPEC_id:\'CAPEC-66\'}) RETURN ap';
MATCH (n:UCKGMeta_Node {semantic:'AttackPattern'}),(p:UCKGMeta_Property {semantic:'capecId',belongs_to:'AttackPattern'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'capecName', belongs_to:'AttackPattern'}) SET p.physical='ucoexCAPEC_name', p.type='string', p.description='Human-readable name of the attack pattern.', p.example='SQL Injection', p.query_pattern='MATCH (ap:UcoexCAPEC) WHERE toLower(ap.ucoexCAPEC_name) CONTAINS \'injection\' RETURN ap';
MATCH (n:UCKGMeta_Node {semantic:'AttackPattern'}),(p:UCKGMeta_Property {semantic:'capecName',belongs_to:'AttackPattern'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'description', belongs_to:'AttackPattern'}) SET p.physical='ucoexDescription', p.type='string', p.description='Detailed attack pattern description.', p.example='This attack exploits improper handling of SQL input...', p.query_pattern='MATCH (ap:UcoexCAPEC) WHERE ap.ucoexDescription IS NOT NULL RETURN ap.ucoexCAPEC_id, ap.ucoexDescription';
MATCH (n:UCKGMeta_Node {semantic:'AttackPattern'}),(p:UCKGMeta_Property {semantic:'description',belongs_to:'AttackPattern'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'severity', belongs_to:'AttackPattern'}) SET p.physical='ucoexSeverity', p.type='string', p.description='Severity rating: High, Medium, or Low.', p.example='High', p.query_pattern='MATCH (ap:UcoexCAPEC {ucoexSeverity:\'High\'}) RETURN ap';
MATCH (n:UCKGMeta_Node {semantic:'AttackPattern'}),(p:UCKGMeta_Property {semantic:'severity',belongs_to:'AttackPattern'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'likelihood', belongs_to:'AttackPattern'}) SET p.physical='ucoexLikelihood', p.type='string', p.description='Likelihood the attack pattern will be used: High, Medium, or Low.', p.example='High', p.query_pattern='MATCH (ap:UcoexCAPEC {ucoexLikelihood:\'High\'}) RETURN ap';
MATCH (n:UCKGMeta_Node {semantic:'AttackPattern'}),(p:UCKGMeta_Property {semantic:'likelihood',belongs_to:'AttackPattern'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'abstraction', belongs_to:'AttackPattern'}) SET p.physical='ucoexAbstraction', p.type='string', p.description='CAPEC abstraction level: Meta, Standard, or Detailed.', p.example='Standard', p.query_pattern='MATCH (ap:UcoexCAPEC {ucoexAbstraction:\'Standard\'}) RETURN ap';
MATCH (n:UCKGMeta_Node {semantic:'AttackPattern'}),(p:UCKGMeta_Property {semantic:'abstraction',belongs_to:'AttackPattern'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'consequences', belongs_to:'AttackPattern'}) SET p.physical='ucoexConsequences', p.type='list<string>', p.description='Potential consequences if this attack pattern is executed.', p.example='[\'Data exfiltration\', \'Authentication bypass\']', p.query_pattern='MATCH (ap:UcoexCAPEC) WHERE any(c IN ap.ucoexConsequences WHERE toLower(c) CONTAINS \'bypass\') RETURN ap';
MATCH (n:UCKGMeta_Node {semantic:'AttackPattern'}),(p:UCKGMeta_Property {semantic:'consequences',belongs_to:'AttackPattern'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'prerequisites', belongs_to:'AttackPattern'}) SET p.physical='ucoexPrerequisites', p.type='list<string>', p.description='Prerequisites needed to execute this attack pattern.', p.example='[\'Network access\', \'Vulnerable input field\']', p.query_pattern='MATCH (ap:UcoexCAPEC) WHERE ap.ucoexPrerequisites IS NOT NULL RETURN ap.ucoexCAPEC_id, ap.ucoexPrerequisites';
MATCH (n:UCKGMeta_Node {semantic:'AttackPattern'}),(p:UCKGMeta_Property {semantic:'prerequisites',belongs_to:'AttackPattern'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'mitigations', belongs_to:'AttackPattern'}) SET p.physical='ucoexMitigations', p.type='list<string>', p.description='Recommended mitigations from the CAPEC specification.', p.example='[\'Input validation\', \'Prepared statements\']', p.query_pattern='MATCH (ap:UcoexCAPEC) WHERE ap.ucoexMitigations IS NOT NULL RETURN ap.ucoexCAPEC_id, ap.ucoexMitigations';
MATCH (n:UCKGMeta_Node {semantic:'AttackPattern'}),(p:UCKGMeta_Property {semantic:'mitigations',belongs_to:'AttackPattern'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'uri', belongs_to:'AttackPattern'}) SET p.physical='uri', p.type='string', p.description='Canonical RDF/ontology URI for this CAPEC node.', p.example='http://uckg.org/capec/CAPEC-66', p.query_pattern='MATCH (ap:UcoexCAPEC) WHERE ap.uri IS NOT NULL RETURN ap.uri';
MATCH (n:UCKGMeta_Node {semantic:'AttackPattern'}),(p:UCKGMeta_Property {semantic:'uri',belongs_to:'AttackPattern'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

// ── D3FENDControl (3 properties) ──
MERGE (p:UCKGMeta_Property {semantic:'label', belongs_to:'D3FENDControl'}) SET p.physical='ucoexMITRED3FEND_LABEL', p.type='string', p.description='D3FEND defensive technique label/name. Primary lookup key.', p.example='Network Traffic Filtering', p.query_pattern='MATCH (d:UcoexMITRED3FEND {ucoexMITRED3FEND_LABEL:\'Network Traffic Filtering\'}) RETURN d';
MATCH (n:UCKGMeta_Node {semantic:'D3FENDControl'}),(p:UCKGMeta_Property {semantic:'label',belongs_to:'D3FENDControl'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'definition', belongs_to:'D3FENDControl'}) SET p.physical='ucoexMITRED3FEND_DEFINITION', p.type='string', p.description='Formal definition of the D3FEND defensive technique.', p.example='Restricting network traffic by filtering based on criteria such as IP address, port, or protocol...', p.query_pattern='MATCH (d:UcoexMITRED3FEND) WHERE d.ucoexMITRED3FEND_DEFINITION IS NOT NULL RETURN d.ucoexMITRED3FEND_LABEL, d.ucoexMITRED3FEND_DEFINITION';
MATCH (n:UCKGMeta_Node {semantic:'D3FENDControl'}),(p:UCKGMeta_Property {semantic:'definition',belongs_to:'D3FENDControl'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'uri', belongs_to:'D3FENDControl'}) SET p.physical='uri', p.type='string', p.description='Canonical RDF/ontology URI for this D3FEND control node.', p.example='http://uckg.org/d3fend/...', p.query_pattern='MATCH (d:UcoexMITRED3FEND) WHERE d.uri IS NOT NULL RETURN d';
MATCH (n:UCKGMeta_Node {semantic:'D3FENDControl'}),(p:UCKGMeta_Property {semantic:'uri',belongs_to:'D3FENDControl'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

// ── ObservedExample (2 properties) ──
MERGE (p:UCKGMeta_Property {semantic:'description', belongs_to:'ObservedExample'}) SET p.physical='ucoexDESCRIPTION', p.type='string', p.description='Description of the real-world exploitation event.', p.example='XSS in the admin interface of Product X allows remote attackers to inject arbitrary web script...', p.query_pattern='MATCH (oe:UcoexObservedExample) WHERE toLower(oe.ucoexDESCRIPTION) CONTAINS \'xss\' RETURN oe';
MATCH (n:UCKGMeta_Node {semantic:'ObservedExample'}),(p:UCKGMeta_Property {semantic:'description',belongs_to:'ObservedExample'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'uri', belongs_to:'ObservedExample'}) SET p.physical='uri', p.type='string', p.description='Canonical RDF/ontology URI for this observed example node.', p.example='http://uckg.org/observedexample/...', p.query_pattern='MATCH (oe:UcoexObservedExample) WHERE oe.uri IS NOT NULL RETURN oe.uri';
MATCH (n:UCKGMeta_Node {semantic:'ObservedExample'}),(p:UCKGMeta_Property {semantic:'uri',belongs_to:'ObservedExample'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);

// ── CPE (6 properties) ──
MERGE (p:UCKGMeta_Property {semantic:'cpeName', belongs_to:'CPE'}) SET p.physical='cpeName', p.type='string', p.description='Full CPE URI string (vendor, product, version encoded). Primary lookup key.', p.example='cpe:/a:apache:log4j:2.14.1', p.query_pattern='MATCH (cpe:UcoexCPE) WHERE cpe.cpeName CONTAINS \'apache:log4j\' RETURN cpe';
MATCH (n:UCKGMeta_Node {semantic:'CPE'}),(p:UCKGMeta_Property {semantic:'cpeName',belongs_to:'CPE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'cpeNameId', belongs_to:'CPE'}) SET p.physical='cpeNameId', p.type='string', p.description='Internal CPE dictionary identifier UUID.', p.example='3fa85f64-5717-4562-b3fc-2c963f66afa6', p.query_pattern='MATCH (cpe:UcoexCPE) WHERE cpe.cpeNameId IS NOT NULL RETURN cpe.cpeName, cpe.cpeNameId';
MATCH (n:UCKGMeta_Node {semantic:'CPE'}),(p:UCKGMeta_Property {semantic:'cpeNameId',belongs_to:'CPE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'titles', belongs_to:'CPE'}) SET p.physical='titles', p.type='string', p.description='Human-readable title(s) for this CPE entry (e.g. Apache Log4j 2.14.1).', p.example='Apache Log4j 2.14.1', p.query_pattern='MATCH (cpe:UcoexCPE) WHERE toLower(cpe.titles) CONTAINS \'apache\' RETURN cpe';
MATCH (n:UCKGMeta_Node {semantic:'CPE'}),(p:UCKGMeta_Property {semantic:'titles',belongs_to:'CPE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'lastModified', belongs_to:'CPE'}) SET p.physical='lastModified', p.type='datetime', p.description='Last modification timestamp of this CPE entry in the NVD dictionary.', p.example='2022-03-15T10:00:00', p.query_pattern='MATCH (cpe:UcoexCPE) WHERE cpe.lastModified IS NOT NULL RETURN cpe.cpeName, cpe.lastModified';
MATCH (n:UCKGMeta_Node {semantic:'CPE'}),(p:UCKGMeta_Property {semantic:'lastModified',belongs_to:'CPE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'dictionaryFound', belongs_to:'CPE'}) SET p.physical='dictionary_found', p.type='boolean', p.description='Flag: was this CPE found in the NVD CPE dictionary.', p.example='true', p.query_pattern='MATCH (cpe:UcoexCPE {dictionary_found:true}) RETURN cpe';
MATCH (n:UCKGMeta_Node {semantic:'CPE'}),(p:UCKGMeta_Property {semantic:'dictionaryFound',belongs_to:'CPE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);
MERGE (p:UCKGMeta_Property {semantic:'uri', belongs_to:'CPE'}) SET p.physical='uri', p.type='string', p.description='Canonical RDF/ontology URI for this CPE node.', p.example='http://uckg.org/cpe/...', p.query_pattern='MATCH (cpe:UcoexCPE) WHERE cpe.uri IS NOT NULL RETURN cpe';
MATCH (n:UCKGMeta_Node {semantic:'CPE'}),(p:UCKGMeta_Property {semantic:'uri',belongs_to:'CPE'}) MERGE (n)-[:META_HAS_PROPERTY]->(p);


// ── 4. Relationship type metadata ─────────────────────────────────────────
// Each entry specifies:
//   semantic             — human name for the relationship
//   physical_rel         — actual Neo4j relationship type
//   source_node_semantic — semantic type of the source node
//   source_node_physical — physical label of the source node
//   target_node_semantic — semantic type of the target node
//   target_node_physical — physical label of the target node
//   nl_template          — sentence template for NL generation
//                          variables: {SRC_ID}, {SRC_LABEL}, {TGT_ID}, {TGT_LABEL}

MERGE (r:UCKGMeta_Relationship {semantic:'hasCPE'})
SET   r.physical_rel          = 'UCOEXHASCPE',
      r.source_node_semantic  = 'CVE',
      r.source_node_physical  = 'UcoCVE',
      r.target_node_semantic  = 'CPE',
      r.target_node_physical  = 'UcoexCPE',
      r.description           = 'Connects a CVE to the specific platform or product versions it affects. Primary relationship for "which platforms/products are affected by this CVE" queries.',
      r.nl_template           = '{SRC_ID}, which is a vulnerability, has a CPE, {TGT_ID}, which is a software platform titled "{TGT_LABEL}".',
      r.cypher_pattern        = 'MATCH (c:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE)',
      r.triggers              = ['affected platform', 'which CPE', 'platforms affected by CVE', 'products affected by vulnerability', 'vendor version affected'],
      r.example_query         = 'MATCH (c:UcoCVE {label:\'CVE-2021-44228\'})-[:UCOEXHASCPE]->(cpe:UcoexCPE) RETURN cpe.cpeName';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'hasCPE'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);

MERGE (r:UCKGMeta_Relationship {semantic:'hasObservedExample'})
SET   r.physical_rel          = 'UCOHASOBSERVEDEXAMPLE',
      r.source_node_semantic  = 'Weakness',
      r.source_node_physical  = 'UcoCWE',
      r.target_node_semantic  = 'ObservedExample',
      r.target_node_physical  = 'UcoexObservedExample',
      r.description           = 'Connects a CWE weakness to real-world observed examples of it being exploited.',
      r.nl_template           = '{SRC_ID}, which is a software weakness, has an observed real-world exploitation example: {TGT_LABEL}.',
      r.cypher_pattern        = 'MATCH (w:UcoCWE)-[:UCOHASOBSERVEDEXAMPLE]->(oe:UcoexObservedExample)',
      r.triggers              = ['real world examples of weakness', 'where has CWE been exploited', 'observed examples', 'historical exploitation of weakness'],
      r.example_query         = 'MATCH (w:UcoCWE {ucocweID:\'CWE-79\'})-[:UCOHASOBSERVEDEXAMPLE]->(oe:UcoexObservedExample) RETURN oe.ucoexDESCRIPTION LIMIT 5';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'hasObservedExample'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);

MERGE (r:UCKGMeta_Relationship {semantic:'hasVulnerability'})
SET   r.physical_rel          = 'UCOHASVULNERABILITY',
      r.source_node_semantic  = 'ExploitTarget',
      r.source_node_physical  = 'UcoExploitTarget',
      r.target_node_semantic  = 'Vulnerability',
      r.target_node_physical  = 'UcoVulnerability',
      r.description           = 'Connects an ExploitTarget pivot node to its associated Vulnerability. Required to traverse from weaknesses to vulnerability records.',
      r.nl_template           = 'Exploit target {SRC_ID} is associated with vulnerability {TGT_ID}.',
      r.cypher_pattern        = 'MATCH (et:UcoExploitTarget)-[:UCOHASVULNERABILITY]->(v:UcoVulnerability)',
      r.triggers              = ['vulnerability from weakness', 'exploit target linked vulnerability', 'CWE causes vulnerability'],
      r.example_query         = 'MATCH (w:UcoCWE {ucocweID:\'CWE-89\'})<-[:UCOHASWEAKNESS]-(et:UcoExploitTarget)-[:UCOHASVULNERABILITY]->(v:UcoVulnerability)-[:UCOHASCVE_ID]->(c:UcoCVE) RETURN c.label LIMIT 10';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'hasVulnerability'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);

MERGE (r:UCKGMeta_Relationship {semantic:'hasWeakness'})
SET   r.physical_rel          = 'UCOHASWEAKNESS',
      r.source_node_semantic  = 'ExploitTarget',
      r.source_node_physical  = 'UcoExploitTarget',
      r.target_node_semantic  = 'Weakness',
      r.target_node_physical  = 'UcoCWE',
      r.description           = 'Connects an ExploitTarget pivot node to the underlying CWE weakness. Used to find which weakness class underlies a given vulnerability.',
      r.nl_template           = 'Exploit target {SRC_ID} is caused by weakness {TGT_ID}, which is a {TGT_LABEL}.',
      r.cypher_pattern        = 'MATCH (et:UcoExploitTarget)-[:UCOHASWEAKNESS]->(w:UcoCWE)',
      r.triggers              = ['weakness causing vulnerability', 'CWE for this CVE', 'underlying weakness', 'root cause weakness'],
      r.example_query         = 'MATCH (v:UcoVulnerability)<-[:UCOHASVULNERABILITY]-(et:UcoExploitTarget)-[:UCOHASWEAKNESS]->(w:UcoCWE) MATCH (v)-[:UCOHASCVE_ID]->(c:UcoCVE {label:\'CVE-2021-44228\'}) RETURN w.ucocweID, w.ucocweName';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'hasWeakness'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);

MERGE (r:UCKGMeta_Relationship {semantic:'hasCVE'})
SET   r.physical_rel          = 'UCOHASCVE_ID',
      r.source_node_semantic  = 'Vulnerability',
      r.source_node_physical  = 'UcoVulnerability',
      r.target_node_semantic  = 'CVE',
      r.target_node_physical  = 'UcoCVE',
      r.description           = 'Connects a Vulnerability concept node to its corresponding CVE identifier node. Required to access CVE scoring data from a Vulnerability node.',
      r.nl_template           = 'Vulnerability {SRC_ID} is identified by {TGT_ID}, which is a CVE entry.',
      r.cypher_pattern        = 'MATCH (v:UcoVulnerability)-[:UCOHASCVE_ID]->(c:UcoCVE)',
      r.triggers              = ['CVE for vulnerability', 'vulnerability identifier', 'get CVE from vulnerability', 'link vulnerability to CVE'],
      r.example_query         = 'MATCH (v:UcoVulnerability)-[:UCOHASCVE_ID]->(c:UcoCVE) WHERE v.ucopublishedDateTime >= datetime(\'2021-01-01\') RETURN c.label, c.ucobaseSeverity LIMIT 10';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'hasCVE'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);

MERGE (r:UCKGMeta_Relationship {semantic:'attributedTo'})
SET   r.physical_rel          = 'UCOEXATTRIBUTEDTO',
      r.source_node_semantic  = 'Campaign',
      r.source_node_physical  = 'UcoexCAMPAIGNS',
      r.target_node_semantic  = 'Group',
      r.target_node_physical  = 'UcoexGROUPS',
      r.description           = 'Indicates that a threat campaign has been attributed to a specific threat actor group.',
      r.nl_template           = 'Campaign {SRC_ID} is attributed to threat group {TGT_ID}.',
      r.cypher_pattern        = 'MATCH (camp:UcoexCAMPAIGNS)-[:UCOEXATTRIBUTEDTO]->(g:UcoexGROUPS)',
      r.triggers              = ['campaign attributed to', 'who conducted campaign', 'which group is behind', 'threat actor responsible'],
      r.example_query         = 'MATCH (camp:UcoexCAMPAIGNS {ucoexNAME:\'Operation Wocao\'})-[:UCOEXATTRIBUTEDTO]->(g:UcoexGROUPS) RETURN g.ucoexNAME';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'attributedTo'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);

MERGE (r:UCKGMeta_Relationship {semantic:'campaignUsesSoftware'})
SET   r.physical_rel          = 'UCOEXCAMPAIGNUSESSOFTWARE',
      r.source_node_semantic  = 'Campaign',
      r.source_node_physical  = 'UcoexCAMPAIGNS',
      r.target_node_semantic  = 'Software',
      r.target_node_physical  = 'UcoexSOFTWARE',
      r.description           = 'Indicates that a campaign used a specific software (malware/tool) as part of its operations.',
      r.nl_template           = 'Campaign {SRC_ID} uses software {TGT_ID}, which is a threat tool.',
      r.cypher_pattern        = 'MATCH (camp:UcoexCAMPAIGNS)-[:UCOEXCAMPAIGNUSESSOFTWARE]->(s:UcoexSOFTWARE)',
      r.triggers              = ['software used in campaign', 'malware deployed by campaign', 'tools used in operation'],
      r.example_query         = 'MATCH (camp:UcoexCAMPAIGNS {ucoexNAME:\'Operation Wocao\'})-[:UCOEXCAMPAIGNUSESSOFTWARE]->(s:UcoexSOFTWARE) RETURN s.ucoexNAME';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'campaignUsesSoftware'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);

MERGE (r:UCKGMeta_Relationship {semantic:'campaignUsesTechnique'})
SET   r.physical_rel          = 'UCOEXCAMPAIGNUSESTECHNIQUE',
      r.source_node_semantic  = 'Campaign',
      r.source_node_physical  = 'UcoexCAMPAIGNS',
      r.target_node_semantic  = 'Technique',
      r.target_node_physical  = 'UcoexMITREATTACK',
      r.description           = 'Indicates that a campaign employed a specific ATT&CK technique.',
      r.nl_template           = 'Campaign {SRC_ID} employs the adversary technique {TGT_ID}.',
      r.cypher_pattern        = 'MATCH (camp:UcoexCAMPAIGNS)-[:UCOEXCAMPAIGNUSESTECHNIQUE]->(t:UcoexMITREATTACK)',
      r.triggers              = ['technique used in campaign', 'campaign TTPs', 'attack techniques in operation'],
      r.example_query         = 'MATCH (camp:UcoexCAMPAIGNS {ucoexNAME:\'Operation Wocao\'})-[:UCOEXCAMPAIGNUSESTECHNIQUE]->(t:UcoexMITREATTACK) RETURN t.ucoexNAME';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'campaignUsesTechnique'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);

MERGE (r:UCKGMeta_Relationship {semantic:'hasRelatedWeakness'})
SET   r.physical_rel          = 'UCOEXHASRELATEDWEAKNESS',
      r.source_node_semantic  = 'AttackPattern',
      r.source_node_physical  = 'UcoexCAPEC',
      r.target_node_semantic  = 'Weakness',
      r.target_node_physical  = 'UcoCWE',
      r.description           = 'Maps a CAPEC attack pattern to the CWE weaknesses it exploits.',
      r.nl_template           = 'Attack pattern {SRC_ID} exploits the weakness {TGT_ID}, which is a {TGT_LABEL}.',
      r.cypher_pattern        = 'MATCH (ap:UcoexCAPEC)-[:UCOEXHASRELATEDWEAKNESS]->(w:UcoCWE)',
      r.triggers              = ['attack pattern for weakness', 'CAPEC exploits CWE', 'which attack patterns exploit this weakness'],
      r.example_query         = 'MATCH (ap:UcoexCAPEC)-[:UCOEXHASRELATEDWEAKNESS]->(w:UcoCWE {ucocweID:\'CWE-89\'}) RETURN ap.ucoexCAPEC_id, ap.ucoexCAPEC_name';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'hasRelatedWeakness'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);

MERGE (r:UCKGMeta_Relationship {semantic:'mapsToTechnique'})
SET   r.physical_rel          = 'UCOEXHASTAXONOMYMAPPING',
      r.source_node_semantic  = 'AttackPattern',
      r.source_node_physical  = 'UcoexCAPEC',
      r.target_node_semantic  = 'Technique',
      r.target_node_physical  = 'UcoexMITREATTACK',
      r.description           = 'Maps a CAPEC attack pattern to corresponding ATT&CK techniques via ATT&CK taxonomy mapping.',
      r.nl_template           = 'Attack pattern {SRC_ID} maps to ATT&CK technique {TGT_ID}.',
      r.cypher_pattern        = 'MATCH (ap:UcoexCAPEC)-[:UCOEXHASTAXONOMYMAPPING]->(t:UcoexMITREATTACK)',
      r.triggers              = ['CAPEC maps to technique', 'attack pattern ATT&CK mapping', 'ATT&CK equivalent of CAPEC'],
      r.example_query         = 'MATCH (ap:UcoexCAPEC {ucoexCAPEC_id:\'CAPEC-66\'})-[:UCOEXHASTAXONOMYMAPPING]->(t:UcoexMITREATTACK) RETURN t.ucoexNAME';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'mapsToTechnique'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);

MERGE (r:UCKGMeta_Relationship {semantic:'groupUsesSoftware'})
SET   r.physical_rel          = 'UCOEXGROUPUSESSOFTWARE',
      r.source_node_semantic  = 'Group',
      r.source_node_physical  = 'UcoexGROUPS',
      r.target_node_semantic  = 'Software',
      r.target_node_physical  = 'UcoexSOFTWARE',
      r.description           = 'Indicates that a threat group uses a specific software (malware or tool).',
      r.nl_template           = 'Threat group {SRC_ID} uses software {TGT_ID}, which is a threat tool.',
      r.cypher_pattern        = 'MATCH (g:UcoexGROUPS)-[:UCOEXGROUPUSESSOFTWARE]->(s:UcoexSOFTWARE)',
      r.triggers              = ['software used by group', 'malware used by APT', 'tools of threat actor', 'group\'s toolset'],
      r.example_query         = 'MATCH (g:UcoexGROUPS {ucoexNAME:\'APT29\'})-[:UCOEXGROUPUSESSOFTWARE]->(s:UcoexSOFTWARE) RETURN s.ucoexNAME';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'groupUsesSoftware'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);

MERGE (r:UCKGMeta_Relationship {semantic:'groupUsesTechnique'})
SET   r.physical_rel          = 'UCOEXGROUPUSESTECHNIQUE',
      r.source_node_semantic  = 'Group',
      r.source_node_physical  = 'UcoexGROUPS',
      r.target_node_semantic  = 'Technique',
      r.target_node_physical  = 'UcoexMITREATTACK',
      r.description           = 'Indicates that a threat group employs a specific ATT&CK technique. Primary relationship for threat-actor TTP queries.',
      r.nl_template           = 'Threat group {SRC_ID} employs the adversary technique {TGT_ID}.',
      r.cypher_pattern        = 'MATCH (g:UcoexGROUPS)-[:UCOEXGROUPUSESTECHNIQUE]->(t:UcoexMITREATTACK)',
      r.triggers              = ['techniques used by group', 'group TTPs', 'APT uses technique', 'threat actor attack methods'],
      r.example_query         = 'MATCH (g:UcoexGROUPS {ucoexNAME:\'APT29\'})-[:UCOEXGROUPUSESTECHNIQUE]->(t:UcoexMITREATTACK) RETURN t.ucoexNAME LIMIT 10';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'groupUsesTechnique'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);

MERGE (r:UCKGMeta_Relationship {semantic:'mitigates'})
SET   r.physical_rel          = 'UCOEXMITIGATES',
      r.source_node_semantic  = 'Mitigation',
      r.source_node_physical  = 'UcoexMITIGATIONS',
      r.target_node_semantic  = 'Technique',
      r.target_node_physical  = 'UcoexMITREATTACK',
      r.description           = 'Indicates that a mitigation reduces the effectiveness of a specific ATT&CK technique.',
      r.nl_template           = 'Security mitigation {SRC_ID} reduces the effectiveness of technique {TGT_ID}.',
      r.cypher_pattern        = 'MATCH (m:UcoexMITIGATIONS)-[:UCOEXMITIGATES]->(t:UcoexMITREATTACK)',
      r.triggers              = ['how to mitigate technique', 'defense against technique', 'which mitigations cover', 'countermeasure for attack'],
      r.example_query         = 'MATCH (m:UcoexMITIGATIONS)-[:UCOEXMITIGATES]->(t:UcoexMITREATTACK) WHERE toLower(t.ucoexNAME) CONTAINS \'phishing\' RETURN m.ucoexNAME';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'mitigates'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);

MERGE (r:UCKGMeta_Relationship {semantic:'d3fendCoversTechnique'})
SET   r.physical_rel          = 'UCOEXHASMITREATTACK',
      r.source_node_semantic  = 'D3FENDControl',
      r.source_node_physical  = 'UcoexMITRED3FEND',
      r.target_node_semantic  = 'Technique',
      r.target_node_physical  = 'UcoexMITREATTACK',
      r.description           = 'Maps a D3FEND defensive control to the ATT&CK offensive technique it defends against.',
      r.nl_template           = 'D3FEND control {SRC_ID} defends against ATT&CK technique {TGT_ID}.',
      r.cypher_pattern        = 'MATCH (d:UcoexMITRED3FEND)-[:UCOEXHASMITREATTACK]->(t:UcoexMITREATTACK)',
      r.triggers              = ['D3FEND control covers technique', 'defensive technique against ATT&CK', 'which D3FEND defends against'],
      r.example_query         = 'MATCH (d:UcoexMITRED3FEND)-[:UCOEXHASMITREATTACK]->(t:UcoexMITREATTACK) WHERE toLower(t.ucoexNAME) CONTAINS \'phishing\' RETURN d.ucoexMITRED3FEND_LABEL';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'d3fendCoversTechnique'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);

MERGE (r:UCKGMeta_Relationship {semantic:'exampleObservedIn'})
SET   r.physical_rel          = 'UCOEXEXAMPLEOBSERVEDIN',
      r.source_node_semantic  = 'ObservedExample',
      r.source_node_physical  = 'UcoexObservedExample',
      r.target_node_semantic  = 'CVE',
      r.target_node_physical  = 'UcoCVE',
      r.description           = 'Links a real-world observed example of a weakness to the CVE where that exploitation was recorded.',
      r.nl_template           = 'This exploitation example was observed in {TGT_ID}, which is a vulnerability.',
      r.cypher_pattern        = 'MATCH (oe:UcoexObservedExample)-[:UCOEXEXAMPLEOBSERVEDIN]->(c:UcoCVE)',
      r.triggers              = ['example observed in CVE', 'weakness observed as CVE', 'real world CVE for weakness'],
      r.example_query         = 'MATCH (w:UcoCWE {ucocweID:\'CWE-79\'})-[:UCOHASOBSERVEDEXAMPLE]->(oe:UcoexObservedExample)-[:UCOEXEXAMPLEOBSERVEDIN]->(c:UcoCVE) RETURN c.label, oe.ucoexDESCRIPTION LIMIT 5';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'exampleObservedIn'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);

MERGE (r:UCKGMeta_Relationship {semantic:'softwareUsesTechnique'})
SET   r.physical_rel          = 'UCOEXSOFTWAREUSESTECHNIQUE',
      r.source_node_semantic  = 'Software',
      r.source_node_physical  = 'UcoexSOFTWARE',
      r.target_node_semantic  = 'Technique',
      r.target_node_physical  = 'UcoexMITREATTACK',
      r.description           = 'Indicates that a software (malware or tool) employs a specific ATT&CK technique.',
      r.nl_template           = 'Software {SRC_ID} employs ATT&CK technique {TGT_ID}.',
      r.cypher_pattern        = 'MATCH (s:UcoexSOFTWARE)-[:UCOEXSOFTWAREUSESTECHNIQUE]->(t:UcoexMITREATTACK)',
      r.triggers              = ['technique used by software', 'malware uses technique', 'tool\'s ATT&CK techniques'],
      r.example_query         = 'MATCH (s:UcoexSOFTWARE {ucoexNAME:\'Mimikatz\'})-[:UCOEXSOFTWAREUSESTECHNIQUE]->(t:UcoexMITREATTACK) RETURN t.ucoexNAME';
MATCH (s:UCKGMeta_Schema {version:'v3'}),(r:UCKGMeta_Relationship {semantic:'softwareUsesTechnique'}) MERGE (s)-[:META_HAS_RELATIONSHIP]->(r);


// ── 5. META_CONNECTS_TO — schema-level topology ───────────────────────────
// One edge per relationship triple, reproducing the graph topology at the
// schema level so the metadata itself is a traversable graph.

MATCH (src:UCKGMeta_Node {semantic:'CVE'}),       (tgt:UCKGMeta_Node {semantic:'CPE'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'hasCPE', via_physical:'UCOEXHASCPE'}]->(tgt);

MATCH (src:UCKGMeta_Node {semantic:'Weakness'}),  (tgt:UCKGMeta_Node {semantic:'ObservedExample'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'hasObservedExample', via_physical:'UCOHASOBSERVEDEXAMPLE'}]->(tgt);

MATCH (src:UCKGMeta_Node {semantic:'ExploitTarget'}), (tgt:UCKGMeta_Node {semantic:'Vulnerability'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'hasVulnerability', via_physical:'UCOHASVULNERABILITY'}]->(tgt);

MATCH (src:UCKGMeta_Node {semantic:'ExploitTarget'}), (tgt:UCKGMeta_Node {semantic:'Weakness'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'hasWeakness', via_physical:'UCOHASWEAKNESS'}]->(tgt);

MATCH (src:UCKGMeta_Node {semantic:'Vulnerability'}), (tgt:UCKGMeta_Node {semantic:'CVE'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'hasCVE', via_physical:'UCOHASCVE_ID'}]->(tgt);

MATCH (src:UCKGMeta_Node {semantic:'Campaign'}),  (tgt:UCKGMeta_Node {semantic:'Group'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'attributedTo', via_physical:'UCOEXATTRIBUTEDTO'}]->(tgt);

MATCH (src:UCKGMeta_Node {semantic:'Campaign'}),  (tgt:UCKGMeta_Node {semantic:'Software'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'campaignUsesSoftware', via_physical:'UCOEXCAMPAIGNUSESSOFTWARE'}]->(tgt);

MATCH (src:UCKGMeta_Node {semantic:'Campaign'}),  (tgt:UCKGMeta_Node {semantic:'Technique'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'campaignUsesTechnique', via_physical:'UCOEXCAMPAIGNUSESTECHNIQUE'}]->(tgt);

MATCH (src:UCKGMeta_Node {semantic:'AttackPattern'}), (tgt:UCKGMeta_Node {semantic:'Weakness'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'hasRelatedWeakness', via_physical:'UCOEXHASRELATEDWEAKNESS'}]->(tgt);

MATCH (src:UCKGMeta_Node {semantic:'AttackPattern'}), (tgt:UCKGMeta_Node {semantic:'Technique'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'mapsToTechnique', via_physical:'UCOEXHASTAXONOMYMAPPING'}]->(tgt);

MATCH (src:UCKGMeta_Node {semantic:'Group'}),     (tgt:UCKGMeta_Node {semantic:'Software'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'groupUsesSoftware', via_physical:'UCOEXGROUPUSESSOFTWARE'}]->(tgt);

MATCH (src:UCKGMeta_Node {semantic:'Group'}),     (tgt:UCKGMeta_Node {semantic:'Technique'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'groupUsesTechnique', via_physical:'UCOEXGROUPUSESTECHNIQUE'}]->(tgt);

MATCH (src:UCKGMeta_Node {semantic:'Mitigation'}),(tgt:UCKGMeta_Node {semantic:'Technique'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'mitigates', via_physical:'UCOEXMITIGATES'}]->(tgt);

MATCH (src:UCKGMeta_Node {semantic:'D3FENDControl'}),(tgt:UCKGMeta_Node {semantic:'Technique'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'d3fendCoversTechnique', via_physical:'UCOEXHASMITREATTACK'}]->(tgt);

MATCH (src:UCKGMeta_Node {semantic:'ObservedExample'}),(tgt:UCKGMeta_Node {semantic:'CVE'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'exampleObservedIn', via_physical:'UCOEXEXAMPLEOBSERVEDIN'}]->(tgt);

MATCH (src:UCKGMeta_Node {semantic:'Software'}),  (tgt:UCKGMeta_Node {semantic:'Technique'})
MERGE (src)-[:META_CONNECTS_TO {via_semantic:'softwareUsesTechnique', via_physical:'UCOEXSOFTWAREUSESTECHNIQUE'}]->(tgt);


// ── 6. Traversal path metadata ────────────────────────────────────────────

MERGE (tp:UCKGMeta_TraversalPath {name:'CWE to CVE (full chain)'})
SET tp.description   = 'Traverse from a weakness (CWE) to all CVEs that resulted from that weakness type.',
    tp.cypher_pattern = 'MATCH (w:UcoCWE)<-[:UCOHASWEAKNESS]-(et:UcoExploitTarget)-[:UCOHASVULNERABILITY]->(v:UcoVulnerability)-[:UCOHASCVE_ID]->(c:UcoCVE)',
    tp.use_cases      = ['CVEs caused by SQL injection weakness', 'all CVEs for a given CWE'];
MATCH (s:UCKGMeta_Schema {version:'v3'}),(tp:UCKGMeta_TraversalPath {name:'CWE to CVE (full chain)'}) MERGE (s)-[:META_HAS_PATH]->(tp);

MERGE (tp:UCKGMeta_TraversalPath {name:'CVE to affected platforms'})
SET tp.description   = 'Find all CPE platforms/products affected by a specific CVE.',
    tp.cypher_pattern = 'MATCH (c:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE)',
    tp.use_cases      = ['which products are affected by Log4Shell', 'affected versions for a CVE'];
MATCH (s:UCKGMeta_Schema {version:'v3'}),(tp:UCKGMeta_TraversalPath {name:'CVE to affected platforms'}) MERGE (s)-[:META_HAS_PATH]->(tp);

MERGE (tp:UCKGMeta_TraversalPath {name:'CVE to weakness (reverse)'})
SET tp.description   = 'From a CVE, find the underlying CWE weakness via the exploit target chain.',
    tp.cypher_pattern = 'MATCH (c:UcoCVE)<-[:UCOHASCVE_ID]-(v:UcoVulnerability)<-[:UCOHASVULNERABILITY]-(et:UcoExploitTarget)-[:UCOHASWEAKNESS]->(w:UcoCWE)',
    tp.use_cases      = ['what weakness type underlies CVE-XXXX', 'CWE for a specific CVE'];
MATCH (s:UCKGMeta_Schema {version:'v3'}),(tp:UCKGMeta_TraversalPath {name:'CVE to weakness (reverse)'}) MERGE (s)-[:META_HAS_PATH]->(tp);

MERGE (tp:UCKGMeta_TraversalPath {name:'CWE to ATT&CK techniques (via CAPEC)'})
SET tp.description   = 'From a CWE weakness, find related ATT&CK techniques through CAPEC attack patterns.',
    tp.cypher_pattern = 'MATCH (w:UcoCWE)<-[:UCOEXHASRELATEDWEAKNESS]-(ap:UcoexCAPEC)-[:UCOEXHASTAXONOMYMAPPING]->(t:UcoexMITREATTACK)',
    tp.use_cases      = ['ATT&CK techniques for SQL injection weakness', 'technique coverage for a CWE'];
MATCH (s:UCKGMeta_Schema {version:'v3'}),(tp:UCKGMeta_TraversalPath {name:'CWE to ATT&CK techniques (via CAPEC)'}) MERGE (s)-[:META_HAS_PATH]->(tp);

MERGE (tp:UCKGMeta_TraversalPath {name:'Group full TTP profile'})
SET tp.description   = 'Complete TTP profile of a threat group: techniques, software, and campaigns.',
    tp.cypher_pattern = 'MATCH (g:UcoexGROUPS) OPTIONAL MATCH (g)-[:UCOEXGROUPUSESTECHNIQUE]->(t:UcoexMITREATTACK) OPTIONAL MATCH (g)-[:UCOEXGROUPUSESSOFTWARE]->(s:UcoexSOFTWARE) OPTIONAL MATCH (camp:UcoexCAMPAIGNS)-[:UCOEXATTRIBUTEDTO]->(g)',
    tp.use_cases      = ['complete profile of APT29', 'all TTPs for a threat actor'];
MATCH (s:UCKGMeta_Schema {version:'v3'}),(tp:UCKGMeta_TraversalPath {name:'Group full TTP profile'}) MERGE (s)-[:META_HAS_PATH]->(tp);

MERGE (tp:UCKGMeta_TraversalPath {name:'Technique to mitigations and D3FEND'})
SET tp.description   = 'For a given ATT&CK technique, find all mitigations and D3FEND controls that address it.',
    tp.cypher_pattern = 'MATCH (t:UcoexMITREATTACK) OPTIONAL MATCH (m:UcoexMITIGATIONS)-[:UCOEXMITIGATES]->(t) OPTIONAL MATCH (d:UcoexMITRED3FEND)-[:UCOEXHASMITREATTACK]->(t)',
    tp.use_cases      = ['how to defend against phishing', 'mitigations for credential dumping'];
MATCH (s:UCKGMeta_Schema {version:'v3'}),(tp:UCKGMeta_TraversalPath {name:'Technique to mitigations and D3FEND'}) MERGE (s)-[:META_HAS_PATH]->(tp);

MERGE (tp:UCKGMeta_TraversalPath {name:'CWE observed examples to CVE evidence'})
SET tp.description   = 'Find real-world CVEs where a specific CWE weakness was demonstrated.',
    tp.cypher_pattern = 'MATCH (w:UcoCWE)-[:UCOHASOBSERVEDEXAMPLE]->(oe:UcoexObservedExample)-[:UCOEXEXAMPLEOBSERVEDIN]->(c:UcoCVE)',
    tp.use_cases      = ['real CVEs for XSS weakness', 'historical exploitation of CWE-89'];
MATCH (s:UCKGMeta_Schema {version:'v3'}),(tp:UCKGMeta_TraversalPath {name:'CWE observed examples to CVE evidence'}) MERGE (s)-[:META_HAS_PATH]->(tp);


// ── Verification ──────────────────────────────────────────────────────────
MATCH (n:UCKGMeta_Node)
OPTIONAL MATCH (n)-[:META_HAS_PROPERTY]->(p:UCKGMeta_Property)
RETURN n.semantic AS node_type, n.physical_label AS physical, count(p) AS properties
ORDER BY n.semantic;
