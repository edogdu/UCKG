# UCKG `extract_text()` — Natural Language Descriptions from the Knowledge Graph

## Overview

`extract_text()` generates **natural-language sentences** from actual UCKG data by combining:

1. **`nl_template`** — a sentence template stored as metadata on `UCKGMeta_*` nodes/edges in Neo4j
2. **Real data values** — fetched from the live knowledge graph at runtime

This produces data-grounded English sentences that describe what each node *is* and how nodes are *connected*.

---

## Output Structure

The output file contains **two sections** written sequentially:

| Section | Count (limit=20) | Description |
|---------|-------------------|-------------|
| **Node sentences** | 280 (14 types × 20) | One sentence per data node — identifies the entity and its key descriptive property |
| **Edge sentences** | 320 (16 types × 20) | One sentence per data edge — describes a relationship between two concrete nodes |

---

## Node Sentences

Each node type in the UCKG has an `nl_template` stored on its `UCKGMeta_Node` metadata node.
The template contains placeholders that are filled with actual data at extraction time:

| Placeholder | Source |
|-------------|--------|
| `{ID}` | The node's `key_identifier` property value (e.g., `label`, `ucoexNAME`, `cpeName`) |
| `{DESC}` | A descriptive property specified by `desc_property` on the metadata node |

### Templates and Examples per Node Type

| Node Type | `nl_template` | `desc_property` | Example Output |
|-----------|---------------|-----------------|----------------|
| **CVE** | `{ID}, which is a {DESC} severity vulnerability.` | `ucobaseSeverity` | CVE-2002-1777, which is a HIGH severity vulnerability. |
| **Weakness** | `{ID} ({DESC}), which is a software weakness.` | `ucocweName` | CWE-22 (Improper Limitation of a Pathname to a Restricted Directory), which is a software weakness. |
| **AttackPattern** | `CAPEC-{ID} ({DESC}), which is an attack pattern.` | `ucoexCAPEC_name` | CAPEC-666 (BlueSmacking), which is an attack pattern. |
| **Technique** | `{ID}, which is an adversary technique: {DESC}` | `ucoexDESCRIPTION` | Network Sniffing, which is an adversary technique: Adversaries may passively sniff network traffic to capture information about an environment. |
| **Group** | `{ID}, which is a threat actor group: {DESC}` | `ucoexDESCRIPTION` | BlackTech, which is a threat actor group: BlackTech is a suspected Chinese cyber espionage group that has primarily targeted organizations in East Asia. |
| **Campaign** | `{ID}, which is a threat campaign: {DESC}` | `ucoexDESCRIPTION` | FrostyGoop Incident, which is a threat campaign: FrostyGoop Incident took place in January 2024 against a municipal district heating company in Ukraine. |
| **Software** | `{ID}, which is a threat software tool: {DESC}` | `ucoexDESCRIPTION` | ZIPLINE, which is a passive backdoor that was used during Cutting Edge on compromised Secure Connect VPNs. |
| **Mitigation** | `{ID}, which is a security mitigation: {DESC}` | `ucoexDESCRIPTION` | Antivirus/Antimalware, which is a security mitigation: Mobile security products, such as Mobile Threat Defense (MTD), offer various device-based mitigations. |
| **D3FENDControl** | `{ID}, which is a D3FEND defensive control: {DESC}` | `ucoexMITRED3FEND_DEFINITION` | Disk Encryption, which is a D3FEND defensive control: Encrypting a hard disk partition to prevent cleartext access to a file system. |
| **Tactic** | `{ID}, which is an attack tactic: {DESC}` | `ucoexDESCRIPTION` | Exfiltration, which is an attack tactic: The adversary is trying to steal data. |
| **Vulnerability** | `Vulnerability {ID} is described as: {DESC}` | `ucosummary` | Vulnerability VULN-CVE-2000-0364 is described as: screen and rxvt in Red Hat Linux 6.0 do not properly set the modes of tty devices. |
| **ObservedExample** | `An observed exploitation example ({ID}): {DESC}` | `ucoexDESCRIPTION` | An observed exploitation example (CWE-81-CVE-2002-1053): XSS in error message. |
| **CPE** | `{ID}, which is a software platform.` | *(none)* | cpe:2.3:a:apache:log4j:2.14.1, which is a software platform. |
| **ExploitTarget** | `Exploit target {ID}, a pivot node linking weaknesses to vulnerabilities.` | *(none)* | Exploit target ExploitTarget-CWE-908, a pivot node linking weaknesses to vulnerabilities. |

### Text Cleanup Applied

- **URI stripping**: `http://purl.org/cyber/uco#VULN-CVE-2000-0363` → `VULN-CVE-2000-0363`
- **Markdown removal**: `[BlackTech](https://attack.mitre.org/groups/G0098)` → `BlackTech`
- **Citation removal**: `(Citation: Praetorian TLS...)` → removed
- **Truncation**: Descriptions capped at ~200 characters at sentence boundaries

---

## Edge Sentences

Each relationship type has an `nl_template` stored on the `META_CONNECTS_TO` edge between two `UCKGMeta_Node` metadata nodes. The template uses these placeholders:

| Placeholder | Source |
|-------------|--------|
| `{SRC_ID}` | Source node's `key_identifier` value |
| `{SRC_LABEL}` | Source node's human-readable name (falls back to ID) |
| `{TGT_ID}` | Target node's `key_identifier` value |
| `{TGT_LABEL}` | Target node's human-readable name (falls back to ID) |

### Templates and Examples per Relationship Type

| Relationship | Source → Target | Example Output |
|--------------|-----------------|----------------|
| **hasCPE** | CVE → CPE | CVE-1999-0878, which is a vulnerability, has a CPE, cpe:2.3:a:beroftpd:beroftpd:1.3.2, which is a software platform titled "...". |
| **hasCVE** | Vulnerability → CVE | Vulnerability VULN-CVE-2000-0363 is identified by CVE-2000-0363, which is a CVE entry. |
| **attributedTo** | Campaign → Group | Campaign Operation Ghost is attributed to threat group APT29. |
| **campaignUsesSoftware** | Campaign → Software | Campaign APT41 DUST uses software Cobalt Strike, which is a threat tool. |
| **campaignUsesTechnique** | Campaign → Technique | Campaign FrostyGoop Incident employs the adversary technique Application Layer Protocol. |
| **groupUsesSoftware** | Group → Software | Threat group BlackTech uses software PLEAD, which is a threat tool. |
| **groupUsesTechnique** | Group → Technique | Threat group BlackTech employs the adversary technique Exploit Public-Facing Application. |
| **softwareUsesTechnique** | Software → Technique | Software ZIPLINE employs ATT&CK technique Traffic Signaling. |
| **mitigates** | Mitigation → Technique | Security mitigation Antivirus/Antimalware reduces the effectiveness of technique Phishing. |
| **d3fendCoversTechnique** | D3FEND → Technique | D3FEND control Disk Encryption defends against ATT&CK technique Cloud Storage Object Discovery. |
| **hasRelatedWeakness** | AttackPattern → Weakness | Attack pattern CAPEC-666 exploits the weakness CWE-404, which is a CWE-404. |
| **mapsToTechnique** | AttackPattern → Technique | Attack pattern CAPEC-532 maps to ATT&CK technique Firmware Corruption. |
| **hasVulnerability** | ExploitTarget → Vulnerability | Exploit target ExploitTarget-CWE-908 is associated with vulnerability VULN-CVE-2018-3975. |
| **hasWeakness** | ExploitTarget → Weakness | Exploit target ExploitTarget-CWE-1431 is caused by weakness CWE-1431. |
| **hasObservedExample** | Weakness → ObservedExample | CWE-24, which is a software weakness, has an observed real-world exploitation example: CWE-24-CVE-2022-45918. |
| **exampleObservedIn** | ObservedExample → CVE | This exploitation example was observed in CVE-2010-4156, which is a vulnerability. |

---

## How to Run

```bash
# Generate 20 instances per node/relationship type → file
python3 schema/semantic_schema.py extract-text --limit 20 --output schema/extract_text_sample.txt

# Generate all instances (full dataset) → file
python3 schema/semantic_schema.py extract-text --output schema/uckg_full.txt

# Generate only edge sentences for specific relationships
python3 schema/semantic_schema.py extract-text --node none --relation hasCPE,mitigates --limit 50

# Generate only node sentences for CVE and Weakness
python3 schema/semantic_schema.py extract-text --node CVE,Weakness --relation none --limit 100
```

---

## File: `extract_text_sample.txt`

The sample file included in this repository was generated with `--limit 20`, producing:

- **Lines 1–280**: Node sentences (14 types × 20 instances each)
- **Lines 281–600**: Edge sentences (16 relationship types × 20 instances each)
- **Total**: 600 sentences

---

## Where the Templates Live

All `nl_template` and `desc_property` values are stored as metadata **inside Neo4j** on `UCKGMeta_Node` nodes and `META_CONNECTS_TO` edges. They are authored in `schema/semantic_schema.cypher` and loaded via:

```bash
python3 schema/semantic_schema.py update
```

To inspect them directly in Neo4j:

```cypher
-- Node templates
MATCH (n:UCKGMeta_Node)
RETURN n.semantic, n.nl_template, n.desc_property
ORDER BY n.semantic;

-- Edge templates
MATCH (s:UCKGMeta_Node)-[e:META_CONNECTS_TO]->(t:UCKGMeta_Node)
RETURN s.semantic AS source, e.semantic AS rel, t.semantic AS target, e.nl_template
ORDER BY s.semantic, e.semantic;
```
