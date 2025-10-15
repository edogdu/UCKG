# Text2Cypher V3 Update: Explicit Outgoing Connections

## Overview
This update (V3) introduces a major improvement to the schema representation by explicitly defining all outgoing connections for each node type, making it crystal clear which relationships are valid for each cybersecurity entity.

---

## 🚀 Key V3 Update: Explicit Outgoing Connection Mapping

### Previous Approach (V2)
In V2, the schema showed relationship signatures in a condensed format:
```
Relationship Types, Properties, and Signatures:
- UCOEXHASCPE: [no properties] paths: UcoCVE->UcoexCPE
- UCOEXGROUPUSESTECHNIQUE: [no properties] paths: UcoexGROUPS->UcoexMITREATTACK
```

**Problems with V2:**
- Hard to see at a glance what connections a specific node type can make
- Relationships were grouped by type, not by source node
- Less intuitive for understanding the graph topology from a node-centric perspective

### New Approach (V3)
V3 reorganizes the schema to show outgoing connections grouped by source node type:

```
Outgoing Connections for Each Node Type:

UcoCVE:
  - UcoCVE -[UCOEXHASCPE]-> UcoexCPE

UcoexCAPEC:
  - UcoexCAPEC -[UCOEXHASRELATEDWEAKNESS]-> UcoCWE
  - UcoexCAPEC -[UCOEXHASTAXONOMYMAPPING]-> UcoexMITREATTACK

UcoexGROUPS:
  - UcoexGROUPS -[UCOEXGROUPUSESSOFTWARE]-> UcoexSOFTWARE
  - UcoexGROUPS -[UCOEXGROUPUSESTECHNIQUE]-> UcoexMITREATTACK
```

**Benefits of V3:**
- ✅ **Node-Centric View**: Easy to see all possible outgoing connections for any node type
- ✅ **Clear Path Definition**: Each connection shows source → relationship → target in a single line
- ✅ **Better LLM Understanding**: The format matches how queries are constructed (start with a node, follow its connections)
- ✅ **Validation Ready**: Easy to validate that generated queries only use valid paths
- ✅ **Human Readable**: Intuitive format for documentation and debugging

---

## 📊 Complete Outgoing Connections Map

### Vulnerability & Weakness Domain

**UcoCVE** (Common Vulnerabilities and Exposures)
- `UcoCVE -[UCOEXHASCPE]-> UcoexCPE` - Links to affected platforms/products

**UcoCWE** (Common Weakness Enumeration)
- `UcoCWE -[UCOHASOBSERVEDEXAMPLE]-> UcoexObservedExample` - Links to real-world examples

**UcoExploitTarget**
- `UcoExploitTarget -[UCOHASVULNERABILITY]-> UcoVulnerability` - Links to vulnerability details
- `UcoExploitTarget -[UCOHASWEAKNESS]-> UcoCWE` - Links to weakness information

**UcoVulnerability**
- `UcoVulnerability -[UCOHASCVE_ID]-> UcoCVE` - Links to CVE identifiers

### Attack Pattern Domain

**UcoexCAPEC** (Common Attack Pattern Enumeration and Classification)
- `UcoexCAPEC -[UCOEXHASRELATEDWEAKNESS]-> UcoCWE` - Links to related weaknesses
- `UcoexCAPEC -[UCOEXHASTAXONOMYMAPPING]-> UcoexMITREATTACK` - Maps to MITRE ATT&CK techniques

### Threat Actor Domain

**UcoexGROUPS** (Threat Actor Groups)
- `UcoexGROUPS -[UCOEXGROUPUSESSOFTWARE]-> UcoexSOFTWARE` - Links to malware/tools used
- `UcoexGROUPS -[UCOEXGROUPUSESTECHNIQUE]-> UcoexMITREATTACK` - Links to techniques employed

**UcoexCAMPAIGNS** (Attack Campaigns)
- `UcoexCAMPAIGNS -[UCOEXATTRIBUTEDTO]-> UcoexGROUPS` - Attribution to threat groups
- `UcoexCAMPAIGNS -[UCOEXCAMPAIGNUSESSOFTWARE]-> UcoexSOFTWARE` - Links to software used
- `UcoexCAMPAIGNS -[UCOEXCAMPAIGNUSESTECHNIQUE]-> UcoexMITREATTACK` - Links to techniques used

**UcoexSOFTWARE** (Malware and Tools)
- `UcoexSOFTWARE -[UCOEXSOFTWAREUSESTECHNIQUE]-> UcoexMITREATTACK` - Links to techniques

### Defense & Mitigation Domain

**UcoexMITIGATIONS** (Security Mitigations)
- `UcoexMITIGATIONS -[UCOEXMITIGATES]-> UcoexMITREATTACK` - Links to techniques mitigated

**UcoexMITRED3FEND** (MITRE D3FEND Countermeasures)
- `UcoexMITRED3FEND -[UCOEXHASMITREATTACK]-> UcoexMITREATTACK` - Maps to ATT&CK techniques

### Example Domain

**UcoexObservedExample** (Real-world Attack Examples)
- `UcoexObservedExample -[UCOEXEXAMPLEOBSERVEDIN]-> UcoCVE` - Links to CVEs where observed

### Hub Nodes

**UcoexMITREATTACK** (MITRE ATT&CK Techniques)
- *No outgoing connections* - Acts as a central hub that other nodes connect TO

**UcoexCPE** (Common Platform Enumeration)
- *No outgoing connections* - Terminal node for platform/product information

**UcoexTACTICS** (MITRE ATT&CK Tactics)
- *No outgoing connections* - High-level tactical information

---

## 🔄 Implementation Changes

### New Method: `_fetch_outgoing_connections()`

Added a new helper method that:
1. Queries Neo4j's `db.schema.visualization()` 
2. Builds a mapping of node labels to their outgoing relationships
3. Filters out ontology metadata (OWL/RDF relationships)
4. Returns a clean dictionary: `{node_label: [(rel_type, target_label), ...]}`

### Modified Method: `get_cybersecurity_schema()`

Updated to generate the new format:
```python
def get_cybersecurity_schema(self) -> str:
    """Get rich schema information with properties + valid edge signatures (V3 approach with explicit outgoing connections)"""
    node_props = self._fetch_node_properties()
    rel_props = self._fetch_relationship_properties()
    outgoing_connections = self._fetch_outgoing_connections()  # NEW
    
    # Format outgoing connections by source node
    for node_label in sorted(outgoing_connections.keys()):
        outgoing_lines += f"\n{node_label}:\n"
        for rel_type, target_label in sorted(connections):
            outgoing_lines += f"  - {node_label} -[{rel_type}]-> {target_label}\n"
```

### Updated Prompt Engineering

Enhanced the critical rules to emphasize valid connection paths:
```
CRITICAL RULES:
2. Use ONLY valid outgoing relationships defined in 'Outgoing Connections for Each Node Type' section
3. IMPORTANT: Each node type has specific allowed outgoing connections. Check the schema to ensure you use valid paths:
   Example: UcoCVE can only connect via UCOEXHASCPE to UcoexCPE
   Example: UcoexCAPEC can connect via UCOEXHASRELATEDWEAKNESS to UcoCWE
14. NEVER create invalid relationship paths - only use the connections defined in the schema
```

---

## 📈 Impact and Benefits

### Before V3
- Relationship information organized by relationship type
- Required mental mapping to understand node connectivity
- Harder for LLM to validate query paths
- Less intuitive documentation format

### After V3
- ✅ Relationship information organized by source node
- ✅ Immediate visibility of all valid paths from any node
- ✅ Easy validation: "Does this node have this outgoing connection?"
- ✅ Natural format that matches query construction patterns
- ✅ Better documentation and debugging experience

### Example Query Generation

**Question:** "Find threat groups using specific attack techniques"

**V3 Schema Lookup:**
```
UcoexGROUPS:
  - UcoexGROUPS -[UCOEXGROUPUSESSOFTWARE]-> UcoexSOFTWARE
  - UcoexGROUPS -[UCOEXGROUPUSESTECHNIQUE]-> UcoexMITREATTACK
```

**Generated Cypher:**
```cypher
MATCH (group:UcoexGROUPS)-[:UCOEXGROUPUSESTECHNIQUE]->(technique:UcoexMITREATTACK) 
WHERE technique.ucoexNAME CONTAINS 'T1078' 
RETURN group
```

The LLM can clearly see that `UcoexGROUPS` has an outgoing connection via `UCOEXGROUPUSESTECHNIQUE` to `UcoexMITREATTACK`, making it confident in generating this path.

---

## 🧪 Testing Results

All test queries successfully use the new schema format:

1. ✅ **CVE to Platform Query**: Correctly uses `UcoCVE -[UCOEXHASCPE]-> UcoexCPE`
2. ✅ **Group to Technique Query**: Correctly uses `UcoexGROUPS -[UCOEXGROUPUSESTECHNIQUE]-> UcoexMITREATTACK`
3. ✅ **CAPEC to Weakness Query**: Correctly uses `UcoexCAPEC -[UCOEXHASRELATEDWEAKNESS]-> UcoCWE`

---

## 🔮 Future Enhancements

Potential improvements for V4:
1. **Bidirectional Paths**: Show both incoming and outgoing connections
2. **Multi-hop Path Templates**: Common 2-3 hop traversal patterns
3. **Relationship Cardinality**: Indicate one-to-many, many-to-many relationships
4. **Property-based Filtering Hints**: Common filter patterns for each connection
5. **Path Complexity Scoring**: Help LLM choose simpler paths when multiple options exist

---

## 📝 Summary

V3 transforms the schema representation from relationship-centric to **node-centric**, making it dramatically easier for both humans and LLMs to understand valid graph traversal paths. This update significantly improves query generation accuracy by providing crystal-clear guidance on which connections are valid for each cybersecurity entity type.

**Key Takeaway**: Each node type now has its own "connection menu" showing exactly what relationships it can form and what nodes it can connect to.
