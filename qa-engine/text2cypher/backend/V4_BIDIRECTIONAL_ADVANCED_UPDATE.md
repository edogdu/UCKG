# Text2Cypher V4 Update: Bidirectional Paths and Advanced Features

## Overview
This update (V4) introduces major enhancements to the Text2Cypher pipeline by implementing bidirectional path mapping, multi-hop templates, relationship cardinality analysis, and property-based filtering hints. These features significantly improve the LLM's understanding of graph topology and query generation capabilities.

---

## 🚀 Key V4 Features

### 1. **Bidirectional Path Mapping**
**Previous (V3)**: Only showed outgoing connections
**V4**: Shows both incoming and outgoing connections for each node type

```
UcoCVE:
  Outgoing:
    - UcoCVE -[UCOEXHASCPE]-> UcoexCPE (1:many)
  Incoming:
    - UcoVulnerability -[UCOHASCVE_ID]-> UcoCVE (1:1)
    - UcoexObservedExample -[UCOEXEXAMPLEOBSERVEDIN]-> UcoCVE (unknown)
```

**Benefits:**
- ✅ **Complete Graph View**: LLM understands both directions of relationships
- ✅ **Reverse Queries**: Can generate queries starting from any node type
- ✅ **Path Discovery**: Easier to find multi-hop paths between any two nodes
- ✅ **Query Optimization**: Better understanding of graph structure for complex queries

### 2. **Multi-hop Path Templates**
**New Feature**: Pre-defined common traversal patterns

```
Common Multi-hop Path Templates:
- UcoCVE -[UCOEXHASCPE]-> UcoexCPE <-[UCOEXHASCPE]- UcoCVE (Find CVEs affecting same platform)
- UcoexGROUPS -[UCOEXGROUPUSESTECHNIQUE]-> UcoexMITREATTACK <-[UCOEXSOFTWAREUSESTECHNIQUE]- UcoexSOFTWARE (Groups and software using same technique)
- UcoexCAMPAIGNS -[UCOEXATTRIBUTEDTO]-> UcoexGROUPS -[UCOEXGROUPUSESTECHNIQUE]-> UcoexMITREATTACK (Campaign attribution to techniques)
```

**Benefits:**
- ✅ **Complex Query Support**: LLM can generate sophisticated multi-hop queries
- ✅ **Pattern Recognition**: Common cybersecurity analysis patterns are pre-defined
- ✅ **Query Templates**: Reusable patterns for similar analysis needs
- ✅ **Performance Hints**: Optimized paths for common use cases

### 3. **Relationship Cardinality Analysis**
**New Feature**: Automatic analysis of relationship cardinality patterns

```
- UcoCVE -[UCOEXHASCPE]-> UcoexCPE (1:many)
- UcoexGROUPS -[UCOEXGROUPUSESTECHNIQUE]-> UcoexMITREATTACK (1:many+)
- UcoexCAMPAIGNS -[UCOEXATTRIBUTEDTO]-> UcoexGROUPS (1:1)
```

**Cardinality Types:**
- `1:1` - One-to-one relationships
- `1:few` - One-to-few relationships (2-5 connections)
- `1:many` - One-to-many relationships (6-10 connections)
- `1:many+` - One-to-many+ relationships (10+ connections)
- `unknown` - Cardinality couldn't be determined

**Benefits:**
- ✅ **Query Optimization**: LLM can optimize queries based on expected result sizes
- ✅ **Performance Awareness**: Understands which relationships will return large result sets
- ✅ **LIMIT Guidance**: Better decisions about when to use LIMIT clauses
- ✅ **Join Strategy**: Can choose optimal traversal directions

### 4. **Property-based Filtering Hints**
**New Feature**: Intelligent filtering suggestions for each node type

```
Property-based Filtering Hints:
- UcoCVE: Filter by ucobaseSeverity: 'HIGH', 'MEDIUM', 'LOW'
- UcoCVE: Filter by ucoexploitabilityScore: numeric values 0.0-10.0
- UcoCWE: Search in ucocweName: use CONTAINS for partial matches
- UcoexGROUPS: Filter by ucoexDOMAIN: 'enterprise-attack', 'mobile-attack', 'ics-attack'
```

**Benefits:**
- ✅ **Smart Filtering**: LLM knows which properties are useful for filtering
- ✅ **Value Guidance**: Suggests appropriate values for each property
- ✅ **Search Patterns**: Indicates when to use CONTAINS vs exact matches
- ✅ **Domain Knowledge**: Captures cybersecurity-specific filtering patterns

---

## 📊 Complete V4 Schema Example

```
CYBERSECURITY KNOWLEDGE GRAPH SCHEMA (V4):

Node Labels and Properties:
- UcoCVE: [embedding, embedding_processed, label, ucobaseSeverity, ucoevaluatorSolution, ...]
- UcoCWE: [ucoabstraction, ucoapplicablePlatform, ucocommonConsequences, ucocweExtendedSummary, ...]
- UcoexCAPEC: [label, ucoexAbstraction, ucoexCAPEC_id, ucoexCAPEC_name, ucoexConsequences, ...]

Bidirectional Connections for Each Node Type:

UcoCVE:
  Outgoing:
    - UcoCVE -[UCOEXHASCPE]-> UcoexCPE (1:many)
  Incoming:
    - UcoVulnerability -[UCOHASCVE_ID]-> UcoCVE (1:1)
    - UcoexObservedExample -[UCOEXEXAMPLEOBSERVEDIN]-> UcoCVE (unknown)

UcoexGROUPS:
  Outgoing:
    - UcoexGROUPS -[UCOEXGROUPUSESSOFTWARE]-> UcoexSOFTWARE (1:many)
    - UcoexGROUPS -[UCOEXGROUPUSESTECHNIQUE]-> UcoexMITREATTACK (1:many+)
  Incoming:
    - UcoexCAMPAIGNS -[UCOEXATTRIBUTEDTO]-> UcoexGROUPS (1:1)

Common Multi-hop Path Templates:
- UcoCVE -[UCOEXHASCPE]-> UcoexCPE <-[UCOEXHASCPE]- UcoCVE (Find CVEs affecting same platform)
- UcoexGROUPS -[UCOEXGROUPUSESTECHNIQUE]-> UcoexMITREATTACK <-[UCOEXSOFTWAREUSESTECHNIQUE]- UcoexSOFTWARE (Groups and software using same technique)

Property-based Filtering Hints:
- UcoCVE: Filter by ucobaseSeverity: 'HIGH', 'MEDIUM', 'LOW'
- UcoCWE: Search in ucocweName: use CONTAINS for partial matches
- UcoexGROUPS: Filter by ucoexDOMAIN: 'enterprise-attack', 'mobile-attack', 'ics-attack'
```

---

## 🔧 Technical Implementation

### New Helper Methods

#### `_fetch_incoming_connections()`
```python
def _fetch_incoming_connections(self) -> dict:
    """Return mapping of node label -> list of (source_label, relationship_type) tuples for incoming connections."""
    # Analyzes Neo4j schema to find all incoming relationships for each node type
    # Returns: {node_label: [(source_label, rel_type), ...]}
```

#### `_generate_multi_hop_templates()`
```python
def _generate_multi_hop_templates(self) -> list:
    """Generate common multi-hop path templates for cybersecurity queries."""
    # Pre-defined patterns for common cybersecurity analysis scenarios
    # Returns: List of string templates with descriptions
```

#### `_fetch_relationship_cardinality()`
```python
def _fetch_relationship_cardinality(self) -> dict:
    """Estimate relationship cardinality based on actual data patterns."""
    # Analyzes actual data to determine relationship cardinality
    # Returns: {rel_type: "1:1"|"1:few"|"1:many"|"1:many+"|"unknown"}
```

#### `_generate_filtering_hints()`
```python
def _generate_filtering_hints(self, node_props: dict) -> list:
    """Generate property-based filtering hints for common query patterns."""
    # Creates intelligent filtering suggestions based on node properties
    # Returns: List of filtering hint strings
```

### Enhanced Prompt Engineering

**New Critical Rules:**
- Rule 16: Use cardinality information to understand relationship patterns
- Rule 17: For complex multi-hop queries, consider using provided path templates
- Rule 18: Use filtering hints to apply appropriate property filters

**Enhanced Query Types:**
- Multi-hop traversals using provided path templates
- Using cardinality information to optimize query structure
- Property-based filtering with intelligent hints

---

## 📈 Impact Analysis

### Before V4 (V3 Limitations)
- ❌ Only outgoing connections visible
- ❌ No guidance for complex multi-hop queries
- ❌ No understanding of relationship cardinality
- ❌ Limited filtering guidance
- ❌ Difficult to generate reverse queries

### After V4 (Solutions)
- ✅ **Bidirectional Visibility**: Complete graph topology understanding
- ✅ **Multi-hop Templates**: Pre-defined patterns for complex queries
- ✅ **Cardinality Awareness**: Performance-optimized query generation
- ✅ **Smart Filtering**: Intelligent property-based filtering hints
- ✅ **Reverse Queries**: Can start from any node type
- ✅ **Pattern Recognition**: Common cybersecurity analysis patterns

### Query Generation Improvements

**Example 1: Complex Multi-hop Query**
```
Question: "Find threat groups that use the same techniques as specific software"

V4 Schema Guidance:
- UcoexGROUPS -[UCOEXGROUPUSESTECHNIQUE]-> UcoexMITREATTACK <-[UCOEXSOFTWAREUSESTECHNIQUE]- UcoexSOFTWARE
- Template: "Groups and software using same technique"

Generated Cypher:
MATCH (group:UcoexGROUPS)-[:UCOEXGROUPUSESTECHNIQUE]->(technique:UcoexMITREATTACK)<-[:UCOEXSOFTWAREUSESTECHNIQUE]-(software:UcoexSOFTWARE)
WHERE software.ucoexNAME CONTAINS 'specific_software'
RETURN group, technique, software
```

**Example 2: Cardinality-Aware Query**
```
Question: "Show CVEs with high severity that affect Windows platforms"

V4 Schema Guidance:
- UcoCVE -[UCOEXHASCPE]-> UcoexCPE (1:many) - Expect multiple CPEs per CVE
- Filtering hints: ucobaseSeverity: 'HIGH', 'MEDIUM', 'LOW'

Generated Cypher:
MATCH (cve:UcoCVE)-[:UCOEXHASCPE]->(cpe:UcoexCPE)
WHERE cve.ucobaseSeverity = 'HIGH' AND cpe.cpeName CONTAINS 'microsoft:windows'
RETURN cve, cpe
```

---

## 🎯 Use Cases Enabled by V4

### 1. **Reverse Analysis Queries**
- "What CVEs are related to this CWE?"
- "Which groups use this specific technique?"
- "What campaigns are attributed to this group?"

### 2. **Complex Multi-hop Analysis**
- "Find groups and software using the same techniques"
- "Show CVEs affecting the same platform with their weaknesses"
- "Find mitigations for techniques used by specific groups"

### 3. **Performance-Optimized Queries**
- Cardinality-aware LIMIT clauses
- Optimal traversal direction selection
- Efficient filtering strategies

### 4. **Intelligent Filtering**
- Property-specific filtering suggestions
- Domain-appropriate value ranges
- Search pattern recommendations

---

## 🔮 Future Enhancements (V5+)

### Potential V5 Features
1. **Query Performance Scoring**: Rate query efficiency based on cardinality
2. **Dynamic Template Generation**: Learn new patterns from successful queries
3. **Context-Aware Filtering**: Adapt filtering hints based on query context
4. **Path Optimization**: Suggest shortest paths between node types
5. **Query Caching**: Cache successful query patterns for reuse

### Advanced Analytics
1. **Query Success Metrics**: Track which patterns work best
2. **Cardinality Evolution**: Monitor how relationships change over time
3. **Template Effectiveness**: Measure which templates are most useful
4. **Filtering Accuracy**: Track which filtering hints are most effective

---

## 📝 Summary

V4 transforms Text2Cypher from a simple query generator into an **intelligent graph analysis assistant** with deep understanding of:

- **Complete Graph Topology**: Bidirectional relationship mapping
- **Complex Query Patterns**: Multi-hop traversal templates
- **Performance Characteristics**: Relationship cardinality analysis
- **Domain Expertise**: Property-based filtering intelligence

**Key Success Factors:**
- **Bidirectional Awareness**: Complete graph understanding
- **Pattern Recognition**: Pre-defined analysis templates
- **Performance Intelligence**: Cardinality-driven optimization
- **Domain Knowledge**: Cybersecurity-specific filtering guidance

This update enables sophisticated cybersecurity analysis queries that were previously impossible or very difficult to generate, while maintaining high performance through intelligent query optimization.

**V4 Achievement**: Text2Cypher now understands the cybersecurity knowledge graph as a complete, bidirectional network with performance characteristics and domain-specific analysis patterns.