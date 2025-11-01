# Question Set Generation

This folder contains tools for generating evaluation questions from the UCKG (Unified Cybersecurity Knowledge Graph) by extracting node data and using LLMs to create natural language questions.

## Overview

The folder consists of four main scripts:

1. **`getNodes.py`** - Extracts node data and relationships from Neo4j database
2. **`get_semantic.py`** - Extracts semantic descriptions for labels and relationships
3. **`get_summary.py`** - Generates human-readable summaries of node groups using LLM
4. **`generate_questions.py`** - Generates natural language questions using LLM based on summaries

## Workflow

```
┌──────────────┐      ┌──────────────┐      ┌─────────────────┐
│  getNodes.py │ ───> │  nodes.json  │ ───> │ get_semantic.py │
│ (Manual IDs) │      │              │      │                 │
└──────────────┘      └──────────────┘      └─────────────────┘
                            │                        │
                            │                        ▼
                            │               ┌──────────────────────┐
                            │               │ semantic_descriptions│
                            │               │        .txt          │
                            │               └──────────────────────┘
                            │                        │
                            ▼                        │
                      ┌──────────────┐               │
                      │  get_summary │ <─────────────┘
                      │     .py      │               │   
                      └──────────────┘               │
                            │                        │
                            ▼                        │
                      ┌──────────────┐               │
                      │  summary.txt │               │
                      └──────────────┘               │
                            │                        │
                            ▼                        │
                      ┌─────────────────────┐        │
                      │ generate_questions  │  <─────┘
                      │     .py (LLM)       │
                      └─────────────────────┘
```

## Prerequisites

### Environment Setup

1. **Neo4j Database Connection**
   - Create a `.env` file in the root directory with:
     ```env
     NEO4J_URI=bolt://localhost:7687
     NEO4J_USER=neo4j
     NEO4J_PASSWORD=your_password
     ```

2. **Python Dependencies**
   ```bash
   pip install neo4j python-dotenv langchain langchain-community
   ```

3. **LLM Setup**
   - **Option A (Default)**: Local Ollama model `gpt-oss:120b` for now
     ```bash
     # Install Ollama and pull the model
     ollama pull gpt-oss:120b
     ```
   - **Option B**: OpenAI API (uncomment lines 28-36 in `generate_questions.py` and provide API key)

## Usage Guide

### Step 1: Extract Node Data (`getNodes.py`)

This script queries the Neo4j database to extract nodes and their relationships.

#### How to Use:

1. **Find Node IDs** in your Neo4j database

2. **Edit `getNodes.py`** (lines 290-294) and manually specify node IDs:
   ```python
   node_groups = [
       # ("783461",) # a node
       ("783461", "2382")  # Two connected nodes
       # ("3778", "782755", "6501")  # Three connected nodes
   ]
   ```

3. **Run the script**:
   ```bash
   python getNodes.py
   ```

4. **Output**: `nodes.json` file containing:
   - Filtered node properties (label-specific properties only)
   - Node labels
   - Relationship types between nodes
   
   **Note**: Only properties defined in `LABEL_PROPERTIES_MAP` for matching labels will be included

#### Supported Node ID Formats:
- **Numeric IDs** (old format): `"782755"` - supported by all functions
- **Element IDs** (new format): `"4:abc123:456"` - supported by 1-node and 2-node queries only

**Note**: The `get_three_connected_nodes()` function currently only supports numeric IDs. Use numeric IDs when querying 3 connected nodes.


### Step 2: Extract Semantic Descriptions (`get_semantic.py`)

This script extracts labels and relationships from `nodes.json` and retrieves their semantic descriptions from the UCKG configuration.

#### How to Use:

1. **Ensure `nodes.json` exists** (generated from Step 1)

2. **Ensure access to UCKG config**:
   - The script imports `CYBERSECURITY_SEMANTICS` from `text2cypher/config.py`
   - Make sure the path in line 7 is correct for your setup

3. **Run the script**:
   ```bash
   python get_semantic.py
   ```

4. **Output**: `semantic_descriptions.txt` containing:
   - Semantic descriptions for all labels found in nodes.json
   - Semantic descriptions for all relationship types found in nodes.json
   - Format: `LABEL_OR_RELATIONSHIP: description`

**Note**: The script automatically filters out the "Resource" label and only includes items that have definitions in `CYBERSECURITY_SEMANTICS`.


### Step 3: Generate Node Summaries (`get_summary.py`)

For now, this script uses OpenAI's LLM to generate human-readable summaries of the nodes extracted in Step 1. It creates natural language descriptions that are used as context for question generation.

#### How to Use:

1. **Ensure required files exist**:
   - `nodes.json` (generated from Step 1)
   - `semantic_descriptions.txt` (generated from Step 2)

2. **Run the script**:
   ```bash
   python get_summary.py
   ```

3. **Output**: `summary.txt` containing:
   - For 1 node: A 3-4 sentence summary explaining what the entity is, its characteristics, and significance
   - For 2 nodes: A 3-4 sentence summary explaining both entities, their relationship, and implications
   - For 3 nodes: A 4-5 sentence summary explaining all entities, relationships, and the pattern they form

#### Summary Features:
- Plain language (no technical jargon or property names)
- Context-aware using semantic descriptions
- Cybersecurity-focused explanations
- Different prompt templates for 1, 2, or 3 node patterns
- Automatic detection of node structure from `nodes.json`

#### Output Formats:
- **Text format** (default): Contains only summaries, one per line with double spacing
- **JSON format**: Full structured output with node data, relationships, and summaries


### Step 4: Generate Questions (`generate_questions.py`)

This script uses an LLM to generate evaluation questions based on the node summaries created in Step 3.

#### How to Use:

1. **Ensure required files exist**:
   - `semantic_descriptions.txt` (generated from Step 2)
   - `summary.txt` (generated from Step 3)
   - `questions.txt` (example questions for style reference)

2. **Select the appropriate prompt** (lines 44-242):
   - **0-hop prompt** (lines 44-101, currently active): For single nodes with no relationships
   - **1-hop prompt** (lines 104-168, currently commented out): For 2 connected nodes (Node1—Node2)
   - **2-hop prompt** (lines 170-242, currently commented out): For 3 connected nodes (Node1—Node2—Node3)
   - Comment/uncomment the appropriate prompt based on your `nodes.json` structure

3. **Configure LLM** (optional):
   - Default: Uses Ollama with `gpt-oss:120b`
   - To use OpenAI: Uncomment lines 28-36 and add your API key

4. **Run the script**:
   ```bash
   python generate_questions.py
   ```

5. **Output**: Generates 5 questions per node group with metadata

#### Question Generation Strategy

The script includes three different prompt templates optimized for different graph patterns:

**0-Hop Questions** (1 single node, currently active):
- Focuses on understanding a single entity
- Uses question type: `⟨s,*,*⟩`
- Questions ask about properties, characteristics, or context of the node itself
- No relationships involved
- Designed to test if the system can retrieve the correct node from thousands of candidates based on description matching

**1-Hop Questions** (2 connected nodes: Node1—Node2):
- Focuses on single-hop relationships
- Uses question types: `⟨s,p,*⟩`, `⟨s,*,o⟩`, `⟨s,p,o⟩`
- Object `o` refers to the second node

**2-Hop Questions** (3 connected nodes: Node1—Node2—Node3):
- Focuses on multi-hop reasoning across two relationships
- Primarily uses `⟨s,*,o⟩` structure
- Object `o` refers to the third (final) node
- Questions must require understanding of both relationships in the chain

Questions are categorized using **PolyG-style triple notation** `⟨s, p, o⟩`:

- **`⟨s,*,*⟩`** - General exploration of the first node
- **`⟨s,p,*⟩`** - Focus on a known predicate/relationship
- **`⟨s,*,o⟩`** - Relation discovery between known nodes
- **`⟨s,p,o⟩`** - Verification of specific predicate between nodes

Where:
- `s` (subject) = First node
- `p` (predicate) = Relationship type(s)
- `o` (object) = Final node in the chain

#### Question Quality Constraints:
- ≤ 25 words
- Natural analyst language (no technical field names)
- No raw IDs or URIs
- Diverse question structures
- Cybersecurity reasoning focus
- No yes/no questions

## File Descriptions

### Scripts

| File | Purpose | Input | Output |
|------|---------|-------|--------|
| `getNodes.py` | Extract nodes from Neo4j | User-specified node IDs | `nodes.json` |
| `get_semantic.py` | Extract semantic descriptions | `nodes.json`, UCKG config | `semantic_descriptions.txt` |
| `get_summary.py` | Generate node summaries | `nodes.json`, `semantic_descriptions.txt` | `summary.txt` |
| `generate_questions.py` | Generate evaluation questions | `semantic_descriptions.txt`, `summary.txt`, `questions.txt` | Console output (JSON) |

### Input Files

| File | Purpose | Source |
|------|---------|--------|
| `getNodes.py` | Extract nodes from Neo4j | User edits node IDs manually |
| `nodes.json` | Intermediate node data | Generated by `getNodes.py` |
| `questions.txt` | Example questions | Style reference for LLM |
| `semantic_descriptions.txt` | Cybersecurity semantics | Generated by `get_semantic.py` |

### Intermediate Files

| File | Content | Format |
|------|---------|--------|
| `nodes.json` | Extracted nodes & relationships | JSON |
| `semantic_descriptions.txt` | Label and relationship descriptions | Plain text |
| `summary.txt` | Human-readable node summaries | Plain text |

## Example Output Structure

### `nodes.json`:
```json
[
    {
        "node1": {
            "label": "CAPEC-256: SOAP Array Overflow",
            "ucoexDescription": "...",
            "labels": ["UcoexCAPEC"]
        },
        "node2": {
            "ucocweName": "Buffer Access with Incorrect Length Value",
            "labels": ["UcoCWE"]
        },
        "relationships": [
            {"type": "UCOEXHASRELATEDWEAKNESS"}
        ]
    }
]
```

### `semantic_descriptions.txt`:
```
UcoCWE: Common Weakness Enumeration - software weaknesses
UcoexCAPEC: Common Attack Pattern Enumeration and Classification
UCOEXHASRELATEDWEAKNESS: Links attack patterns to related weaknesses
```

### `summary.txt` (example for single node):
```
CWE-119 describes a fundamental weakness where software fails to properly restrict 
operations within memory buffer boundaries. This can lead to buffer overflows, 
out-of-bounds reads, and other memory corruption issues. It's a critical 
vulnerability class that enables various exploitation techniques.
```

### Expected Question Output (0-hop):
```json
{
   "question": "Which weakness involves improper operations within memory buffer boundaries?",
   "type": "<s,*,*>",
   "first_node": "CWE-119: Improper Restriction of Operations within the Bounds of a Memory Buffer",
   "context": "CWE-119 describes a fundamental weakness..."
}
```

### Expected Question Output (1-hop):
```json
{
   "question": "How does SOAP array overflow exploit buffer vulnerabilities?",
   "type": "<s,*,o>",
   "first_node": "CAPEC-256: SOAP Array Overflow",
   "relationship": "UCOEXHASRELATEDWEAKNESS",
   "second_node": "Buffer Access with Incorrect Length Value",
   "context": "CAPEC-256 is an attack pattern that exploits..."
}
```

### Expected Question Output (2-hop):
```json
{
   "question": "What risk scenarios arise when UNIX symlink handling weaknesses interact with container copy vulnerabilities in Kubernetes?",
   "type": "<s,*,o>",
   "first_node": "UNIX Symbolic Link (Symlink) Following",
   "relationship_1": "UCOHASWEAKNESS",
   "second_node": "UcoExploitTarget",
   "relationship_2": "UCOHASVULNERABILITY",
   "third_node": "Kubernetes kubectl cp vulnerability",
   "context": "UNIX symlink vulnerabilities can be exploited..."
}
```

## Node Property Filtering

The `filter_node_properties()` function uses **label-specific property filtering** based on a predefined mapping (`LABEL_PROPERTIES_MAP`). Only properties defined in the mapping for each label will be included in the output.

### Supported Labels and Properties:

| Label Pattern | Allowed Properties |
|--------------|-------------------|
| `CWE` | `ucocweSummary`, `ucocweExtendedSummary`, `ucocweName`, `uri` |
| `CVE` | `label`, `ucobaseSeverity`, `uri` |
| `Vulnerability` | `ucosummary`, `uri` |
| `CPE` | `cpeName`, `titles`, `uri` |
| `CAPEC` | `label`, `ucoexDescription`, `uri` |
| `ATT&CK` | `uri` |
| `Softwares` | `ucoexDESCRIPTION`, `ucoexDOMAIN`, `uri` |
| `Groups` | `ucoexDESCRIPTION`, `ucoexDOMAIN`, `uri` |
| `CAMPAIGNS` | `ucoexDESCRIPTION`, `ucoexDOMAIN`, `uri` |
| `MITIGATIONS` | `ucoexDESCRIPTION`, `ucoexDOMAIN`, `ucoexName`, `uri` |
| `MITREATTACK` | `ucoexDESCRIPTION`, `ucoexDOMAIN`, `ucoexName`, `uri` |
| `ObservedExample` | `ucoexDESCRIPTION`, `uri` |
| `TACTICS` | `ucoexDESCRIPTION`, `ucoexDOMAIN`, `uri` |
| `D3FEND` | `ucoexMITRED3FEND_DEFINITION`, `ucoexMITRED3FEND_LABEL`, `uri` |


## Troubleshooting

### Connection Issues
```
Failed to connect to Neo4j: ...
```
**Solution**: Verify `.env` file has correct Neo4j credentials and URI

### Node Not Found
```json
{"error": "Node not found", "node_id": "..."}
```
**Solution**: Verify node IDs exist in database using Cypher query

### LLM Errors
```
Error: Model not found
```
**Solution**: Ensure Ollama is running and model is pulled:
```bash
ollama serve
ollama pull gpt-oss:120b
```

## Customization

### Switch Between 0-Hop, 1-Hop, and 2-Hop Prompts
The script includes three prompt templates in `generate_questions.py`:
- **0-hop prompt**: Lines 44-101 (currently active)
- **1-hop prompt**: Lines 104-168 (currently commented out)
- **2-hop prompt**: Lines 170-242 (currently commented out)

To switch:
1. Comment out the active prompt
2. Uncomment the desired prompt
3. Ensure you're using the correct `nodes.json` structure (1, 2, or 3 nodes)
4. Re-run `get_semantic.py` and `get_summary.py` if your node structure changed

### Modify Question Style
Edit any of the prompt templates in `generate_questions.py` to change:
- Question length constraints
- Category types (⟨s,*,*⟩, ⟨s,p,*⟩, ⟨s,*,o⟩, ⟨s,p,o⟩)
- Focus and reasoning style
- Output format and metadata fields

### Modify Summary Generation
Edit the prompt templates in `get_summary.py` (lines 48-80, 111-149, 184-229) to change:
- Summary length and detail level
- Tone and style
- Focus areas (technical vs. practical)
- Context inclusion from semantic descriptions

### Change Node Properties Used
Edit the `LABEL_PROPERTIES_MAP` dictionary in `getNodes.py` (lines 28-43) to:
- Add new label patterns and their allowed properties
- Modify existing property lists for labels
- Add or remove properties for specific node types

Example:
```python
LABEL_PROPERTIES_MAP = {
    "CWE": ["ucocweSummary", "ucocweName"],  # Removed ucocweExtendedSummary
    "NewLabel": ["property1", "property2"]    # Added new label
}
```

### Customize Semantic Descriptions
To modify which semantic descriptions are included:
1. Edit the `CYBERSECURITY_SEMANTICS` dictionary in `text2cypher/config.py`
2. Add or modify descriptions for labels and relationships
3. Re-run `get_semantic.py` to regenerate `semantic_descriptions.txt`

### Add Support for More Nodes
Extend the functions in `getNodes.py` to support 4+ connected nodes by following the pattern of existing functions. You'll also need to:
1. Add a new summary function in `get_summary.py` for the new pattern
2. Create a new prompt template in `generate_questions.py` for multi-hop questions
