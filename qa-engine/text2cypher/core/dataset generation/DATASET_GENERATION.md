# Dataset Generation Workflow with Gemini 2.5 Pro

## Overview
A two-stage process using Gemini 2.5 Pro to generate question-Cypher pairs with built-in quality validation through reverse generation.

---

## Input Files

**schema_cache.txt**
- Graph database schema (nodes, properties, relationships)

**CYBERSECURITY_SEMANTICS_COMPLETE.md**
- Detailed descriptions of each node label
- Property definitions with context
- Domain-specific guidance for question generation

---

## Stage 1: Generate Question-Cypher Pairs

### Prompt
```
Look at schema_cache.txt carefully. The content inside {} shows node properties 
and their format. Below that are the relationships between nodes.

Also review CYBERSECURITY_SEMANTICS_COMPLETE.txt to understand each node's purpose.

Create 90 unique, non-duplicate questions and Cypher queries across these categories:
- Node Lookup Queries
- Relationship Traversal Queries
- Multi-hop Queries
- Aggregation and Counting
- Conditional and Boolean Queries
- Path Queries (Variable-length)
- Graph Pattern Matching
- Comparative and Ranking
- Existence and Set Operations Queries

Output as CSV:
Category,NaturalLanguageQuestion,CypherQuery
```

### Output
CSV with 3 columns:
- `Category` - Query complexity type
- `NaturalLanguageQuestion` - Human-readable question
- `CypherQuery` - Corresponding Cypher query

---

## Stage 2: Reverse Generation (Cypher → Question)

### Prompt
```
From now on, I will provide 90 CSV rows.

Generate a 'CypherToQuestion' column from the 'CypherQuery' column.
Create questions as a cybersecurity analyst would ask them.

Output only the CypherToQuestion column with comma + newline for easy copying.

Format:
CypherToQuestion
```

### Process
1. Extract `CypherQuery` column from Stage 1 output
2. Feed to Gemini with second prompt
3. Receive `CypherToQuestion` column

### Final Output
CSV with 4 columns:
- `Category`
- `NaturalLanguageQuestion` *(original human question)*
- `CypherQuery` *(validated query)*
- `CypherToQuestion` *(question derived from Cypher)*

---

## Purpose of Two Questions

**Validation through semantic comparison:**
- `NaturalLanguageQuestion` = What user intended to ask
- `CypherToQuestion` = What the Cypher actually answers

If these align semantically → valid pair  
If these diverge → mismatch detected

---

## Next Steps

The 4-column dataset proceeds to:
1. **Duplicate detection** - Remove identical questions/queries
2. **Dataset enrichment** - Add helper columns (hops, properties, etc.)
3. **Full validation suite** - Schema, execution, relevance checks