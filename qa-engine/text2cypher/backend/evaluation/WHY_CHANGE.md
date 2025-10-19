I was implementing the old method that I mentioned on the **UCKG issue**, but then I ran into a problem:

---

### Original Idea (from the paper)
- **Grammatical Validator** – check if Cypher queries work when run.  
- **Entity Validator** – check (via NER) if Cypher queries match the entities from the questions. *(Problem here)*  
- **Schema Validator** – check labels, nodes, and properties from the schema.

---

### The Problem
The issue arises with the **NER process** in the Entity Validator.  
A user can ask a simple question, but the properties needed in the Cypher query to work in Neo4j are different.

**Example:**

```
----- Validating Entry #2 -----
Question: Retrieve the details of the CWE with the ID 'CWE-89'.
Query: MATCH (c:UcoCWE {ucocweID: 'CWE-89'}) RETURN c.ucocweName, c.ucodescription
Grammar Check: PASS - Valid Cypher grammar.
NER Check: FAIL - Entities missing from Cypher: {'CWE', 'ID'}
Schema Check: PASS - Schema compliance check passed.
```

---

### Proposed Fix
To improve this, I plan to create three new columns (as suggested by Bill) to help the LLM understand Cypher structure better:

- `ExpectedNodeLabels`
- `ExpectedRelationshipTypes`
- `ExpectedProperties`

The **Hops** column simply counts how many hops the query performs — not relevant now, but potentially useful for LLM context.
---

### Current Dataset Generation Flow
1. Ask the LLM to output:
   - Question  
   - Cypher query  
   - The three columns above

**Problem:**  
If the generated Cypher query is incorrect, then the three new columns (`ExpectedNodeLabels`, `ExpectedRelationshipTypes`, `ExpectedProperties`) will also be wrong.

---

### Proposed 4-Stage Validation Solution
1. **Schema Check** – use schema to validate the Cypher’s labels, relationships, and properties.  
2. **Cypher Executability Check** – ensure the query can actually run in Neo4j.  
3. **Entity Extraction Check** – verify that `ExpectedNodeLabels`, `ExpectedRelationshipTypes`, and `ExpectedProperties` match the Cypher query.  
4. **Question-to-Query Relevance Check** – confirm that the question and query are semantically aligned, ensuring that when a user asks a question, the query produces the correct data.
