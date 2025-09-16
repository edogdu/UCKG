# Getting Distinct Node Labels in Neo4j

## The Problem
When you run `CALL db.schema.nodetype properties` in Neo4j, you get duplicates because nodes can have multiple labels. For example:
```
":`FunctionalProperty`:`ObjectProperty`:`Resource`"
":`IrreflexiveProperty`:`ObjectProperty`:`Resource`"
":`DatatypeProperty`:`FunctionalProperty`:`ObjectProperty`:`Resource`"
```

## The Solution
Use these Cypher queries instead:

### 1. Get Just the Distinct Labels
```cypher
CALL db.labels() YIELD label
RETURN label
ORDER BY label;
```

### 2. Get Distinct Labels with Properties (Recommended)
```cypher
CALL db.labels() YIELD label
CALL {
  WITH label
  MATCH (n)
  WHERE n:label
  RETURN label, keys(n) as properties
  LIMIT 1
}
RETURN label, properties
ORDER BY label;
```

### 3. Get Distinct Labels with Node Counts
```cypher
CALL db.labels() YIELD label
CALL {
  WITH label
  MATCH (n)
  WHERE n:label
  RETURN label, count(n) as node_count
}
RETURN label, node_count
ORDER BY node_count DESC;
```

## Why This Works
- `CALL db.labels()` returns only the distinct labels that exist in your database
- It doesn't show label combinations, just the individual labels
- Each label appears only once, regardless of how many nodes have multiple labels

## Example Output
Instead of seeing:
```
":`FunctionalProperty`:`ObjectProperty`:`Resource`"
":`IrreflexiveProperty`:`ObjectProperty`:`Resource`"
```

You'll see:
```
"FunctionalProperty"
"IrreflexiveProperty" 
"ObjectProperty"
"Resource"
```

## Quick Test
Run this in Neo4j to see the difference:
```cypher
-- This shows duplicates (what you were getting)
CALL db.schema.visualization() YIELD nodes
UNWIND nodes as node
UNWIND node.labels as label
RETURN DISTINCT label
ORDER BY label;

-- This shows distinct labels (what you want)
CALL db.labels() YIELD label
RETURN label
ORDER BY label;
```

The second query will give you clean, distinct labels without duplicates! 