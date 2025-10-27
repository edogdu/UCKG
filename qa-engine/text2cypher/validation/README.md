# Validation Module

Pre-execution Cypher query validation system.

## 📁 Structure

```
validation/
├── __init__.py
├── noexec_validator.py          ⭐ Main validation logic
└── utils/
    └── regex_patterns.py         Regex patterns for parsing
```

## 🎯 Purpose

Validates Cypher queries **WITHOUT executing them** to ensure:
- ✅ No write operations (CREATE, DELETE, MERGE, etc.)
- ✅ Valid Cypher syntax
- ✅ Schema correctness (labels and relationships exist)
- ✅ Property existence (properties exist on nodes/relationships)

## 🚀 Usage

### Basic Validation

```python
from validation.noexec_validator import validate_cypher_noexec
from neo4j import GraphDatabase

# Connect to Neo4j
driver = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "password"))

# Validate a query
cypher_query = "MATCH (c:UcoCVE) RETURN c LIMIT 10"
is_valid, errors = validate_cypher_noexec(driver, cypher_query)

if is_valid:
    print("✅ Query is valid!")
    # Safe to execute
    with driver.session() as session:
        result = session.run(cypher_query)
        print(result.data())
else:
    print("❌ Query validation failed:")
    for error in errors:
        print(f"  - {error}")
```

### In Evaluation Pipeline

```python
# From evaluation/evaluate_models.py
from validation.noexec_validator import validate_cypher_noexec

# Validate generated queries
full_kg_ok, _ = validate_cypher_noexec(driver, generated_query)

# Track validation rate
kg_valid_rate = (valid_count / total_count) * 100
```

## 🔍 Validation Steps

### 1. Write Clause Guard

Blocks queries containing write operations:
- `CREATE`
- `MERGE`
- `DELETE`
- `DETACH DELETE`
- `SET`
- `REMOVE`
- `FOREACH`
- `LOAD CSV`
- `CALL dbms`

**Example:**
```python
cypher = "CREATE (n:Node) RETURN n"
is_valid, errors = validate_cypher_noexec(driver, cypher)
# Returns: (False, ["Contains write clause: CREATE"])
```

### 2. Syntax Check

Uses `EXPLAIN` to verify Cypher grammar without execution:

```python
cypher = "MATCH (n:Node RETURN n"  # Missing closing parenthesis
is_valid, errors = validate_cypher_noexec(driver, cypher)
# Returns: (False, ["Syntax error: ..."])
```

### 3. Schema Validation

Checks that node labels and relationship types exist in the database:

```python
cypher = "MATCH (n:NonExistentLabel) RETURN n"
is_valid, errors = validate_cypher_noexec(driver, cypher)
# Returns: (False, ["Label 'NonExistentLabel' not found in database"])
```

### 4. Property Validation

Verifies that properties exist on the specified nodes/relationships:

```python
cypher = "MATCH (n:UcoCVE {nonExistentProp: 'value'}) RETURN n"
is_valid, errors = validate_cypher_noexec(driver, cypher)
# Returns: (False, ["Property 'nonExistentProp' not found on label 'UcoCVE'"])
```

## 📊 Return Values

```python
is_valid, errors = validate_cypher_noexec(driver, cypher_query)
```

**Returns:**
- `is_valid` (bool): `True` if query passes all checks, `False` otherwise
- `errors` (List[str]): List of error messages (empty if valid)

## 🎯 Use Cases

### 1. Pre-execution Safety Check

```python
def safe_execute(driver, cypher):
    is_valid, errors = validate_cypher_noexec(driver, cypher)
    if not is_valid:
        raise ValueError(f"Invalid query: {errors}")
    
    with driver.session() as session:
        return session.run(cypher).data()
```

### 2. LLM-Generated Query Validation

```python
# Generate query with LLM
generated_cypher = llm.generate_cypher(user_question)

# Validate before execution
is_valid, errors = validate_cypher_noexec(driver, generated_cypher)

if is_valid:
    results = execute_query(generated_cypher)
else:
    # Retry generation or return error to user
    print(f"Generated query failed validation: {errors}")
```

### 3. Evaluation Metrics

```python
# Calculate KG Valid Query Rate
valid_queries = 0
total_queries = len(dataset)

for question in dataset:
    generated = model.generate(question)
    is_valid, _ = validate_cypher_noexec(driver, generated)
    if is_valid:
        valid_queries += 1

kg_valid_rate = (valid_queries / total_queries) * 100
print(f"KG Valid Query Rate: {kg_valid_rate:.1f}%")
```

## 🔧 Implementation Details

### Entity Extraction

The validator extracts entities from Cypher using regex patterns:

```python
from validation.utils.regex_patterns import (
    get_node_pattern,
    get_relationship_pattern,
    get_property_pattern,
)
```

### Schema Checks

Direct Neo4j queries to verify existence:

```python
# Check if label exists
MATCH (n:`UcoCVE`) RETURN 1 LIMIT 1

# Check if relationship type exists
MATCH ()-[r:`UCOHASWEAKNESS`]-() RETURN 1 LIMIT 1

# Check if property exists on label
MATCH (n:`UcoCVE`) WHERE n.`label` IS NOT NULL RETURN 1 LIMIT 1
```

## ⚠️ Limitations

1. **Does not execute queries**: Cannot validate runtime errors or result correctness
2. **Schema-dependent**: Requires access to the Neo4j database
3. **Pattern-based extraction**: May miss complex or nested patterns
4. **No semantic validation**: Does not check if query logic matches intent

## 🎓 Best Practices

1. **Always validate before execution** in production
2. **Log validation errors** for debugging and improvement
3. **Use in evaluation pipelines** to measure query quality
4. **Combine with execution validation** for comprehensive checking
5. **Handle validation errors gracefully** in user-facing applications

## 📚 References

- Neo4j Cypher Manual: https://neo4j.com/docs/cypher-manual/
- EXPLAIN clause: https://neo4j.com/docs/cypher-manual/current/query-tuning/basic-example/
- Neo4j Python Driver: https://neo4j.com/docs/python-manual/

## 🤝 Contributing

To extend validation:
1. Add new check functions in `noexec_validator.py`
2. Update `validate_cypher_noexec()` to call new checks
3. Add regex patterns to `utils/regex_patterns.py` if needed
4. Update this README with examples

