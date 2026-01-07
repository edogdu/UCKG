# Category Dataset Overall Documentation

## Overview

The `Schema Validator` is a specialized analysis file designed to evaluate dataset coverage and validity across different categories. It checks whether questions in a categorized dataset adequately cover all elements of a graph schema (node labels, relationships, and properties), and validates that the expected elements in the dataset actually exist in the schema.

## Core Purpose

This file serves two primary functions:

1. **Validation** - Ensures that elements referenced in dataset entries (labels, relationships, properties) exist in the actual graph schema
2. **Coverage Analysis** - Identifies which schema elements are missing from each category of questions, helping to detect gaps in dataset coverage

## Class Structure

### Initialization

```python
SchemaValidator(schema_file)
```

**Parameters:**
- `schema_file`: Path to the schema cache file (same format as used by DatasetValidator)

**Initialization Process:**
1. Loads and parses the schema file
2. Extracts all node labels into a set
3. Extracts all relationship types into a set
4. Collects all properties from all nodes into a single set

**Attributes Created:**
- `self.schema` - Full schema dictionary with nodes and relationships
- `self.labels` - Set of all node label names
- `self.relationships` - Set of all relationship type names
- `self.properties` - Set of all property names across all nodes

### Schema Loading

The `_load_schema()` method uses the same parsing logic as the DatasetValidator:

**Expected Schema Format:**
```
NodeLabel {
  property1: type1,
  property2: type2
}
(:NodeA)-[:RELATIONSHIP_TYPE]->(:NodeB)
```

**Returns:** Dictionary with structure `{"nodes": {label: {prop: type}}, "relationships": set()}`

## Core Methods

### 1. Check CSV Expectations

`check_csv_expectations(csv_file)` validates that all expected elements in each dataset row exist in the schema.

**Process:**
1. Reads the CSV file with proper quote handling
2. For each row, parses the expected elements columns:
   - `ExpectedNodeLabels`
   - `ExpectedRelationshipTypes`
   - `ExpectedProperties`
3. Checks if each expected element exists in the schema
4. Records validation results for each row

**Returns:** DataFrame with columns:
- `Category` - The category of the question
- `LabelsValid` - Boolean indicating if all labels exist in schema
- `RelationshipsValid` - Boolean indicating if all relationships exist in schema
- `PropertiesValid` - Boolean indicating if all properties exist in schema
- `AllValid` - Boolean indicating if all checks passed

**Use Case:** Identifies queries that reference non-existent schema elements, which would cause execution failures.

### 2. Check CSV Coverage

`check_csv_coverage(csv_file)` analyzes what percentage of the schema is covered by questions in each category.

**Process:**
1. Groups dataset rows by `Category` column
2. For each category:
   - Aggregates all expected labels, relationships, and properties used
   - Compares aggregated elements against complete schema
   - Identifies which schema elements are missing from that category

**Returns:** DataFrame with columns per category:
- `Category` - Category name
- `LabelsCovered` - List of labels that appear in this category
- `LabelsMissing` - List of labels that don't appear in this category
- `RelationshipsCovered` - List of relationships that appear in this category
- `RelationshipsMissing` - List of relationships that don't appear in this category
- `PropertiesCovered` - List of properties that appear in this category
- `PropertiesMissing` - List of properties that don't appear in this category
- `AllLabelsCovered` - Boolean indicating if all schema labels are covered
- `AllRelsCovered` - Boolean indicating if all schema relationships are covered
- `AllPropsCovered` - Boolean indicating if all schema properties are covered
- `AllCovered` - Boolean indicating complete schema coverage

**Use Case:** Identifies gaps in dataset coverage to guide creation of additional questions for underrepresented schema elements.

### 3. Check CSV Coverage Detailed

`check_csv_coverage_detailed(csv_file, txt_output_path)` provides a more granular coverage analysis with property-level detail per node label.

**Enhanced Features:**
- Tracks which properties are used with which node labels
- Creates both CSV and human-readable TXT reports
- Provides property coverage breakdown per label (not just overall)

**Process:**
1. Groups dataset by category
2. For each category:
   - Tracks properties by the labels they're associated with
   - Creates a dictionary mapping labels to their used properties
3. Compares each label's used properties against schema's defined properties
4. Writes detailed missing elements report to TXT file

**TXT Report Format:**
```
Category: CategoryName
  Missing Labels: [label1, label2]
  Missing Relationships: [rel1, rel2]
  Missing Properties per Label:
    LabelName: [prop1, prop2, prop3]
    AnotherLabel: [prop4, prop5]

Category: NextCategory
  ...
```

**Returns:** DataFrame with columns:
- `Category` - Category name
- `LabelsMissing` - List of labels not covered
- `RelationshipsMissing` - List of relationships not covered
- `PropertiesMissingPerLabel` - Dictionary mapping labels to their missing properties
- `AllCovered` - Boolean indicating complete coverage

**Use Case:** Provides actionable insights for dataset expansion by showing exactly which properties of which nodes need more questions.

## Key Features

### Safe CSV Parsing

All methods use robust CSV reading with explicit quote handling:
```python
df = pd.read_csv(csv_file, quotechar='"', doublequote=True)
```

### Data Cleaning

The code handles malformed JSON strings in CSV columns:
```python
ast.literal_eval(row.get('ExpectedNodeLabels', '[]').replace('""', '"'))
```

This fixes double-quoted strings that may occur during CSV export/import cycles.

### Category-Based Analysis

All coverage methods group by the `Category` column, enabling:
- Comparison of coverage across different question types
- Targeted dataset expansion for specific categories
- Identification of over/under-represented categories

## Workflow Integration

### Typical Usage Flow

1. **Load Schema** - Initialize validator with schema file
2. **Run Expectations Check** - Validate that dataset references only existing schema elements
3. **Run Coverage Analysis** - Identify gaps in schema coverage
4. **Run Detailed Coverage** - Get granular property-level coverage report
5. **Generate Reports** - Save results as CSV and TXT files

### Output Files

The script generates three types of output files:

1. **Expectations CSV** - Row-by-row validation results
2. **Coverage Summary CSV** - Category-level coverage statistics
3. **Detailed Coverage CSV** - Property-level coverage data
4. **Human-Readable TXT** - Easy-to-read coverage report

## Differences from DatasetValidator

| Feature | DatasetValidator | SchemaValidator |
|---------|-----------------|-----------------|
| **Purpose** | Validates individual queries | Analyzes category coverage |
| **Scope** | Row-level validation | Category-level aggregation |
| **Schema Check** | Per-query element validation | Coverage gap identification |
| **Output** | Pass/fail logs per entry | Coverage statistics per category |
| **Neo4j** | Requires connection for execution tests | No database connection needed |
| **Focus** | Data quality and correctness | Dataset completeness |

## Use Cases

### 1. Dataset Gap Analysis

After generating questions for a dataset, use this tool to identify:
- Which categories have poor schema coverage
- Which node labels are underrepresented
- Which relationships are rarely queried
- Which properties are not being tested

### 2. Category Balance

Evaluate whether categories are balanced in terms of schema coverage:
- Do all categories exercise the full schema?
- Are some categories too narrow in scope?
- Which categories need expansion?

### 3. Schema Exercise Coverage

Determine how well your dataset exercises the entire schema:
- Are there "dead" schema elements never used in queries?
- Which schema elements need more question variations?
- Is coverage uniform or concentrated?

### 4. Quality Assurance

Validate that dataset entries reference valid schema elements:
- Catch typos in label names
- Identify non-existent relationship types
- Find references to removed properties

## Example Analysis Workflow

```python
# Initialize validator
validator = SchemaValidator('schema_cache.txt')

# Check if all dataset entries reference valid schema elements
validity_results = validator.check_csv_expectations('dataset.csv')
invalid_rows = validity_results[~validity_results['AllValid']]
print(f"Found {len(invalid_rows)} rows with invalid schema references")

# Analyze coverage gaps by category
coverage_results = validator.check_csv_coverage('dataset.csv')
incomplete_categories = coverage_results[~coverage_results['AllCovered']]
print(f"{len(incomplete_categories)} categories have incomplete coverage")

# Generate detailed report
detailed_results = validator.check_csv_coverage_detailed(
    'dataset.csv', 
    'coverage_report.txt'
)
```

## Practical Insights

### Understanding Coverage Gaps

**Missing Labels:** Indicates this category doesn't include questions about certain node types. May need questions like:
- "What are all the [MissingLabel]?"
- "Show me [MissingLabel] that..."

**Missing Relationships:** Indicates this category doesn't traverse certain paths. May need questions involving:
- Multi-hop queries using missing relationships
- Pattern matching with these relationships

**Missing Properties:** Most granular gap - shows which attributes aren't being queried. May need questions that:
- Filter by these properties
- Return these properties in results
- Aggregate or compare these properties

### Property Assignment Note

The detailed coverage method uses a simplified approach to assign properties to labels:

```python
# Assigns expected properties to all labels in the same query
for label in expected_labels:
    all_props_by_label[label].update(expected_props)
```

**Limitation:** If a query uses multiple labels, properties are assigned to all of them, which may not be accurate if properties belong to only one label.

**Impact:** May underreport missing properties if properties are incorrectly associated with labels they don't actually use in that query.

## Configuration

The main block demonstrates typical configuration:

```python
schema_file = 'schema_cache.txt'
csv_file = 'dataset.csv'
txt_output_path = 'coverage_report.txt'

validator = SchemaValidator(schema_file)
coverage_results = validator.check_csv_coverage(csv_file)
detailed_results = validator.check_csv_coverage_detailed(csv_file, txt_output_path)

# Save outputs
coverage_results.to_csv('coverage_results.csv', index=False)
detailed_results.to_csv('detailed_coverage.csv', index=False)
```

## Best Practices

1. **Run After Dataset Generation** - Use this tool after creating categorized questions to identify gaps before training

2. **Iterate on Coverage** - Generate additional questions for categories with poor coverage, then re-run analysis

3. **Combine with DatasetValidator** - First validate correctness with DatasetValidator, then analyze coverage with SchemaValidator

4. **Review TXT Reports** - The human-readable TXT output is easier for manual review than CSV files

5. **Track Coverage Over Time** - Save reports with timestamps to track dataset improvement across versions