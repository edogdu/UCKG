# Text-to-Cypher Evaluation Framework

Comprehensive evaluation system for comparing Text-to-Cypher pipelines using multiple metrics across different query categories.

## 📊 Overview

This framework evaluates two T2C approaches:
1. **Full Schema Pipeline**: Uses complete graph schema
2. **Semantic Schema Pipeline (T2CSS)**: Uses semantically filtered schema

## 🎯 Evaluation Metrics

### 1. Cypher Text Similarity
Measures how similar the generated Cypher is to the gold standard:

- **Jaro-Winkler**: Character-level similarity (good for typos)
- **Jaccard (tokens)**: Token overlap similarity
- **ROUGE-L**: Longest common subsequence F1 score
- **BLEU-4**: N-gram precision (1-4 grams)

### 2. Output Correctness
Measures if the query produces correct results:

- **Pass@1**: Exact match between generated and gold output (binary: 0 or 1)
- **Jaccard Output Similarity**: Set-based similarity of result sets

### 3. Query Validation
Pre-execution validation without running the query:

- **KG Valid Query Rate**: Percentage of queries that pass:
  - Write clause guard (no CREATE/DELETE/etc.)
  - Syntax check (valid Cypher grammar)
  - Schema validation (labels and relationships exist)
  - Property validation (properties exist on entities)

### 4. Composite Metric
**LLMetric** combines all metrics with weights:

```
LLMetric = 0.3 × Pass@1 + 0.4 × KG_Valid_Rate + 0.2 × Jaccard_Output + 0.1 × JaRou_Factor
```

Where:
- `JaRou_Factor = (ROUGE-L + Token_F1 + Jaro-Winkler) / 3`

## 📁 Dataset

**File**: `dataset/technical_dataset_COMPLETION.csv`

**Size**: 388 questions across 9 categories

### Category Breakdown

| Category | Count | Percentage | Avg Query Length |
|----------|-------|------------|------------------|
| Node Lookup Queries | 173 | 44.6% | 71 chars |
| Relationship Traversal | 42 | 10.8% | 114 chars |
| Existence and Set Operations | 26 | 6.7% | 123 chars |
| Multi-hop Queries | 25 | 6.4% | 175 chars |
| Aggregation and Counting | 25 | 6.4% | 110 chars |
| Path Queries (Variable-length) | 25 | 6.4% | 108 chars |
| Graph Pattern Matching | 25 | 6.4% | 187 chars |
| Conditional and Boolean | 24 | 6.2% | 139 chars |
| Comparative and Ranking | 23 | 5.9% | 162 chars |

### Dataset Columns

- `Category`: Question type
- `NaturalLanguageQuestion`: User query
- `CypherQuery`: Gold standard Cypher
- `generated_question`: Alternative phrasing
- `ExpectedNodeLabels`: Expected node types
- `ExpectedRelationshipTypes`: Expected relationships
- `ExpectedProperties`: Expected properties
- `Hops`: Graph traversal depth
- `ExtractedPropertyValues`: Property values in query

## 🚀 Running Evaluation

### Full Evaluation (All 388 Questions)

```bash
python evaluate_models.py
```

**Expected time**: ~2 hours (20 seconds per question)

### Quick Test (Limited Questions)

```bash
EVAL_LIMIT=50 python evaluate_models.py
```

### Background Execution

```bash
nohup python evaluate_models.py > evaluation_run.log 2>&1 &
```

### Monitor Progress

```bash
./monitor_progress.sh
```

Or watch live:
```bash
tail -f evaluation_run_clean.log
```

## 📈 Output

### 1. Markdown Report

**File**: `report_llama3_full_vs_semantic.md`

Contains:
- Overall aggregated metrics
- Cypher text similarity comparison
- **Per-category performance breakdown**
- Category comparison summary
- Winner by category analysis

### 2. Console Output

Real-time progress bar showing:
- Questions processed
- Time per question
- ETA

### 3. Log Files

- `evaluation_run_clean.log`: Clean execution log
- `evaluation_run.log`: Verbose log (if T2CSS_VERBOSE=1)

## 📊 Dataset Analysis

### Jupyter Notebook

Explore the dataset before evaluation:

```bash
jupyter notebook dataset_analysis.ipynb
```

**Includes:**
- Category distribution visualizations
- Query complexity analysis
- Sample questions per category
- Hops and aggregation statistics
- Evaluation expectations and hypotheses

### Python Script

Quick analysis without Jupyter:

```python
import pandas as pd

df = pd.read_csv('../dataset/technical_dataset_COMPLETION.csv')
print(df['Category'].value_counts())
print(df.groupby('Category')['CypherQuery'].apply(lambda x: x.str.len().mean()))
```

## 🔧 Configuration

### Environment Variables

- `EVAL_LIMIT`: Limit number of questions (default: all 388)
- `T2CSS_VERBOSE`: Enable verbose T2CSS logging (0 or 1)

### Neo4j Connection

Edit in `evaluate_models.py`:
```python
NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "your_password"
```

### Model Selection

Currently evaluates:
- `llama3:instruct` via Ollama

To add more models, modify the script:
```python
# Add new model
new_llm = OllamaLLM(model="mistral:instruct")
new_pipeline = Text2Cypher(NEO4J_URI, NEO4J_USER, NEO4J_PASS, new_llm)
```

## 📝 Evaluation Process

For each question:

1. **Generate Cypher** with both pipelines
2. **Validate** generated queries (syntax, schema, properties)
3. **Execute** generated and gold queries
4. **Compare outputs** using all metrics
5. **Store results** by category

## 🎯 Expected Results

### Hypotheses

**Full Schema Pipeline:**
- ✅ Better on simple node lookups (clear patterns)
- ❌ Struggles with complex multi-hop queries (context overload)
- ❌ Lower KG Valid Rate (more schema confusion)

**Semantic Schema Pipeline (T2CSS):**
- ✅ Better on complex queries (focused schema)
- ✅ Higher KG Valid Rate (relevant schema only)
- ❌ May miss some simple queries (over-filtering)

### Performance by Category

**Expected High Performance:**
- Node Lookup Queries (simple patterns)
- Relationship Traversal (clear relationships)

**Expected Medium Performance:**
- Aggregation and Counting
- Conditional and Boolean
- Existence and Set Operations

**Expected Challenging:**
- Multi-hop Queries (3+ hops)
- Path Queries (variable-length)
- Graph Pattern Matching (complex patterns)
- Comparative and Ranking (sorting logic)

## 🐛 Troubleshooting

### Evaluation Hangs

- Check if Ollama is running: `ollama list`
- Check Neo4j connection: `cypher-shell`
- Monitor system resources

### Low Pass@1 Scores

- Normal for complex queries
- Focus on KG Valid Rate and output similarity
- Check if gold queries are correct

### Memory Issues

- Reduce `EVAL_LIMIT`
- Close other applications
- Use smaller embedding model

## 📚 References

- **T2CSS Paper**: "Prompting large language models based on semantic schema for text-to-Cypher transformation" (DSS 2025)
- **Validation**: Adapted from Neo4j GraphRAG examples
- **Metrics**: Standard NLP and IR metrics (BLEU, ROUGE, Jaccard, Jaro-Winkler)

## 🤝 Contributing

To add new metrics:
1. Implement metric function in `evaluate_models.py`
2. Add to evaluation loop
3. Include in report generation
4. Update this README

## 📧 Support

For issues or questions, please check:
1. Log files for error messages
2. Neo4j and Ollama status
3. Dataset format and completeness

