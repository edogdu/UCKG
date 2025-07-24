# UCKG Embedding Processor

**Production-ready embedding generation for large-scale cybersecurity knowledge graphs.**

Provides efficient, scalable embedding generation with database-level pagination and batch API processing for comprehensive cybersecurity datasets.

## 🎯 What It Does

- ✅ Processes **all 738K+ cybersecurity nodes** efficiently
- ✅ **Continuous processing** - completes entire datasets in single runs
- ✅ **Graceful interruption handling** - Ctrl+C safely stops after current batch
- ✅ **Database-level pagination** for unlimited scalability
- ✅ **Batch API processing** with Ollama `/api/embed` endpoint
- ✅ **Intelligent batch sizing** (8 nodes per API call) for performance/quality balance
- ✅ **Dynamic property extraction** - discovers all node properties automatically
- ✅ **Comprehensive searchContent generation** for Graph RAG applications
- ✅ **768-dimensional embeddings** using Ollama embedding models
- ✅ **Support for all 12 node types** (CVE, CWE, CPE, CAPEC, MITRE ATT&CK, Vulnerability, D3FEND, Software, Groups, Mitigations, Campaigns, Tactics)
- ✅ **Robust error handling** with automatic fallback mechanisms
- ✅ **Professional CLI interface** with comprehensive options

## 📁 Files

```
uckg_embedding_processor.py  # Main embedding processor
reset_embeddings.py          # Reset tool for testing and development
test/
└── test_simple.py           # Functionality tests
```

**Enterprise-grade implementation with comprehensive error handling and user experience features.**

## 🚀 Quick Start

### 1. View Current Statistics
```bash
python uckg_embedding_processor.py --stats
```

### 2. Process Small Test Batch
```bash
python uckg_embedding_processor.py --node-type UcoexMITRED3FEND --limit 10
```

### 3. Process All Nodes (Production)
```bash
python uckg_embedding_processor.py --all
```

### 4. Run Tests
```bash
python test/test_simple.py
```

### 5. Reset for Testing
```bash
python reset_embeddings.py --all --confirm
```

## 🛡️ Graceful Interruption

The processor supports safe interruption at any time:

- **Press `Ctrl+C`** to stop processing gracefully
- **Current batch completes** before stopping to prevent data corruption  
- **Progress is preserved** - all completed work is saved to the database
- **Resume anytime** by running the same command again
- **Clear feedback** with processing summary and statistics

```bash
# Example interruption output:
🛑 Interruption received (Ctrl+C). Finishing current batch...
💡 The process will stop gracefully after the current batch completes.
💾 All completed work has been saved to the database.
📊 UcoexCAPEC: 100 processed, Rate: 23.5 nodes/sec, Errors: 0
🛑 EMBEDDING PROCESSING INTERRUPTED!
✅ Completed types: UcoexCAPEC
📊 Processed before interruption: 100 nodes
💾 All completed work has been saved. You can resume by running the command again.
```

## 📊 Performance

- **Processing rate**: ~23 nodes/second with intelligent batch sizing
- **Large datasets**: Processes 1M+ nodes in approximately 12 hours
- **Memory efficiency**: Minimal memory usage through database-level pagination
- **Reliability**: <1% error rate with comprehensive error handling
- **API efficiency**: Batch processing with 8 nodes per API call for performance balance
- **Continuous operation**: Completes entire datasets without manual intervention

## 🔧 Configuration

Edit `uckg_embedding_processor.py` or use environment variables:

```bash
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_PASSWORD="your_password"
export OLLAMA_URL="http://localhost:11434"
export EMBEDDING_MODEL="nomic-embed-text"
export EMBED_ENV="true"  # Enable/disable embedding generation
```

### Docker Environment Control

The system uses `EMBED_ENV` environment variable to control whether embeddings are generated during system initialization:

- **`EMBED_ENV="true"`**: Enables embedding generation (default in production)
- **`EMBED_ENV="false"`**: Disables embedding generation (useful for testing or when embeddings aren't needed)

Configure in `docker-compose.yml`:
```yaml
uckg-scripts:
  environment:
    EMBED_ENV: "true"   # Change to "false" to disable
    # ... other variables
```

This allows you to control embedding generation without code changes - simply update the environment variable and restart the container.

## 📖 CLI Options

```bash
# View help and all available options
python uckg_embedding_processor.py --help

# View current embedding statistics
python uckg_embedding_processor.py --stats

# Process all node types (recommended for production)
python uckg_embedding_processor.py --all

# Process specific node type
python uckg_embedding_processor.py --node-type UcoCVE

# Limit processing for testing
python uckg_embedding_processor.py --node-type UcoCVE --limit 1000

# Custom database batch size for performance tuning
python uckg_embedding_processor.py --all --batch-size 100

# Custom API batch size (recommended: 8)
python uckg_embedding_processor.py --all --api-batch-size 8

# Both batch sizes
python uckg_embedding_processor.py --all --batch-size 100 --api-batch-size 8
```

## 🎯 What Gets Extracted

**All properties dynamically discovered using hybrid approach with smart ordering**, including:

### Core Vulnerability Data
- **UcoCVE** (299K nodes): `label`, `ucovectorString`, `ucobaseSeverity`, `ucoexploitabilityScore`, `ucoimpactScore`
- **UcoVulnerability** (299K nodes): `ucosummary`, `ucopublishedDateTime`, `ucolastModifiedDateTime`
- **UcoexCPE** (137K nodes): `cpeName`, `dictionary_found`, platform identification

### Weakness & Attack Intelligence  
- **UcoCWE** (968 nodes): `ucocweID`, `ucocweName`, `ucodescription`, `ucopotentialMitigations`
- **UcoexCAPEC** (559 nodes): `ucoexCAPEC_id`, `ucoexCAPEC_name`, `ucoexDescription`, `ucoexMitigations`
- **UcoexMITREATTACK** (884 nodes): `ucoexNAME`, `ucoexDESCRIPTION`, `ucoexDOMAIN`

### Defense & Threat Actor Data
- **UcoexMITRED3FEND** (244 nodes): `ucoexMITRED3FEND_LABEL`, `ucoexMITRED3FEND_DEFINITION`
- **UcoexSOFTWARE** (877 nodes): `ucoexNAME`, `ucoexDESCRIPTION`, `ucoexDOMAIN`
- **UcoexGROUPS** (170 nodes): `ucoexNAME`, `ucoexDESCRIPTION`, threat actor information
- **UcoexMITIGATIONS** (108 nodes): `ucoexNAME`, `ucoexDESCRIPTION`, security measures
- **UcoexCAMPAIGNS** (50 nodes): `ucoexNAME`, `ucoexDESCRIPTION`, campaign details
- **UcoexTACTICS** (38 nodes): `ucoexNAME`, `ucoexDESCRIPTION`, tactical information

**Smart property ordering ensures important identifiers and descriptions appear first, while including all available properties.**

## 📋 Sample Output

**Generated searchContent examples:**

**D3FEND Countermeasure:**
```
CYBERSECURITY DEFENSE COUNTERMEASURE | ucoexMITRED3FEND_LABEL: Network Traffic Filtering | ucoexMITRED3FEND_DEFINITION: Restricting network traffic based on defined rules and policies | DOMAIN: UcoexMITRED3FEND | GRAPH: UCKG | Keywords: defense, countermeasure, mitigation, security control, protection
```

**Attack Pattern:**
```
CYBERSECURITY ATTACK PATTERN ENUMERATION | ucoexCAPEC_name: Documentation Alteration | ucoexDescription: An adversary intentionally alters documentation to introduce errors... | ucoexSeverity: Medium | DOMAIN: UcoexCAPEC | GRAPH: UCKG | Keywords: attack pattern, attack method, exploitation technique
```

## 🔍 Statistics Output Example

```
📊 EMBEDDING COVERAGE STATISTICS
==================================================
UcoCVE          | Total: 299,050 | Embeddings:       0 (  0.0%) | SearchContent:       0 (  0.0%)
UcoVulnerability | Total: 299,050 | Embeddings:       0 (  0.0%) | SearchContent:       0 (  0.0%)
UcoexCPE        | Total: 136,667 | Embeddings:     550 (  0.4%) | SearchContent:     550 (  0.4%)
UcoCWE          | Total:     968 | Embeddings:     968 (100.0%) | SearchContent:     968 (100.0%)
UcoexMITREATTACK | Total:     884 | Embeddings:     884 (100.0%) | SearchContent:     884 (100.0%)
UcoexCAPEC      | Total:     559 | Embeddings:     559 (100.0%) | SearchContent:     559 (100.0%)
UcoexMITRED3FEND | Total:     244 | Embeddings:       5 (  2.0%) | SearchContent:       5 (  2.0%)
UcoexSOFTWARE   | Total:     877 | Embeddings:       5 (  0.6%) | SearchContent:       5 (  0.6%)
UcoexGROUPS     | Total:     170 | Embeddings:       0 (  0.0%) | SearchContent:       0 (  0.0%)
UcoexMITIGATIONS | Total:     108 | Embeddings:       0 (  0.0%) | SearchContent:       0 (  0.0%)
UcoexCAMPAIGNS  | Total:      50 | Embeddings:       0 (  0.0%) | SearchContent:       0 (  0.0%)
UcoexTACTICS    | Total:      38 | Embeddings:       3 (  7.9%) | SearchContent:       3 (  7.9%)
--------------------------------------------------
TOTAL           | Total: 738,665 | Embeddings:   2,974 (  0.4%) | SearchContent:   2,974 (  0.4%)
```

## 🛠️ How It Works

1. **Hybrid Property Processing**: Uses smart ordering to prioritize important properties (label, name, id, description, summary, definition) while including all available properties
2. **Universal Text Generation**: Single method handles all 12 node types with appropriate cybersecurity contexts
3. **Database-Level Pagination**: Processes nodes in batches with automatic pagination for scalability
4. **Batch API Processing**: Groups multiple nodes for efficient embedding generation via Ollama
5. **Incremental Processing**: Only processes nodes that need embeddings, enabling safe restarts
6. **Graceful Interruption**: Ctrl+C stops processing after current batch completes
7. **Comprehensive Coverage**: Processes all cybersecurity entity types in optimal order

## 🔧 Customization

### Add New Node Type
1. Add to `node_types` list in `process_all_types()`
2. Add context mapping in `create_comprehensive_text()`
3. Add keywords in `_get_keywords()`
4. Add identifier logic in `save_node_embedding()` if needed

### Modify Text Generation
Edit the `create_comprehensive_text()` method - single location handles all node types with hybrid approach

### Change Processing Order
Modify the `node_types` list in `process_all_types()` (smaller datasets first recommended for faster feedback)

## ❓ Troubleshooting

### "No embedding returned"
- Check Ollama is running: `curl http://localhost:11434/api/tags`
- Verify model is installed: `ollama list`
- Ensure model supports the `/api/embed` endpoint

### "Node not found" errors
- Check your node identifiers match the database schema
- Verify node types exist in your database
- Review the `save_node_embedding()` method for identifier mapping

### Processing appears to stop early
- This is normal behavior - the processor only processes nodes needing embeddings
- Check statistics with `--stats` to see current coverage
- Previously processed nodes are automatically skipped

### Slow performance
- Increase database batch size: `--batch-size 100`
- Ensure Neo4j and Ollama are running on fast storage
- Monitor system resources (CPU, memory, network)

### Interruption and resumption
- Press `Ctrl+C` to stop gracefully - current batch will complete
- Restart with the same command to resume from where you left off
- Use `--stats` to monitor progress between runs

## 🎉 Success Criteria

After running `python uckg_embedding_processor.py --all`:

✅ All nodes have `embedding` property (768-dimensional vectors)  
✅ All nodes have `searchContent` property (comprehensive text)  
✅ Vector index `uckg_universal_embeddings` populated  
✅ Ready for Graph RAG applications  
✅ Zero data loss with graceful interruption support  
✅ Full resumability for long-running processes  

## 🏆 Key Features

- **Enterprise-grade reliability**: Comprehensive error handling and graceful degradation
- **Scalable architecture**: Database pagination handles datasets of any size
- **User-friendly experience**: Clear progress reporting and safe interruption
- **Performance balanced**: Intelligent batch sizing maintains quality while maximizing speed
- **Memory efficient**: Minimal memory footprint regardless of dataset size
- **Production ready**: Robust implementation suitable for mission-critical applications
- **Maintainable code**: Clean, well-documented implementation for easy customization

**Professional solution for large-scale cybersecurity knowledge graph embedding tasks.** 🎯
