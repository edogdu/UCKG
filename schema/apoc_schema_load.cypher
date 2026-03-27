// ─────────────────────────────────────────────────────────────────────────────
// UCKG Semantic Schema — APOC apoc.load.json() loader
// ─────────────────────────────────────────────────────────────────────────────
//
// PRE-REQUISITE:
//   1. Copy the v3 schema JSON into Neo4j's import directory:
//        cp qa-engine/text2cypher/configt2c/semantic_schema_uckg_v3.json \
//           neo4j/import/semantic_schema_uckg_v3.json
//
//   2. Run this file in Neo4j Browser (paste all blocks) or via cypher-shell:
//        cypher-shell -u neo4j -p abcd90909090 \
//          --file qa-engine/text2cypher/core/apoc_schema_load.cypher
//
// Your docker-compose already has:
//   NEO4J_apoc_import_file_enabled: "true"
//   ./neo4j/import:/var/lib/neo4j/import
// so the JSON will be visible at  file:///var/lib/neo4j/import/...
// ─────────────────────────────────────────────────────────────────────────────

// ── 1. Schema singleton node ─────────────────────────────────────────────────
CALL apoc.load.json("file:///var/lib/neo4j/import/semantic_schema_uckg_v3.json")
YIELD value
MERGE (s:UCKGMeta_Schema {version: value.version})
SET   s.notes               = value.notes,
      s.embedding_corpus_size = size(value.embedding_corpus),
      s.last_loaded         = toString(datetime())
RETURN s.version AS schema_version;

// ── 2. Node types ────────────────────────────────────────────────────────────
CALL apoc.load.json("file:///var/lib/neo4j/import/semantic_schema_uckg_v3.json")
YIELD value
UNWIND value.nodes AS nd
MERGE (n:UCKGMeta_Node {semantic: nd.semantic})
SET   n.physical_label          = nd.physical_label,
      n.purpose                 = nd.purpose,
      n.description             = nd.description,
      n.key_identifier          = nd.key_identifier,
      n.key_identifier_example  = nd.key_identifier_example,
      n.triggers                = nd.typical_natural_language_triggers
WITH  n, value
MATCH (s:UCKGMeta_Schema {version: value.version})
MERGE (s)-[:META_HAS_NODE]->(n)
RETURN count(n) AS node_types_loaded;

// ── 3. Properties ────────────────────────────────────────────────────────────
CALL apoc.load.json("file:///var/lib/neo4j/import/semantic_schema_uckg_v3.json")
YIELD value
UNWIND value.nodes AS nd
UNWIND nd.properties AS prop
MERGE (p:UCKGMeta_Property {semantic: prop.semantic, belongs_to: nd.semantic})
SET   p.physical      = prop.physical,
      p.type          = prop.type,
      p.description   = prop.description,
      p.example       = toString(prop.example),
      p.query_pattern = prop.query_pattern
WITH  p, nd
MATCH (n:UCKGMeta_Node {semantic: nd.semantic})
MERGE (n)-[:META_HAS_PROPERTY]->(p)
RETURN count(p) AS properties_loaded;

// ── 4. Relationship triples ──────────────────────────────────────────────────
CALL apoc.load.json("file:///var/lib/neo4j/import/semantic_schema_uckg_v3.json")
YIELD value
UNWIND value.relationships AS rel
MERGE (r:UCKGMeta_Relationship {semantic: rel.semantic})
SET   r.physical_rel         = rel.physical_rel,
      r.domain_semantic      = rel.domain_semantic,
      r.domain_physical      = rel.domain_physical,
      r.range_semantic       = rel.range_semantic,
      r.range_physical       = rel.range_physical,
      r.description          = rel.description,
      r.traversal_direction  = rel.traversal_direction,
      r.cypher_pattern       = rel.cypher_pattern,
      r.triggers             = rel.natural_language_triggers,
      r.example_query        = rel.example_query
WITH  r, rel, value
MATCH (s:UCKGMeta_Schema {version: value.version})
MERGE (s)-[:META_HAS_RELATIONSHIP]->(r)
RETURN count(r) AS relationships_loaded;

// ── 5. META_CONNECTS_TO edges between node types ─────────────────────────────
CALL apoc.load.json("file:///var/lib/neo4j/import/semantic_schema_uckg_v3.json")
YIELD value
UNWIND value.relationships AS rel
MATCH (src:UCKGMeta_Node {semantic: rel.domain_semantic})
MATCH (tgt:UCKGMeta_Node {semantic: rel.range_semantic})
MERGE (src)-[e:META_CONNECTS_TO {via_semantic: rel.semantic}]->(tgt)
SET   e.via_physical   = rel.physical_rel,
      e.description    = rel.description,
      e.cypher_pattern = rel.cypher_pattern
RETURN count(e) AS connect_edges_loaded;

// ── 6. Traversal paths ───────────────────────────────────────────────────────
CALL apoc.load.json("file:///var/lib/neo4j/import/semantic_schema_uckg_v3.json")
YIELD value
UNWIND value.graph_traversal_paths AS path
MERGE (tp:UCKGMeta_TraversalPath {name: path.name})
SET   tp.description    = path.description,
      tp.cypher_pattern = path.cypher_pattern,
      tp.use_cases      = path.use_cases
WITH  tp, value
MATCH (s:UCKGMeta_Schema {version: value.version})
MERGE (s)-[:META_HAS_PATH]->(tp)
RETURN count(tp) AS paths_loaded;

// ── 7. Quick verification ────────────────────────────────────────────────────
MATCH (n:UCKGMeta_Node)
OPTIONAL MATCH (n)-[:META_HAS_PROPERTY]->(p:UCKGMeta_Property)
RETURN n.semantic AS node,
       n.physical_label AS physical_label,
       count(p) AS num_properties
ORDER BY n.semantic;
