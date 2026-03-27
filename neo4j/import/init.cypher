CALL n10s.graphconfig.init({
  handleVocabUris: 'MAP',
  handleMultival: 'ARRAY',
  multivalPropList: [
      'http://example.com/ucoexRelatedAttPattern',
      'http://example.com/ucoexExecutionFlowTechnique',
      'http://example.com/ucoexPrerequisites',
      'http://example.com/ucoexSkills_Required',
      'http://example.com/ucoexResources_Required',
      'http://example.com/ucoexMitigations',
      'http://example.com/ucoexConsequences',
      'http://example.com/ucoexExample',
      'http://example.com/ucoexTaxonomyMappingATTACK',
      'http://example.com/ucoexRelatedWeaknesses',
      'http://example.com/ucoexExtendedDescription'
  ],
  keepLangTag: true,
  keepCustomDataTypes: true,
  applyNeo4jNaming: true
});

// ─── UCKG Semantic Schema metadata ───────────────────────────────────────────
// Load UCKGMeta_* nodes and edges on first container boot.
// Skipped silently if the schema node already exists (idempotent).
CALL apoc.cypher.runFile('uckg_semantic_schema.cypher') YIELD row, result RETURN row, result;