CALL n10s.graphconfig.init({
  handleVocabUris: 'MAP',
  handleMultival: 'ARRAY',
  multivalPropList: [
    'http://example.com/ucoPrerequisites',
    'http://example.com/ucoRelatedWeaknesses'
  ],
  keepLangTag: true,
  keepCustomDataTypes: true,
  applyNeo4jNaming: true
});