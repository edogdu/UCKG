-- Query 1: Get distinct node labels (equivalent to CALL db.labels())
CALL db.labels() YIELD label
RETURN label
ORDER BY label;

-- Query 2: Get distinct node types with their properties (no duplicates)
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

-- Query 3: Get distinct node types with property counts
CALL db.labels() YIELD label
CALL {
  WITH label
  MATCH (n)
  WHERE n:label
  RETURN label, size(keys(n)) as property_count
  LIMIT 1
}
RETURN label, property_count
ORDER BY label;

-- Query 4: Get distinct node types with sample properties (formatted)
CALL db.labels() YIELD label
CALL {
  WITH label
  MATCH (n)
  WHERE n:label
  RETURN label, [prop in keys(n) | prop] as properties
  LIMIT 1
}
RETURN label + ': ' + apoc.text.join(properties, ', ') as node_type_info
ORDER BY label;

-- Query 5: Alternative approach using UNWIND to get all properties for each label
CALL db.labels() YIELD label
MATCH (n)
WHERE n:label
WITH label, keys(n) as all_properties
UNWIND all_properties as prop
WITH label, collect(DISTINCT prop) as distinct_properties
RETURN label, distinct_properties
ORDER BY label; 