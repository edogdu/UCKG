-- Query 1: Get distinct node labels (this replaces db.schema.nodetype properties)
CALL db.labels() YIELD label
RETURN label
ORDER BY label;

-- Query 2: Get distinct node labels with their properties (equivalent to db.schema.nodetype properties but without duplicates)
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

-- Query 3: Get distinct node labels with properties in a more readable format
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

-- Query 4: Alternative approach - get all properties for each distinct label
CALL db.labels() YIELD label
MATCH (n)
WHERE n:label
WITH label, keys(n) as all_properties
UNWIND all_properties as prop
WITH label, collect(DISTINCT prop) as distinct_properties
RETURN label, distinct_properties
ORDER BY label;

-- Query 5: Get node count for each distinct label
CALL db.labels() YIELD label
CALL {
  WITH label
  MATCH (n)
  WHERE n:label
  RETURN label, count(n) as node_count
}
RETURN label, node_count
ORDER BY node_count DESC;

-- Query 6: Get distinct labels with sample node properties (most comprehensive)
CALL db.labels() YIELD label
CALL {
  WITH label
  MATCH (n)
  WHERE n:label
  RETURN label, keys(n) as properties, count(n) as node_count
  LIMIT 1
}
RETURN label, properties, node_count
ORDER BY label; 