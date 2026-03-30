"""
Relationship Retriever for GraphRAG Pipeline

Vector search over relationship-level embeddings using the
`relationship_embedding_idx` index created by the embedding pipeline.

The retriever returns relationship items in a format compatible with the
existing node-retrieval item envelope so they can be merged via RRF.
"""

import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)


class RelationshipRetriever:
    """Vector search over MITRE ATT&CK relationship embeddings.

    Requires:
    - `relationship_embedding_idx` vector index to exist in Neo4j (created
      by the embedding pipeline after `embed_relationships()` runs).
    - Relationship edges to have `r.embedding` set.
    """

    def __init__(self, driver, config):
        """
        Args:
            driver: Active Neo4j driver instance.
            config: GraphRAGConfig (uses relationship_retrieval_top_k).
        """
        self.driver = driver
        self.config = config

    def retrieve(
        self,
        query_embedding: List[float],
        top_k: int,
    ) -> List[Dict[str, Any]]:
        """Search for relationships semantically similar to the query.

        Args:
            query_embedding: Embedding vector for the user query.
            top_k: Number of top relationship results to return.

        Returns:
            List of relationship item dicts in the standard pipeline envelope:
            {
                "primarySource": {
                    "nodeId": "<source_uri>|<target_uri>",
                    "nodeType": "Relationship",
                    "label": "<source_name> --[<mapping_type>]--> <target_name>",
                    "content": "<description>",
                    "score": <float>,
                    "allProperties": { ... }
                },
                "firstHopNeighbors": [],
                "score": <float>,
                "isRelationshipResult": True,
            }
        """
        # Discover all per-type relationship vector indexes (named rel_emb_*_idx)
        try:
            with self.driver.session() as session:
                result = session.run("""
                    SHOW VECTOR INDEXES YIELD name
                    WHERE name STARTS WITH 'rel_emb_'
                """)
                index_names = [record['name'] for record in result]
        except Exception as e:
            logger.warning("Failed to discover relationship vector indexes: %s", e)
            return []

        if not index_names:
            logger.warning("No relationship vector indexes found (prefix 'rel_emb_')")
            return []

        cypher = """
            CALL db.index.vector.queryRelationships(
                $index_name, $top_k, $query_embedding
            )
            YIELD relationship AS r, score
            MATCH (source)-[r]->(target)
            RETURN
                r.description      AS rel_description,
                r.mapping_type     AS mapping_type,
                r.description_type AS description_type,
                type(r)            AS rel_type,
                source.uri         AS source_uri,
                target.uri         AS target_uri,
                r.source_name      AS source_name,
                r.target_name      AS target_name,
                score
        """

        rows = []
        for index_name in index_names:
            try:
                with self.driver.session() as session:
                    result = session.run(
                        cypher,
                        index_name=index_name,
                        top_k=top_k,
                        query_embedding=query_embedding,
                    )
                    rows.extend([dict(record) for record in result])
            except Exception as e:
                logger.warning("RelationshipRetriever query on '%s' failed: %s", index_name, e)

        # Merge results from all indexes, keep top_k by score
        rows.sort(key=lambda x: float(x.get('score') or 0.0), reverse=True)
        rows = rows[:top_k]

        items = []
        for row in rows:
            source_name = row.get('source_name') or ''
            target_name = row.get('target_name') or ''
            mapping_type = row.get('mapping_type') or ''
            rel_type = row.get('rel_type') or ''
            description = row.get('rel_description') or ''
            score = float(row.get('score') or 0.0)
            source_uri = row.get('source_uri') or ''
            target_uri = row.get('target_uri') or ''

            label = f"{source_name} --[{mapping_type or rel_type}]--> {target_name}"
            composite_id = f"{source_uri}|{target_uri}"

            primary_source = {
                'nodeId':      composite_id,
                'nodeType':    'Relationship',
                'label':       label,
                'content':     description,
                'score':       score,
                'allProperties': {
                    'rel_type':         rel_type,
                    'mapping_type':     mapping_type,
                    'description':      description,
                    'description_type': row.get('description_type') or '',
                    'source_uri':       source_uri,
                    'target_uri':       target_uri,
                    'source_name':      source_name,
                    'target_name':      target_name,
                },
            }

            items.append({
                'primarySource':        primary_source,
                'firstHopNeighbors':    [],
                'score':                score,
                'isRelationshipResult': True,
            })

        logger.debug("RelationshipRetriever returned %d results", len(items))
        return items
