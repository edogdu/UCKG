"""
Retrieval Module for GraphRAG Pipeline
Handles Stages 1 & 2: Semantic search + Graph traversal
"""

from typing import List, Dict, Any
from neo4j_graphrag.retrievers import VectorCypherRetriever
from neo4j_graphrag.embeddings import OllamaEmbeddings
from .utils import GraphRAGConfig, INDEX_NAME


class GraphRetriever:
    """
    Handles Stages 1 & 2: Semantic search + Graph traversal

    Stage 1: Vector similarity search to find initial candidate nodes
    Stage 2: Graph traversal to enrich each candidate with 1-hop neighbors (and optionally 2-hop)
    """

    def __init__(self, driver, config: GraphRAGConfig):
        """
        Initialize the GraphRetriever

        Args:
            driver: Neo4j database driver
            config: GraphRAGConfig with retrieval parameters
        """
        self.driver = driver
        self.config = config
        self.embedder = OllamaEmbeddings(model="nomic-embed-text:latest")
        self._current_hop_depth = 1  # Default to 1-hop

    def retrieve(self, query: str, top_k: int, hop_depth: int = None) -> List[Dict]:
        """
        Execute combined semantic search + graph traversal

        Args:
            query: User query string
            top_k: Number of results to return
            hop_depth: Graph traversal depth (0=semantic only, 1=1-hop, 2=2-hop)
                      If None, uses config.enable_second_hop

        Returns:
            List of items with primary nodes and their graph neighbors
        """
        # Set hop depth
        if hop_depth is not None:
            self._current_hop_depth = hop_depth
        else:
            self._current_hop_depth = 2 if self.config.enable_second_hop else 1

        # Fetch extra candidates for reranking stage (if > 0-hop)
        if self._current_hop_depth == 0:
            initial_top_k = top_k  # No reranking, fetch exactly what we need
        else:
            initial_top_k = top_k * self.config.initial_top_k_multiplier

        print(f"[Retriever] Executing {self._current_hop_depth}-hop retrieval (fetching {initial_top_k} candidates)")

        # Build and execute query
        retrieval_query = self._build_query()
        retriever = VectorCypherRetriever(
            driver=self.driver,
            index_name=INDEX_NAME,
            retrieval_query=retrieval_query,
            embedder=self.embedder,
            result_formatter=lambda rec: rec["item"]
        )

        results = retriever.search(query_text=query, top_k=initial_top_k)

        # Convert to list format
        if hasattr(results, 'items'):
            result_list = []
            for item in results.items:
                if hasattr(item, '__dict__'):
                    result_dict = item.__dict__
                elif hasattr(item, 'content') and hasattr(item, 'metadata'):
                    result_dict = {
                        'content': item.content,
                        'metadata': item.metadata,
                        'score': getattr(item, 'score', 0.0)
                    }
                else:
                    result_dict = item
                result_list.append(result_dict)
            return result_list
        elif hasattr(results, 'results'):
            return list(results.results)
        else:
            return []

    def _build_query(self) -> str:
        """Build Cypher query based on current hop depth"""
        if self._current_hop_depth == 0:
            return self._build_zero_hop_query()
        elif self._current_hop_depth == 1:
            return self._build_one_hop_query()
        else:  # 2-hop
            return self._build_two_hop_query()

    def _build_zero_hop_query(self) -> str:
        """
        Build 0-hop query: Semantic search only (no graph traversal)

        Returns structured data compatible with VectorCypherRetriever format
        """
        return """
            // STAGE 1: Semantic search only (no graph traversal for 0-hop)
            WITH node, score,
                id(node) as nodeId,
                labels(node) as nodeLabels,
                properties(node) as allNodeProperties,
                [label IN labels(node) WHERE label <> 'Resource'][0] as nodeType

            // Extract node label and content based on type
            WITH nodeId, nodeLabels, allNodeProperties, nodeType, score,
                CASE nodeType
                    WHEN 'UcoCWE' THEN allNodeProperties.ucocweName
                    WHEN 'UcoCVE' THEN allNodeProperties.label
                    WHEN 'UcoVulnerability' THEN COALESCE(allNodeProperties.label, allNodeProperties.uri)
                    WHEN 'UcoexCAPEC' THEN allNodeProperties.label
                    WHEN 'UcoexMITREATTACK' THEN allNodeProperties.ucoexNAME
                    WHEN 'UcoexMITIGATIONS' THEN allNodeProperties.ucoexNAME
                    WHEN 'UcoexSOFTWARE' THEN allNodeProperties.label
                    WHEN 'UcoexGROUPS' THEN allNodeProperties.ucoexNAME
                    WHEN 'UcoexCAMPAIGNS' THEN allNodeProperties.ucoexNAME
                    WHEN 'UcoexCPE' THEN allNodeProperties.cpeName
                    WHEN 'UcoexObservedExample' THEN COALESCE(allNodeProperties.label, allNodeProperties.uri)
                    WHEN 'UcoexTACTICS' THEN allNodeProperties.ucoexNAME
                    WHEN 'UcoexMITRED3FEND' THEN allNodeProperties.ucoexMITRED3FEND_LABEL
                    ELSE COALESCE(allNodeProperties.label, allNodeProperties.uri)
                END as displayLabel,
                CASE nodeType
                    WHEN 'UcoCWE' THEN COALESCE(allNodeProperties.ucocweExtendedSummary, allNodeProperties.ucocweSummary, '')
                    WHEN 'UcoCVE' THEN COALESCE(allNodeProperties.ucosummary, allNodeProperties.ucobaseSeverity, '')
                    WHEN 'UcoVulnerability' THEN COALESCE(allNodeProperties.ucosummary, '')
                    WHEN 'UcoexCAPEC' THEN COALESCE(allNodeProperties.ucoexDescription, '')
                    WHEN 'UcoexMITREATTACK' THEN COALESCE(allNodeProperties.ucoexDESCRIPTION, '')
                    WHEN 'UcoexMITIGATIONS' THEN COALESCE(allNodeProperties.ucoexDESCRIPTION, '')
                    WHEN 'UcoexSOFTWARE' THEN COALESCE(allNodeProperties.ucoexDESCRIPTION, '')
                    WHEN 'UcoexGROUPS' THEN COALESCE(allNodeProperties.ucoexDESCRIPTION, '')
                    WHEN 'UcoexCAMPAIGNS' THEN COALESCE(allNodeProperties.ucoexDESCRIPTION, '')
                    WHEN 'UcoexCPE' THEN COALESCE(allNodeProperties.cpeName, '')
                    WHEN 'UcoexObservedExample' THEN COALESCE(allNodeProperties.ucoexDESCRIPTION, '')
                    WHEN 'UcoexTACTICS' THEN COALESCE(allNodeProperties.ucoexDESCRIPTION, allNodeProperties.ucoexDOMAIN, allNodeProperties.ucoexNAME, '')
                    WHEN 'UcoexMITRED3FEND' THEN COALESCE(allNodeProperties.ucoexMITRED3FEND_DEFINITION, allNodeProperties.ucoexMITRED3FEND_LABEL, '')
                    ELSE ''
                END as nodeContent

            // Return structured data matching VectorCypherRetriever format
            RETURN {
                content: nodeContent,
                metadata: {
                    primarySource: {
                        nodeId: nodeId,
                        nodeLabel: displayLabel,
                        nodeType: nodeType,
                        nodeContent: nodeContent,
                        embedding: allNodeProperties.embedding,
                        initialScore: score,
                        score: score,
                        allProperties: allNodeProperties
                    },
                    firstHopNeighbors: []  // No neighbors for 0-hop
                }
            } as item
        """

    def _build_one_hop_query(self) -> str:
        """
        Build 1-hop query: Semantic search + 1-hop neighbors
        """
        base_query = """
            // STAGE 1: Semantic search (node, score from vector index)
            WITH node, score
            ORDER BY score DESC
            LIMIT $top_k

            // STAGE 2: Extract primary node properties BEFORE traversal
            WITH node, score,
                id(node) as nodeId,
                labels(node) as nodeLabels,
                node.embedding as nodeEmbedding,
                properties(node) as allNodeProperties,
                node.ucocweName as ucocweName,
                node.label as nodeLabel,
                node.uri as nodeUri,
                node.ucocweExtendedSummary as ucocweExtendedSummary,
                node.ucocweSummary as ucocweSummary,
                node.ucosummary as ucosummary,
                node.ucobaseSeverity as ucobaseSeverity,
                node.ucoexDescription as ucoexDescription,
                node.ucoexDESCRIPTION as ucoexDESCRIPTION,
                node.ucoexNAME as ucoexNAME,
                node.cpeName as cpeName

            // STAGE 2: Graph traversal - get 1-hop neighbors
            OPTIONAL MATCH (node)-[r]-(neighbor)
            WHERE neighbor.embedding IS NOT NULL

            // Aggregate 1-hop neighbors
            WITH nodeId, nodeLabels, nodeEmbedding, allNodeProperties, ucocweName, nodeLabel, nodeUri,
                 ucocweExtendedSummary, ucocweSummary, ucosummary, ucobaseSeverity,
                 ucoexDescription, ucoexDESCRIPTION, ucoexNAME, cpeName, score,
                 collect(DISTINCT {
                     relationshipType: type(r),
                     primaryNode: {
                         nodeId: id(neighbor),
                         nodeLabel: CASE [label IN labels(neighbor) WHERE label <> 'Resource'][0]
                             WHEN 'UcoCWE' THEN neighbor.ucocweName
                             WHEN 'UcoCVE' THEN neighbor.label
                             WHEN 'UcoVulnerability' THEN COALESCE(neighbor.label, neighbor.uri)
                             WHEN 'UcoexCAPEC' THEN neighbor.label
                             WHEN 'UcoexMITREATTACK' THEN neighbor.ucoexNAME
                             WHEN 'UcoexMITIGATIONS' THEN neighbor.ucoexNAME
                             WHEN 'UcoexSOFTWARE' THEN neighbor.label
                             WHEN 'UcoexGROUPS' THEN neighbor.ucoexNAME
                             WHEN 'UcoexCAMPAIGNS' THEN neighbor.ucoexNAME
                             WHEN 'UcoexCPE' THEN neighbor.cpeName
                             WHEN 'UcoexObservedExample' THEN COALESCE(neighbor.label, neighbor.uri)
                             WHEN 'UcoexTACTICS' THEN neighbor.ucoexNAME
                             WHEN 'UcoexMITRED3FEND' THEN neighbor.ucoexMITRED3FEND_LABEL
                             ELSE COALESCE(neighbor.label, neighbor.uri)
                         END,
                         nodeType: [label IN labels(neighbor) WHERE label <> 'Resource'][0],
                         nodeContent: CASE [label IN labels(neighbor) WHERE label <> 'Resource'][0]
                             WHEN 'UcoCWE' THEN COALESCE(neighbor.ucocweSummary, '')
                             WHEN 'UcoCVE' THEN COALESCE(neighbor.ucosummary, '')
                             WHEN 'UcoVulnerability' THEN COALESCE(neighbor.ucosummary, '')
                             WHEN 'UcoexCAPEC' THEN COALESCE(neighbor.ucoexDescription, '')
                             WHEN 'UcoexMITREATTACK' THEN COALESCE(neighbor.ucoexDESCRIPTION, '')
                             WHEN 'UcoexMITIGATIONS' THEN COALESCE(neighbor.ucoexDESCRIPTION, '')
                             WHEN 'UcoexSOFTWARE' THEN COALESCE(neighbor.ucoexDESCRIPTION, '')
                             WHEN 'UcoexGROUPS' THEN COALESCE(neighbor.ucoexDESCRIPTION, '')
                             WHEN 'UcoexCAMPAIGNS' THEN COALESCE(neighbor.ucoexDESCRIPTION, '')
                             WHEN 'UcoexCPE' THEN COALESCE(neighbor.cpeName, '')
                             WHEN 'UcoexObservedExample' THEN COALESCE(neighbor.ucoexDESCRIPTION, '')
                             WHEN 'UcoexTACTICS' THEN COALESCE(neighbor.ucoexDESCRIPTION, neighbor.ucoexDOMAIN, neighbor.ucoexNAME, '')
                             WHEN 'UcoexMITRED3FEND' THEN COALESCE(neighbor.ucoexMITRED3FEND_DEFINITION, neighbor.ucoexMITRED3FEND_LABEL, '')
                             ELSE ''
                         END,
                         embedding: neighbor.embedding,
                         allProperties: CASE WHEN neighbor IS NOT NULL THEN properties(neighbor) ELSE {} END
                     }
                 })[..%s] as neighbors
        """ % self.config.max_neighbors_per_node

        # Add final return section
        base_query += self._build_final_return_section()
        return base_query

    def _build_two_hop_query(self) -> str:
        """
        Build 2-hop query: Semantic search + 1-hop + 2-hop neighbors
        """
        base_query = """
            // STAGE 1: Semantic search (node, score from vector index)
            WITH node, score
            ORDER BY score DESC
            LIMIT $top_k

            // STAGE 2: Extract primary node properties BEFORE traversal
            WITH node, score,
                id(node) as nodeId,
                labels(node) as nodeLabels,
                node.embedding as nodeEmbedding,
                properties(node) as allNodeProperties,
                node.ucocweName as ucocweName,
                node.label as nodeLabel,
                node.uri as nodeUri,
                node.ucocweExtendedSummary as ucocweExtendedSummary,
                node.ucocweSummary as ucocweSummary,
                node.ucosummary as ucosummary,
                node.ucobaseSeverity as ucobaseSeverity,
                node.ucoexDescription as ucoexDescription,
                node.ucoexDESCRIPTION as ucoexDESCRIPTION,
                node.ucoexNAME as ucoexNAME,
                node.cpeName as cpeName

            // STAGE 2: Graph traversal - get 1-hop neighbors
            OPTIONAL MATCH (node)-[r]-(neighbor)
            WHERE neighbor.embedding IS NOT NULL

            // STAGE 2 (Extended): Get 2-hop neighbors
            OPTIONAL MATCH (neighbor)-[r2]-(secondHop)
            WHERE secondHop.embedding IS NOT NULL
                AND id(secondHop) <> nodeId  // Don't go back to primary node

            // Aggregate 2-hop neighbors per 1-hop neighbor
            WITH nodeId, nodeLabels, nodeEmbedding, allNodeProperties, ucocweName, nodeLabel, nodeUri,
                 ucocweExtendedSummary, ucocweSummary, ucosummary, ucobaseSeverity,
                 ucoexDescription, ucoexDESCRIPTION, ucoexNAME, cpeName, score,
                 neighbor, r,
                 [item IN collect(DISTINCT {
                     relationshipType: type(r2),
                     relatedNode: {
                         nodeId: id(secondHop),
                         nodeLabel: CASE [label IN labels(secondHop) WHERE label <> 'Resource'][0]
                             WHEN 'UcoCWE' THEN secondHop.ucocweName
                             WHEN 'UcoCVE' THEN secondHop.label
                             WHEN 'UcoVulnerability' THEN COALESCE(secondHop.label, secondHop.uri)
                             WHEN 'UcoexCAPEC' THEN secondHop.label
                             WHEN 'UcoexMITREATTACK' THEN secondHop.ucoexNAME
                             WHEN 'UcoexMITIGATIONS' THEN secondHop.ucoexNAME
                             WHEN 'UcoexSOFTWARE' THEN secondHop.label
                             WHEN 'UcoexGROUPS' THEN secondHop.ucoexNAME
                             WHEN 'UcoexCAMPAIGNS' THEN secondHop.ucoexNAME
                             WHEN 'UcoexCPE' THEN secondHop.cpeName
                             WHEN 'UcoexObservedExample' THEN COALESCE(secondHop.label, secondHop.uri)
                             WHEN 'UcoexTACTICS' THEN secondHop.ucoexNAME
                             WHEN 'UcoexMITRED3FEND' THEN secondHop.ucoexMITRED3FEND_LABEL
                             ELSE COALESCE(secondHop.label, secondHop.uri)
                         END,
                         nodeType: [label IN labels(secondHop) WHERE label <> 'Resource'][0],
                         nodeContent: CASE [label IN labels(secondHop) WHERE label <> 'Resource'][0]
                             WHEN 'UcoCWE' THEN COALESCE(secondHop.ucocweSummary, '')
                             WHEN 'UcoCVE' THEN COALESCE(secondHop.ucosummary, '')
                             WHEN 'UcoVulnerability' THEN COALESCE(secondHop.ucosummary, '')
                             WHEN 'UcoexCAPEC' THEN COALESCE(secondHop.ucoexDescription, '')
                             WHEN 'UcoexMITREATTACK' THEN COALESCE(secondHop.ucoexDESCRIPTION, '')
                             WHEN 'UcoexMITIGATIONS' THEN COALESCE(secondHop.ucoexDESCRIPTION, '')
                             WHEN 'UcoexSOFTWARE' THEN COALESCE(secondHop.ucoexDESCRIPTION, '')
                             WHEN 'UcoexGROUPS' THEN COALESCE(secondHop.ucoexDESCRIPTION, '')
                             WHEN 'UcoexCAMPAIGNS' THEN COALESCE(secondHop.ucoexDESCRIPTION, '')
                             WHEN 'UcoexCPE' THEN COALESCE(secondHop.cpeName, '')
                             WHEN 'UcoexObservedExample' THEN COALESCE(secondHop.ucoexDESCRIPTION, '')
                             WHEN 'UcoexTACTICS' THEN COALESCE(secondHop.ucoexDESCRIPTION, secondHop.ucoexDOMAIN, secondHop.ucoexNAME, '')
                             WHEN 'UcoexMITRED3FEND' THEN COALESCE(secondHop.ucoexMITRED3FEND_DEFINITION, secondHop.ucoexMITRED3FEND_LABEL, '')
                             ELSE ''
                         END,
                        allProperties: CASE WHEN secondHop IS NOT NULL THEN properties(secondHop) ELSE {} END
                    }
                 }) WHERE item.relatedNode.nodeId IS NOT NULL][..%s] as secondHopNeighbors

            // Aggregate 1-hop neighbors with their 2-hop neighbors
            WITH nodeId, nodeLabels, nodeEmbedding, allNodeProperties, ucocweName, nodeLabel, nodeUri,
                 ucocweExtendedSummary, ucocweSummary, ucosummary, ucobaseSeverity,
                 ucoexDescription, ucoexDESCRIPTION, ucoexNAME, cpeName, score,
                 collect(DISTINCT {
                     relationshipType: type(r),
                     primaryNode: {
                         nodeId: id(neighbor),
                         nodeLabel: CASE [label IN labels(neighbor) WHERE label <> 'Resource'][0]
                             WHEN 'UcoCWE' THEN neighbor.ucocweName
                             WHEN 'UcoCVE' THEN neighbor.label
                             WHEN 'UcoVulnerability' THEN COALESCE(neighbor.label, neighbor.uri)
                             WHEN 'UcoexCAPEC' THEN neighbor.label
                             WHEN 'UcoexMITREATTACK' THEN neighbor.ucoexNAME
                             WHEN 'UcoexMITIGATIONS' THEN neighbor.ucoexNAME
                             WHEN 'UcoexSOFTWARE' THEN neighbor.label
                             WHEN 'UcoexGROUPS' THEN neighbor.ucoexNAME
                             WHEN 'UcoexCAMPAIGNS' THEN neighbor.ucoexNAME
                             WHEN 'UcoexCPE' THEN neighbor.cpeName
                             WHEN 'UcoexObservedExample' THEN COALESCE(neighbor.label, neighbor.uri)
                             WHEN 'UcoexTACTICS' THEN neighbor.ucoexNAME
                             WHEN 'UcoexMITRED3FEND' THEN neighbor.ucoexMITRED3FEND_LABEL
                             ELSE COALESCE(neighbor.label, neighbor.uri)
                         END,
                         nodeType: [label IN labels(neighbor) WHERE label <> 'Resource'][0],
                         nodeContent: CASE [label IN labels(neighbor) WHERE label <> 'Resource'][0]
                             WHEN 'UcoCWE' THEN COALESCE(neighbor.ucocweSummary, '')
                             WHEN 'UcoCVE' THEN COALESCE(neighbor.ucosummary, '')
                             WHEN 'UcoVulnerability' THEN COALESCE(neighbor.ucosummary, '')
                             WHEN 'UcoexCAPEC' THEN COALESCE(neighbor.ucoexDescription, '')
                             WHEN 'UcoexMITREATTACK' THEN COALESCE(neighbor.ucoexDESCRIPTION, '')
                             WHEN 'UcoexMITIGATIONS' THEN COALESCE(neighbor.ucoexDESCRIPTION, '')
                             WHEN 'UcoexSOFTWARE' THEN COALESCE(neighbor.ucoexDESCRIPTION, '')
                             WHEN 'UcoexGROUPS' THEN COALESCE(neighbor.ucoexDESCRIPTION, '')
                             WHEN 'UcoexCAMPAIGNS' THEN COALESCE(neighbor.ucoexDESCRIPTION, '')
                             WHEN 'UcoexCPE' THEN COALESCE(neighbor.cpeName, '')
                             WHEN 'UcoexObservedExample' THEN COALESCE(neighbor.ucoexDESCRIPTION, '')
                             WHEN 'UcoexTACTICS' THEN COALESCE(neighbor.ucoexDESCRIPTION, neighbor.ucoexDOMAIN, neighbor.ucoexNAME, '')
                             WHEN 'UcoexMITRED3FEND' THEN COALESCE(neighbor.ucoexMITRED3FEND_DEFINITION, neighbor.ucoexMITRED3FEND_LABEL, '')
                             ELSE ''
                         END,
                         embedding: neighbor.embedding,
                         allProperties: CASE WHEN neighbor IS NOT NULL THEN properties(neighbor) ELSE {} END
                     },
                     secondHopNeighbors: secondHopNeighbors
                 })[..%s] as neighbors
        """ % (self.config.max_second_hop_per_first, self.config.max_neighbors_per_node)

        # Add final return section
        base_query += self._build_final_return_section()
        return base_query

    def _build_final_return_section(self) -> str:
        """Common final RETURN section for 1-hop and 2-hop queries"""
        return """

            // Final RETURN with all aggregated data
            // Filter out null neighbors (from nodes with no connections)
            WITH nodeId, nodeLabels, nodeEmbedding, allNodeProperties, ucocweName, nodeLabel, nodeUri,
                 ucocweExtendedSummary, ucocweSummary, ucosummary, ucobaseSeverity,
                 ucoexDescription, ucoexDESCRIPTION, ucoexNAME, cpeName, score,
                 [n IN neighbors WHERE n.primaryNode.nodeId IS NOT NULL] as neighbors,
                 CASE [label IN nodeLabels WHERE label <> 'Resource'][0]
                     WHEN 'UcoCWE' THEN COALESCE(ucocweExtendedSummary, ucocweSummary, '')
                     WHEN 'UcoCVE' THEN COALESCE(ucosummary, ucobaseSeverity, '')
                     WHEN 'UcoVulnerability' THEN COALESCE(ucosummary, '')
                     WHEN 'UcoexCAPEC' THEN COALESCE(ucoexDescription, '')
                     WHEN 'UcoexMITREATTACK' THEN COALESCE(ucoexDESCRIPTION, '')
                     WHEN 'UcoexMITIGATIONS' THEN COALESCE(ucoexDESCRIPTION, '')
                     WHEN 'UcoexSOFTWARE' THEN COALESCE(ucoexDESCRIPTION, '')
                     WHEN 'UcoexGROUPS' THEN COALESCE(ucoexDESCRIPTION, '')
                     WHEN 'UcoexCAMPAIGNS' THEN COALESCE(ucoexDESCRIPTION, '')
                     WHEN 'UcoexCPE' THEN COALESCE(cpeName, '')
                     WHEN 'UcoexObservedExample' THEN COALESCE(allNodeProperties.ucoexDESCRIPTION, '')
                     WHEN 'UcoexTACTICS' THEN COALESCE(allNodeProperties.ucoexDESCRIPTION, allNodeProperties.ucoexDOMAIN, allNodeProperties.ucoexNAME, '')
                     WHEN 'UcoexMITRED3FEND' THEN COALESCE(allNodeProperties.ucoexMITRED3FEND_DEFINITION, allNodeProperties.ucoexMITRED3FEND_LABEL, '')
                     ELSE ''
                 END as nodeContent,
                 CASE [label IN nodeLabels WHERE label <> 'Resource'][0]
                     WHEN 'UcoCWE' THEN ucocweName
                     WHEN 'UcoCVE' THEN nodeLabel
                     WHEN 'UcoVulnerability' THEN COALESCE(nodeLabel, nodeUri)
                     WHEN 'UcoexCAPEC' THEN nodeLabel
                     WHEN 'UcoexMITREATTACK' THEN ucoexNAME
                     WHEN 'UcoexMITIGATIONS' THEN ucoexNAME
                     WHEN 'UcoexSOFTWARE' THEN nodeLabel
                     WHEN 'UcoexGROUPS' THEN ucoexNAME
                     WHEN 'UcoexCAMPAIGNS' THEN ucoexNAME
                     WHEN 'UcoexCPE' THEN cpeName
                     WHEN 'UcoexObservedExample' THEN COALESCE(nodeLabel, nodeUri)
                     WHEN 'UcoexTACTICS' THEN COALESCE(allNodeProperties.ucoexNAME, nodeLabel, nodeUri)
                     WHEN 'UcoexMITRED3FEND' THEN COALESCE(allNodeProperties.ucoexMITRED3FEND_LABEL, nodeLabel, nodeUri)
                     ELSE COALESCE(nodeLabel, nodeUri)
                 END as displayLabel,
                 [label IN nodeLabels WHERE label <> 'Resource'][0] as nodeType

            RETURN {
                content: nodeContent,
                metadata: {
                    primarySource: {
                        nodeId: nodeId,
                        nodeLabel: displayLabel,
                        nodeType: nodeType,
                        nodeContent: nodeContent,
                        embedding: nodeEmbedding,
                        initialScore: score,
                        score: score,
                        allProperties: allNodeProperties
                    },
                    firstHopNeighbors: neighbors
                }
            } as item
        """
