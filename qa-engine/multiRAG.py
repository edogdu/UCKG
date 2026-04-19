"""
Simplified Multi-RAG System for UCKG
Combines semantic search, graph traversal, and hybrid approaches
"""

import os
from enum import Enum
from typing import List, Dict, Any
from pydantic import BaseModel, Field, ValidationError
from neo4j import GraphDatabase
from neo4j_graphrag.retrievers import VectorCypherRetriever
from neo4j_graphrag.generation import RagTemplate
from neo4j_graphrag.embeddings import OllamaEmbeddings
from langchain_core.prompts import PromptTemplate
from langchain_ollama import ChatOllama
from langchain_core.output_parsers import PydanticOutputParser

# Configuration
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "abcd90909090")
INDEX_NAME = "global_embedding_idx"

class RAGMode(str, Enum):
    semantic = "semantic"
    graphrag = "graphrag"
    hybrid = "hybrid"

class QueryRoute(BaseModel):
    mode: str = Field(
        description='One of: "semantic", "graphrag", or "hybrid".'
    )
    top_k: int = Field(
        ge=5, le=5,
        description="Number of results to retrieve (5)."
    )

class MultiRAG:
    """Simplified Multi-RAG system with three strategies"""
    
    def __init__(self):

        # Initialize connections
        self.driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        self.llm = ChatOllama(model="llama3:8b", temperature=0.2)
        self.router_llm = ChatOllama(model="llama3:8b", temperature=0)
        self._route_parser = PydanticOutputParser(pydantic_object=QueryRoute)

        self._route_prompt = PromptTemplate(
            template=(
                "You are a query router for a cybersecurity Multi-RAG.\n\n"
                "Choose retrieval mode:\n"
                "- semantic: direct definitions.\n"
                "- graphrag: relationships, paths, impact between nodes.\n"
                "- hybrid: broad or ambiguous queries benefiting from both.\n\n"
                "Rules:\n"
                "- mode must be exactly one of: semantic, graphrag, hybrid\n"
                "- top_k = 5 based on complexity/ambiguity\n"
                "{format_instructions}\n\n"
                "User query:\n{query}\n"
            ),
            input_variables=["query"],
            partial_variables={"format_instructions": self._route_parser.get_format_instructions()},
        )
        # Compile the chain: prompt -> router LLM -> pydantic parser
        self._router_chain = self._route_prompt | self.router_llm | self._route_parser
        # Create retrievers
        self._create_retrievers()
        # Create prompt template
        self.prompt1 = RagTemplate(
            template="""TASK: You are a cybersecurity expert chatbot using semantic similarity search.
Use the following information to provide a comprehensive answer to the question.

QUESTIONS: {query_text}

=== SEMANTIC SEARCH RESULTS ===
{context}

INSTRUCTIONS:
- Prioritize information from nodes with highest semantic similarity scores
- Use semantic scores to indicate confidence: "High confidence (score: 0.92): [statement]"
- If semantic scores vary significantly, note the range: "Scores range from 0.85-0.95"
- Focus on the most semantically relevant content first
- Address semantic ambiguity by comparing similar but different concepts
- Keep answer to 3-5 sentences with semantic confidence indicators

FINAL ANSWER:""",
            expected_inputs=["context", "query_text"]
        )
            
        self.prompt2 = RagTemplate(
            template="""TASK: You are a cybersecurity expert chatbot using graph-based knowledge exploration.
Use the following information to provide a comprehensive answer by leveraging relationship networks.

QUESTIONS: {query_text}

=== GRAPH CONTEXT ===
{context}

INSTRUCTIONS:
- **Primary Node Focus**: Start with the main semantically matched node
- **Relationship Exploration**: Trace 1-hop and 2-hop relationships to build comprehensive understanding
- **Attack Chain Mapping**: Use relationships to show how vulnerabilities connect to attack patterns
- **Mitigation Discovery**: Leverage graph structure to find related defensive techniques
- **Relationship Types**: Pay attention to relationship types (UCOEX_RELATES_TO, UCOEX_ATTACK_PATTERN, etc.)
- **Neighborhood Context**: Use neighbor_count to understand the scope of related concepts
- **Graph Traversal**: Explain the "path" from primary node through relationships to related concepts

OUTPUT STRUCTURE:
1. Primary Vulnerability/Concept: [Main node with semantic score]
2. Direct Relationships: [1-hop neighbors and their significance]
3. Extended Context: [2-hop neighbors showing broader impact]
4. Attack Chain: [How concepts connect through relationships]

FINAL ANSWER:""",
            expected_inputs=["context", "query_text"]
        )
        self.prompt3 = RagTemplate(
            template="""TASK: You are a cybersecurity expert chatbot using both semantic similarity and graph relationship analysis.
Leverage semantic scores for relevance and graph structure for comprehensive context.

QUESTIONS: {query_text}

=== HYBRID CONTEXT ===
{context}

INSTRUCTIONS:
- **Semantic Priority**: Start with highest scoring semantically relevant nodes
- **Graph Expansion**: Use 1-hop and 2-hop relationships to expand understanding
- **Score-Weighted Analysis**: Higher semantic scores indicate more relevant primary information
- **Relationship Mapping**: Show how concepts connect through graph relationships
- **Comprehensive Coverage**: Combine semantic relevance with graph neighborhood exploration
- **Confidence Assessment**: Use both semantic scores and relationship density for confidence

APPROACH:
1. Identify primary nodes by semantic similarity
2. Explore their graph neighborhoods (1-hop + 2-hop)
3. Map relationship chains and attack patterns
4. Provide comprehensive answer leveraging both approaches

FINAL ANSWER:""",
            expected_inputs=["context", "query_text"]
        )

    def _create_retrievers(self):
        """Create the three retriever strategies with advanced attribute selection"""
        embedder = OllamaEmbeddings(model="nomic-embed-text:latest")
        
        # 1. Enhanced Semantic Retriever with smart attribute selection
        self.semantic_retriever = VectorCypherRetriever(
            driver=self.driver,
            index_name=INDEX_NAME,
            retrieval_query="""
            WITH node, score
            ORDER BY score DESC
            LIMIT $top_k
            
            RETURN {
                content: CASE [label IN labels(node) WHERE label <> 'Resource'][0]
                    WHEN 'UcoCWE' THEN COALESCE(node.ucocweExtendedSummary, node.ucocweSummary, node.ucocweName, '')
                    WHEN 'UcoCVE' THEN COALESCE(node.ucosummary, node.ucobaseSeverity, node.label, '')
                    WHEN 'UcoVulnerability' THEN COALESCE(node.ucosummary, node.label, node.uri, '')
                    WHEN 'UcoexCAPEC' THEN COALESCE(node.ucoexDescription, node.label, '')
                    WHEN 'UcoexMITREATTACK' THEN COALESCE(node.ucoexDESCRIPTION, node.ucoexNAME, '')
                    WHEN 'UcoexMITIGATIONS' THEN COALESCE(node.ucoexDESCRIPTION, node.ucoexNAME, '')
                    WHEN 'UcoexSOFTWARE' THEN COALESCE(node.ucoexDESCRIPTION, node.label, '')
                    WHEN 'UcoexGROUPS' THEN COALESCE(node.ucoexDESCRIPTION, node.ucoexNAME, '')
                    WHEN 'UcoexCAMPAIGNS' THEN COALESCE(node.ucoexDESCRIPTION, node.ucoexNAME, '')
                    WHEN 'UcoexObservedExample' THEN COALESCE(node.ucoexDESCRIPTION, '')
                    WHEN 'UcoexTACTICS' THEN COALESCE(node.ucoexDESCRIPTION, node.ucoexNAME, '')
                    WHEN 'UcoexMITRED3FEND' THEN COALESCE(node.ucoexMITRED3FEND_DEFINITION, node.ucoexNAME, '')
                    WHEN 'UcoexCPE' THEN COALESCE(node.cpeName, node.label, '')
                    ELSE COALESCE(node.label, node.uri, '')
                END,
                metadata: {
                    labels: labels(node),
                    id: elementId(node),
                    uri: node.uri,
                    nodeType: [label IN labels(node) WHERE label <> 'Resource'][0],
                    nodeLabel: CASE [label IN labels(node) WHERE label <> 'Resource'][0]
                        WHEN 'UcoCWE' THEN node.ucocweName
                        WHEN 'UcoCVE' THEN node.label
                        WHEN 'UcoVulnerability' THEN COALESCE(node.label, node.uri)
                        WHEN 'UcoexCAPEC' THEN node.label
                        WHEN 'UcoexMITREATTACK' THEN node.ucoexNAME
                        WHEN 'UcoexMITIGATIONS' THEN node.ucoexNAME
                        WHEN 'UcoexSOFTWARE' THEN node.label
                        WHEN 'UcoexGROUPS' THEN node.ucoexNAME
                        WHEN 'UcoexCAMPAIGNS' THEN node.ucoexNAME
                        WHEN 'UcoexCPE' THEN node.cpeName
                        ELSE COALESCE(node.label, node.uri)
                    END
                },
                score: score
            } as item
            """,
            embedder=embedder,
            result_formatter=lambda rec: rec["item"]
        )
        
        # 2. Enhanced Graph retriever with advanced attribute selection
        self.graph_retriever = VectorCypherRetriever(
            driver=self.driver,
            index_name=INDEX_NAME,
            retrieval_query="""
            // 1. Get top_k semantically similar nodes FIRST
            WITH node, score
            ORDER BY score DESC
            LIMIT $top_k

            // 2. THEN explore their 2-hop neighborhoods with smart attribute selection
            OPTIONAL MATCH (node)-[r1]-(n1)
            OPTIONAL MATCH (n1)-[r2]-(n2)
            WHERE n1.embedding IS NOT NULL AND n2.embedding IS NOT NULL
            
            WITH node, score, n1, r1, collect({
                relationshipType: type(r2),
                relatedNode: {
                    nodeLabel: CASE [label IN labels(n2) WHERE label <> 'Resource'][0]
                        WHEN 'UcoCWE' THEN n2.ucocweName
                        WHEN 'UcoCVE' THEN n2.label
                        WHEN 'UcoVulnerability' THEN COALESCE(n2.label, n2.uri)
                        WHEN 'UcoexCAPEC' THEN n2.label
                        WHEN 'UcoexMITREATTACK' THEN n2.ucoexNAME
                        WHEN 'UcoexMITIGATIONS' THEN n2.ucoexNAME
                        WHEN 'UcoexSOFTWARE' THEN n2.label
                        WHEN 'UcoexGROUPS' THEN n2.ucoexNAME
                        WHEN 'UcoexCAMPAIGNS' THEN n2.ucoexNAME
                        WHEN 'UcoexCPE' THEN n2.cpeName
                        ELSE COALESCE(n2.label, n2.uri)
                    END,
                    nodeType: [label IN labels(n2) WHERE label <> 'Resource'][0],
                    nodeContent: CASE [label IN labels(n2) WHERE label <> 'Resource'][0]
                        WHEN 'UcoCWE' THEN substring(COALESCE(n2.ucocweSummary, n2.ucocweExtendedSummary, ''), 0, 250)
                        WHEN 'UcoCVE' THEN substring(COALESCE(n2.ucosummary, n2.ucobaseSeverity, ''), 0, 250)
                        WHEN 'UcoVulnerability' THEN substring(COALESCE(n2.ucosummary, ''), 0, 250)
                        WHEN 'UcoexCAPEC' THEN substring(COALESCE(n2.ucoexDescription, ''), 0, 250)
                        WHEN 'UcoexMITREATTACK' THEN substring(COALESCE(n2.ucoexDESCRIPTION, ''), 0, 250)
                        WHEN 'UcoexMITIGATIONS' THEN substring(COALESCE(n2.ucoexDESCRIPTION, ''), 0, 250)
                        WHEN 'UcoexSOFTWARE' THEN substring(COALESCE(n2.ucoexDESCRIPTION, ''), 0, 250)
                        WHEN 'UcoexGROUPS' THEN substring(COALESCE(n2.ucoexDESCRIPTION, ''), 0, 250)
                        WHEN 'UcoexCAMPAIGNS' THEN substring(COALESCE(n2.ucoexDESCRIPTION, ''), 0, 250)
                        WHEN 'UcoexCPE' THEN substring(COALESCE(n2.cpeName, ''), 0, 250)
                        ELSE ''
                    END
                }
            }) as n2Neighbors
            
            WITH node, score, collect({
                relationshipType: type(r1),
                primaryNode: {
                    nodeLabel: CASE [label IN labels(n1) WHERE label <> 'Resource'][0]
                        WHEN 'UcoCWE' THEN n1.ucocweName
                        WHEN 'UcoCVE' THEN n1.label
                        WHEN 'UcoVulnerability' THEN COALESCE(n1.label, n1.uri)
                        WHEN 'UcoexCAPEC' THEN n1.label
                        WHEN 'UcoexMITREATTACK' THEN n1.ucoexNAME
                        WHEN 'UcoexMITIGATIONS' THEN n1.ucoexNAME
                        WHEN 'UcoexSOFTWARE' THEN n1.label
                        WHEN 'UcoexGROUPS' THEN n1.ucoexNAME
                        WHEN 'UcoexCAMPAIGNS' THEN n1.ucoexNAME
                        WHEN 'UcoexCPE' THEN n1.cpeName
                        ELSE COALESCE(n1.label, n1.uri)
                    END,
                    nodeType: [label IN labels(n1) WHERE label <> 'Resource'][0],
                    nodeContent: CASE [label IN labels(n1) WHERE label <> 'Resource'][0]
                        WHEN 'UcoCWE' THEN COALESCE(n1.ucocweExtendedSummary, n1.ucocweSummary, '')
                        WHEN 'UcoCVE' THEN COALESCE(n1.ucosummary, n1.ucobaseSeverity, '')
                        WHEN 'UcoVulnerability' THEN COALESCE(n1.ucosummary, '')
                        WHEN 'UcoexCAPEC' THEN COALESCE(n1.ucoexDescription, '')
                        WHEN 'UcoexMITREATTACK' THEN COALESCE(n1.ucoexDESCRIPTION, '')
                        WHEN 'UcoexMITIGATIONS' THEN COALESCE(n1.ucoexDESCRIPTION, '')
                        WHEN 'UcoexSOFTWARE' THEN COALESCE(n1.ucoexDESCRIPTION, '')
                        WHEN 'UcoexGROUPS' THEN COALESCE(n1.ucoexDESCRIPTION, '')
                        WHEN 'UcoexCAMPAIGNS' THEN COALESCE(n1.ucoexDESCRIPTION, '')
                        WHEN 'UcoexCPE' THEN COALESCE(n1.cpeName, '')
                        ELSE ''
                    END
                },
                secondHopNeighbors: n2Neighbors
            }) as firstHopWithSecondHop
            
            RETURN {
                primarySource: {
                    nodeLabel: CASE [label IN labels(node) WHERE label <> 'Resource'][0]
                        WHEN 'UcoCWE' THEN node.ucocweName
                        WHEN 'UcoCVE' THEN node.label
                        WHEN 'UcoVulnerability' THEN COALESCE(node.label, node.uri)
                        WHEN 'UcoexCAPEC' THEN node.label
                        WHEN 'UcoexMITREATTACK' THEN node.ucoexNAME
                        WHEN 'UcoexMITIGATIONS' THEN node.ucoexNAME
                        WHEN 'UcoexSOFTWARE' THEN node.label
                        WHEN 'UcoexGROUPS' THEN node.ucoexNAME
                        WHEN 'UcoexCAMPAIGNS' THEN node.ucoexNAME
                        WHEN 'UcoexCPE' THEN node.cpeName
                        ELSE COALESCE(node.label, node.uri)
                    END,
                    nodeType: [label IN labels(node) WHERE label <> 'Resource'][0],
                    nodeContent: CASE [label IN labels(node) WHERE label <> 'Resource'][0]
                        WHEN 'UcoCWE' THEN COALESCE(node.ucocweExtendedSummary, node.ucocweSummary, '')
                        WHEN 'UcoCVE' THEN COALESCE(node.ucosummary, node.ucobaseSeverity, '')
                        WHEN 'UcoVulnerability' THEN COALESCE(node.ucosummary, '')
                        WHEN 'UcoexCAPEC' THEN COALESCE(node.ucoexDescription, '')
                        WHEN 'UcoexMITREATTACK' THEN COALESCE(node.ucoexDESCRIPTION, '')
                        WHEN 'UcoexMITIGATIONS' THEN COALESCE(node.ucoexDESCRIPTION, '')
                        WHEN 'UcoexSOFTWARE' THEN COALESCE(node.ucoexDESCRIPTION, '')
                        WHEN 'UcoexGROUPS' THEN COALESCE(node.ucoexDESCRIPTION, '')
                        WHEN 'UcoexCAMPAIGNS' THEN COALESCE(node.ucoexDESCRIPTION, '')
                        WHEN 'UcoexObservedExample' THEN COALESCE(node.ucoexDESCRIPTION, '')
                        WHEN 'UcoexTACTICS' THEN COALESCE(node.ucoexDESCRIPTION, '')
                        WHEN 'UcoexMITRED3FEND' THEN COALESCE(node.ucoexMITRED3FEND_DEFINITION, '')
                        WHEN 'UcoexCPE' THEN COALESCE(node.cpeName, '')
                        ELSE ''
                    END,
                    score: score
                },
                firstHopNeighbors: firstHopWithSecondHop
            } as result
            """,
            embedder=embedder,
            result_formatter=lambda rec: rec["item"]
        )
    
    def _classify_query(self, query: str) -> tuple[RAGMode, int]:
        """LLM-powered routing with structured output + safe fallback."""
        try:
            result: QueryRoute = self._router_chain.invoke({"query": query})
            # Normalize + validate mode
            mode_str = result.mode.strip().lower()
            if mode_str not in {"semantic", "graphrag", "hybrid"}:
                mode_str = "hybrid"
            mode = RAGMode(mode_str)
            # top_k of 5 nodes
            top_k = 5
            return mode, top_k

        except (ValidationError, ValueError, TypeError, Exception):
            # Robust fallback if parsing/model fails
            return RAGMode.hybrid, 5
    
    def _get_semantic_results(self, query: str, top_k: int) -> List[Dict]:
        """Get semantic search results"""
        try:
            results = self.semantic_retriever.search(query_text=query, top_k=top_k)
            
            if hasattr(results, 'items'):
                result_list = []
                for item in results.items:
                    # Convert RetrieverResultItem to dictionary format expected by wrapper
                    result_dict = {
                        'content': item.content,
                        'metadata': item.metadata,
                        'score': getattr(item, 'score', 0.0)  # Add score if available
                    }
                    result_list.append(result_dict)
                
                return result_list
            elif hasattr(results, 'results'):
                return list(results.results)
            else:
                return []
        except Exception as e:
            # Log error but don't print to stdout (interferes with JSON output)
            import traceback
            import sys
            print(f"ERROR in _get_semantic_results: {str(e)}", file=sys.stderr)
            traceback.print_exc(file=sys.stderr)
            return []
    
    def _get_graph_results(self, query: str, top_k: int) -> List[Dict]:
        """Get graph traversal results"""
        try:
            results = self.graph_retriever.search(query_text=query, top_k=top_k)
            if hasattr(results, 'items'):
                result_list = []
                for item in results.items:
                    result_dict = {
                        'content': item.content,
                        'metadata': item.metadata,
                        'score': getattr(item, 'score', 0.0)
                    }
                    result_list.append(result_dict)
                return result_list
            elif hasattr(results, 'results'):
                return list(results.results)
            else:
                return []
        except Exception as e:
            import sys
            print(f"ERROR in _get_graph_results: {str(e)}", file=sys.stderr)
            return []
    
    def _get_hybrid_results(self, query: str, top_k: int) -> List[Dict]:
        """Get hybrid results by combining both approaches"""
        semantic = self._get_semantic_results(query, top_k)
        graph = self._get_graph_results(query, top_k)
        
        # Simple deduplication by ID
        seen = set()
        combined = []
        
        for item in semantic + graph:
            item_id = item.get("metadata", {}).get("id")
            if item_id and item_id not in seen:
                seen.add(item_id)
                combined.append(item)
        # Return top_k items by score
        return sorted(combined, key=lambda x: x.get("score", 0), reverse=True)[:top_k]
    
    def _format_context(self, items: List[Dict], mode: RAGMode) -> str:
        """Format retrieved items into context string based on retrieval mode"""
        if not items:
            return "No relevant information found."
        
        if mode == RAGMode.semantic:
            return self._format_semantic_context(items)
        elif mode == RAGMode.graphrag:
            return self._format_graph_context(items)
        else:  # hybrid
            return self._format_hybrid_context(items)

    def _format_semantic_context(self, items: List[Dict]) -> str:
        """Enhanced semantic context with smart attribute selection"""
        lines = []
        lines.append("=== SEMANTIC SEARCH RESULTS ===")
        
        for i, item in enumerate(items, 1):
            content = item.get("content", "No content")
            labels = item.get("metadata", {}).get("labels", [])
            score = item.get("score", 0.0)
            node_type = item.get("metadata", {}).get("nodeType", "Unknown")
            node_label = item.get("metadata", {}).get("nodeLabel", "Unknown")
            
            # Enhanced formatting with type-specific information
            lines.append(f"[{i}] {node_label} ({node_type}) [Score: {score:.3f}]")
            lines.append(f"    Labels: {', '.join(labels)}")
            lines.append(f"    Content: {content}")
            lines.append("")
        
        return "\n".join(lines)

    def _format_graph_context(self, items: List[Dict]) -> str:
        """Enhanced graph context with smart attribute selection"""
        lines = []
        lines.append("=== GRAPH-BASED KNOWLEDGE NETWORK ===")
        
        for i, item in enumerate(items, 1):
            if "primarySource" in item:
                primary = item["primarySource"]
                first_hop = item.get("firstHopNeighbors", [])
                
                # Enhanced primary node display
                lines.append(f"[{i}] PRIMARY NODE: {primary.get('nodeLabel', 'Unknown')}")
                lines.append(f"    Type: {primary.get('nodeType', 'Unknown')}")
                lines.append(f"    Content: {primary.get('nodeContent', 'No content')}")
                lines.append(f"    Semantic Score: {primary.get('semanticScore', 0.0):.3f}")
                lines.append("")
                
                if first_hop:
                    lines.append("    RELATIONSHIPS:")
                    for rel in first_hop:
                        rel_type = rel.get("relationshipType", "Unknown")
                        primary_node = rel.get("primaryNode", {})
                        second_hop = rel.get("secondHopNeighbors", [])
                        
                        # Enhanced relationship display
                        lines.append(f"    ├── {rel_type} → {primary_node.get('nodeLabel', 'Unknown')}")
                        lines.append(f"        Type: {primary_node.get('nodeType', 'Unknown')}")
                        lines.append(f"        Content: {primary_node.get('nodeContent', 'No content')}")
                        
                        if second_hop:
                            lines.append(f"        └── 2-hop connections ({len(second_hop)} nodes):")
                            for n2 in second_hop:
                                n2_type = n2.get("relationshipType", "Unknown")
                                n2_node = n2.get("relatedNode", {})
                                lines.append(f"            {n2_type} → {n2_node.get('nodeLabel', 'Unknown')}")
                                lines.append(f"                Type: {n2_node.get('nodeType', 'Unknown')}")
                                lines.append(f"                Content: {n2_node.get('nodeContent', 'No content')}")
                        
                        lines.append("")
    
        return "\n".join(lines)

    def _format_hybrid_context(self, items: List[Dict]) -> str:
        """Enhanced hybrid context combining both approaches"""
        lines = []
        lines.append("=== HYBRID KNOWLEDGE CONTEXT ===")
        lines.append("Combining semantic relevance with graph relationships")
        lines.append("")
        
        for i, item in enumerate(items, 1):
            # Enhanced semantic item handling
            if "score" in item:
                content = item.get("content", "No content")
                labels = item.get("metadata", {}).get("labels", [])
                score = item.get("score", 0.0)
                node_type = item.get("metadata", {}).get("nodeType", "Unknown")
                node_label = item.get("metadata", {}).get("nodeLabel", "Unknown")
                
                lines.append(f"[{i}] SEMANTIC MATCH: {node_label}")
                lines.append(f"    Type: {node_type}")
                lines.append(f"    Labels: {', '.join(labels)}")
                lines.append(f"    Relevance Score: {score:.3f}")
                lines.append(f"    Content: {content}")
                lines.append("")
            
            # Enhanced graph item handling
            elif "primarySource" in item:
                primary = item["primarySource"]
                first_hop = item.get("firstHopNeighbors", [])
                
                lines.append(f"[{i}] GRAPH NODE: {primary.get('nodeLabel', 'Unknown')}")
                lines.append(f"    Type: {primary.get('nodeType', 'Unknown')}")
                lines.append(f"    Semantic Score: {primary.get('semanticScore', 0.0):.3f}")
                lines.append(f"    Content: {primary.get('nodeContent', 'No content')}")
                lines.append("")
                
                if first_hop:
                    lines.append("    RELATIONSHIP NETWORK:")
                    for rel in first_hop:
                        rel_type = rel.get("relationshipType", "Unknown")
                        primary_node = rel.get("primaryNode", {})
                        second_hop = rel.get("secondHopNeighbors", [])
                        
                        lines.append(f"    ├── {rel_type} → {primary_node.get('nodeLabel', 'Unknown')}")
                        lines.append(f"        Type: {primary_node.get('nodeType', 'Unknown')}")
                        if second_hop:
                            lines.append(f"        └── 2-hop connections: {len(second_hop)} nodes")
                        lines.append("")
        
        return "\n".join(lines)
    def _format_context_with_metadata(self, items: List[Dict], mode: RAGMode) -> Dict[str, Any]:
        """Enhanced context formatting that preserves structured information"""
        if not items:
            return {
                "formatted_text": "No relevant information found.",
                "structured_data": [],
                "metadata": {"mode": mode.value, "item_count": 0}
            }
        
        if mode == RAGMode.semantic:
            return self._format_semantic_with_metadata(items)
        elif mode == RAGMode.graphrag:
            return self._format_graph_with_metadata(items)
        else:  # hybrid
            return self._format_graph_with_metadata(items)

    def _format_semantic_with_metadata(self, items: List[Dict]) -> Dict[str, Any]:
        """Semantic context with structured metadata"""
        formatted_lines = []
        structured_data = []
        
        for i, item in enumerate(items, 1):
            content = item.get("content", "No content")
            labels = item.get("metadata", {}).get("labels", [])
            score = item.get("score", 0.0)
            node_id = item.get("metadata", {}).get("id", "")
            uri = item.get("metadata", {}).get("uri", "")
            
            # Formatted text
            formatted_lines.append(f"[{i}] ({','.join(labels)}) [Score: {score:.3f}]")
            formatted_lines.append(f"    {content}")
            formatted_lines.append("")
            
            # Structured data
            structured_data.append({
                "index": i,
                "labels": labels,
                "content": content,
                "score": score,
                "node_id": node_id,
                "uri": uri
            })
        
        return {
            "formatted_text": "\n".join(formatted_lines),
            "structured_data": structured_data,
            "metadata": {
                "mode": "semantic",
                "item_count": len(items),
                "score_range": {
                    "min": min(item.get("score", 0) for item in items),
                    "max": max(item.get("score", 0) for item in items),
                    "avg": sum(item.get("score", 0) for item in items) / len(items)
                }
            }
        }

    def _format_graph_with_metadata(self, items: List[Dict]) -> Dict[str, Any]:
        """Graph context with structured metadata"""
        formatted_lines = []
        structured_data = []
        
        for i, item in enumerate(items, 1):
            if "primarySource" in item:
                primary = item["primarySource"]
                first_hop = item.get("firstHopNeighbors", [])
                
                # Formatted text
                lines = []
                lines.append(f"[{i}] PRIMARY NODE: {primary.get('nodeLabel', 'Unknown')}")
                lines.append(f"    Type: {primary.get('nodeType', 'Unknown')}")
                lines.append(f"    Content: {primary.get('nodeContent', 'No content')}")
                lines.append(f"    Semantic Score: {primary.get('semanticScore', 0.0):.3f}")
                lines.append("")
                
                if first_hop:
                    lines.append("    RELATIONSHIPS:")
                    for rel in first_hop:
                        rel_type = rel.get("relationshipType", "Unknown")
                        primary_node = rel.get("primaryNode", {})
                        second_hop = rel.get("secondHopNeighbors", [])
                        
                        lines.append(f"    ├── {rel_type} → {primary_node.get('nodeLabel', 'Unknown')}")
                        lines.append(f"        Content: {primary_node.get('nodeContent', 'No content')}")
                        
                        if second_hop:
                            for n2 in second_hop:
                                n2_type = n2.get("relationshipType", "Unknown")
                                n2_node = n2.get("relatedNode", {})
                                lines.append(f"        └── {n2_type} → {n2_node.get('nodeLabel', 'Unknown')}")
                                lines.append(f"            Content: {n2_node.get('nodeContent', 'No content')}")
                        
                        lines.append("")
                
                formatted_lines.extend(lines)
                
                # Structured data
                structured_data.append({
                    "index": i,
                    "primary_source": primary,
                    "relationships": first_hop,
                    "total_relationships": len(first_hop),
                    "total_second_hop": sum(len(rel.get("secondHopNeighbors", [])) for rel in first_hop)
                })
        
        return {
            "formatted_text": "\n".join(formatted_lines),
            "structured_data": structured_data,
            "metadata": {
                "mode": "graphrag",
                "item_count": len(items),
                "total_relationships": sum(item.get("total_relationships", 0) for item in structured_data),
                "total_second_hop": sum(item.get("total_second_hop", 0) for item in structured_data)
            }
        }
    
    def _extract_enhanced_metadata(self, items: List[Dict], mode: RAGMode) -> Dict[str, Any]:
        """Extract enhanced metadata with smart attribute analysis"""
        metadata = {
            "mode": mode.value,
            "item_count": len(items),
            "node_types": set(),
            "relationship_types": set(),
            "content_quality": {},
            "semantic_scores": []
        }
        
        for item in items:
            # Extract node types
            if "metadata" in item:
                node_type = item["metadata"].get("nodeType")
                if node_type:
                    metadata["node_types"].add(node_type)
            
            if "primarySource" in item:
                node_type = item["primarySource"].get("nodeType")
                if node_type:
                    metadata["node_types"].add(node_type)
            
            # Extract semantic scores
            if "score" in item:
                metadata["semantic_scores"].append(item["score"])
            
            if "primarySource" in item:
                score = item["primarySource"].get("semanticScore")
                if score:
                    metadata["semantic_scores"].append(score)
            
            # Extract relationship types
            if "firstHopNeighbors" in item:
                for rel in item["firstHopNeighbors"]:
                    rel_type = rel.get("relationshipType")
                    if rel_type:
                        metadata["relationship_types"].add(rel_type)
        
        # Convert sets to lists for JSON serialization
        metadata["node_types"] = list(metadata["node_types"])
        metadata["relationship_types"] = list(metadata["relationship_types"])
        
        # Calculate score statistics
        if metadata["semantic_scores"]:
            metadata["score_statistics"] = {
                "min": min(metadata["semantic_scores"]),
                "max": max(metadata["semantic_scores"]),
                "avg": sum(metadata["semantic_scores"]) / len(metadata["semantic_scores"])
            }
        
        return metadata

    def run(self, query: str) -> Dict[str, Any]:
        """Enhanced main method with advanced attribute handling"""
        try:
            # Classify query and get strategy
            mode, top_k = self._classify_query(query)
            
            # Get results based on strategy
            if mode == RAGMode.semantic:
                items = self._get_semantic_results(query, top_k)
            elif mode == RAGMode.graphrag:
                items = self._get_graph_results(query, top_k)
            else:  # hybrid
                items = self._get_hybrid_results(query, top_k)

            # Generate enhanced context based on mode
            context_info = self._format_context_with_metadata(items, mode)
            context = context_info["formatted_text"]
            
            # Extract enhanced metadata
            enhanced_metadata = self._extract_enhanced_metadata(items, mode)
            
            # Generate answer based on method with enhanced context
            if mode == RAGMode.semantic:
                response = self.llm.invoke(self.prompt1.template.format(
                    context=context, 
                    query_text=query
                ))
            elif mode == RAGMode.graphrag:
                response = self.llm.invoke(self.prompt2.template.format(
                    context=context, 
                    query_text=query
                ))
            else:
                response = self.llm.invoke(self.prompt3.template.format(
                    context=context, 
                    query_text=query
                ))

            # Extract answer text
            answer_text = getattr(response, "content", str(response))

            return {
                "answer": answer_text,
                "mode": mode.value,
                "sources": items,
                "context": context,
                "context_metadata": context_info["metadata"],
                "structured_context": context_info["structured_data"],
                "enhanced_metadata": enhanced_metadata
            }
            
        except Exception as e:
            return {
                "answer": f"Error processing query: {str(e)}",
                "mode": "error",
                "sources": [],
                "context": "",
                "context_metadata": {},
                "structured_context": [],
                "enhanced_metadata": {}
            }
    
    def close(self):
        """Clean up resources"""
        if self.driver:
            self.driver.close()

# Simple usage example
if __name__ == "__main__":
    rag = MultiRAG()
    try:
        # Test queries
        test_queries = [
            "What is CWE-16?",
            "How can SQL Injection effect to database authorization?",
            "What are the most weakness in cybersecurity space?"
        ]
        
        for query in test_queries:
            print(f"\nQuery: {query}")
            print("-" * 50)
            
            result = rag.run(query)
            print(f"Mode: {result['mode']}")
            print(f"Answer: {result['answer']}...")
            print("-" * 50)

    finally:
        rag.close()
