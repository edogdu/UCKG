"""
Generation Module for GraphRAG Pipeline
Handles Stage 4: Context formatting and answer generation
"""

from typing import List, Dict, Any
from neo4j_graphrag.generation import RagTemplate
from .utils import RAGMode


class ContextFormatter:
    """Formats graph data into LLM-readable context"""

    def format(self, items: List[Dict], mode: RAGMode) -> Dict[str, Any]:
        """
        Format items into readable context with metadata

        Args:
            items: List of graph items with primary nodes and neighbors
            mode: RAG mode (graphrag or hybrid)

        Returns:
            Dictionary with:
                - formatted_text: Human-readable context
                - structured_data: Machine-readable format
                - metadata: Statistics and info
        """
        if not items:
            return {
                "formatted_text": "No relevant information found.",
                "structured_data": [],
                "metadata": {"mode": mode.value, "item_count": 0}
            }

        # Both graphrag and hybrid use same formatting
        return self._format_graph_with_metadata(items)

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
                lines.append(f"    Semantic Score: {primary.get('score', 0.0):.3f}")
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

    def extract_enhanced_metadata(self, items: List[Dict], mode: RAGMode) -> Dict[str, Any]:
        """Extract enhanced metadata with node and relationship statistics.
        Expects items in normalized flat format."""
        metadata = {
            "mode": mode.value,
            "item_count": len(items),
            "node_types": set(),
            "relationship_types": set(),
            "semantic_scores": []
        }

        for item in items:
            primary = item.get("primarySource", {})
            node_type = primary.get("nodeType")
            if node_type:
                metadata["node_types"].add(node_type)

            score = item.get("score")
            if score is not None:
                metadata["semantic_scores"].append(score)

            for rel in item.get("firstHopNeighbors", []):
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


class AnswerGenerator:
    """Generates natural language answers using LLM"""

    def __init__(self, llm):
        """
        Initialize the AnswerGenerator

        Args:
            llm: Language model (e.g., ChatOllama)
        """
        self.llm = llm

        # GraphRAG prompt (also used for hybrid)
        self.prompt_graphrag = RagTemplate(
            template="""TASK: You are a cybersecurity expert assistant. Answer the user's question using the graph-based knowledge provided below.

QUESTION: {query_text}

=== GRAPH KNOWLEDGE CONTEXT ===
{context}

INSTRUCTIONS:
- **PRIMARY SOURCE**: Focus on [1] PRIMARY NODE and its complete relationship tree (1-hop and 2-hop neighbors) as your main information source
- **SUPPLEMENTARY SOURCE**: Use [2] PRIMARY NODE and its relationships ONLY if it provides additional relevant information to answer the question
- **INFORMATION DEPTH**: The most detailed and relevant information often appears in RELATIONSHIPS and 2-hop neighbors, not just the PRIMARY NODE itself
- **CONNECT THE DOTS**: When you see a chain like "Attack Pattern → Weakness → Specific Vulnerability", explain the connection across hops
- **CYBERSECURITY SPECIFICS**: Include relevant identifiers (CVE IDs, CWE IDs, CAPEC IDs) and technical details (affected products, attack vectors, mitigations)
- **FORMAT**: Use **bold** for important terms, bullet points for lists, and proper markdown formatting
- **STRUCTURE**:
  1. Direct answer to the question (1-2 sentences)
  2. Supporting details from the [1] subgraph (1-2 paragraphs)
  3. Additional context from [2] if relevant (optional)
- **LENGTH**: Keep response compact and well-organized (2-4 paragraphs maximum)
- **HONESTY**: If the graph context doesn't contain enough information to fully answer, acknowledge this

ANSWER:""",
            expected_inputs=["context", "query_text"]
        )

    def generate(self, query: str, context: str, mode: RAGMode) -> str:
        """
        Generate natural language answer from context

        Args:
            query: Original user query
            context: Formatted context string
            mode: RAG mode

        Returns:
            Generated answer string
        """
        response = self.llm.invoke(self.prompt_graphrag.template.format(
            context=context,
            query_text=query
        ))
        return getattr(response, "content", str(response))
