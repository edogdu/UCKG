"""
Query Processing Module for GraphRAG Pipeline

Key features:
- Dynamic hop selection (0-hop, 1-hop, 2-hop)
- Schema-aware relationship prediction using UCKG schema
- Query routing for GraphRAG modes
"""

import re
import os
from typing import Tuple, Optional, List, Dict, Any
from dataclasses import dataclass
from pydantic import BaseModel, Field
from langchain_core.prompts import PromptTemplate
from langchain_core.output_parsers import PydanticOutputParser
from langchain_ollama import ChatOllama


@dataclass
class HopDecision:
    """Result of hop selection analysis"""
    hop_depth: int  # 0, 1, or 2
    reasoning: str
    confidence: float  # 0.0 to 1.0
    method: str  # "rule", "llm", or "hybrid"


class LLMHopStrategy(BaseModel):
    """Structured output for LLM hop selection"""
    hop_depth: int = Field(ge=0, le=2, description="Number of hops: 0, 1, or 2")
    reasoning: str = Field(description="Brief explanation for hop depth selection")


class RelationshipPrediction(BaseModel):
    """Structured output for relationship prediction"""
    primary_relationships: List[Dict[str, str]] = Field(
        description="List of relevant relationship types with start/end node types"
    )
    reasoning: str = Field(description="Brief explanation of relevance")


class HopSelector:
    """Hybrid hop selection system combining rule-based and LLM approaches."""

    def __init__(self, llm=None, use_llm_threshold: float = 0.7, enable_llm: bool = True, schema_file: str = None):
        self.llm = llm or ChatOllama(model="llama3:8b", temperature=0)
        self.use_llm_threshold = use_llm_threshold
        self.enable_llm = enable_llm
        
        # Load schema if available
        self.schema_content = ""
        if schema_file and os.path.exists(schema_file):
            with open(schema_file, 'r') as f:
                self.schema_content = f.read()
        
        self._hop_parser = PydanticOutputParser(pydantic_object=LLMHopStrategy)
        self._hop_prompt = PromptTemplate(
            template="""You are a query analyzer for the UCKG cybersecurity knowledge graph system.

Your task: Analyze a user query and determine the optimal graph traversal depth needed to answer it.

## UCKG Schema Information:

{schema_content}

## Hop Depth Decision Criteria:

**0-hop (Semantic Search Only) - NO GRAPH TRAVERSAL:**
- Simple "What is X?" queries asking for definition/description
- Answer found ENTIRELY within ONE node's properties
- NO relationships needed - just semantic search
- Examples: "What is Cross-site Scripting?", "What is SQL injection?", "Define buffer overflow"

**1-hop (Direct Relationships) - ONE GRAPH TRAVERSAL:**
- Requires ONE relationship traversal (A→B)
- "What is X and what are Y related to it?" (2 entities, direct connection)
- Relationship keywords: exploit, use, affect, mitigate, prevent, related to
- Examples: "What weaknesses does Cross-site Scripting exploit?", "How to defend against phishing?"

**2-hop (Multi-Hop Chains) - TWO GRAPH TRAVERSALS:**
- Requires TWO relationship traversals (A→B→C)
- Complex queries needing multiple connected entities
- Examples: "What attacks exploit SQL injection weaknesses and how do they work?"

## Analysis Process:
1. Identify the main entities/concepts in the query
2. Determine if the query needs direct relationships (1-hop) or complex chains (2-hop)
3. If asking for basic information about one concept, use 0-hop
4. If asking about relationships between two concepts, use 1-hop
5. If asking about multi-step processes or complex chains, use 2-hop

Query: {query}

{format_instructions}

Analyze the query and determine the appropriate hop depth with clear reasoning.""",
            input_variables=["query"],
            partial_variables={
                "format_instructions": self._hop_parser.get_format_instructions(),
                "schema_content": self.schema_content
            }
        )
        self._hop_chain = self._hop_prompt | self.llm | self._hop_parser

    def _rule_based_selection(self, query: str) -> HopDecision:
        """Rule-based hop selection using pattern matching"""
        query_lower = query.lower()
        
        # 0-hop patterns: Simple factual questions about single entities
        zero_hop_patterns = [
            r'\bwhat is\b.*\?$', r'\bdefine\b', r'\bexplain\b.*\?$',
            r'\btell me about\b', r'\bwhat does.*mean\b', r'\bdefinition of\b'
        ]
        
        # 1-hop patterns: Direct relationship questions
        one_hop_patterns = [
            r'\bwhat.*exploit\b', r'\bwhat.*mitigate\b', r'\bhow.*defend\b',
            r'\bwhat.*prevent\b', r'\bwhich.*use\b', r'\bhow.*affect\b',
            r'\bwhat.*related to\b', r'\bwhat.*associated with\b'
        ]
        
        # 2-hop patterns: Complex multi-hop questions
        two_hop_patterns = [
            r'\bwhat.*and.*what\b', r'\bcomplete.*path\b', r'\battack chain\b',
            r'\bstep.*by.*step\b', r'\bsequence of\b', r'\bprogression\b',
            r'\bescalation\b', r'\bend.*to.*end\b', r'\bcomprehensive\b'
        ]
        
        # Check patterns in order of complexity
        for pattern in two_hop_patterns:
            if re.search(pattern, query_lower):
                return HopDecision(
                    hop_depth=2,
                    reasoning=f"Complex multi-hop query detected: '{pattern}'",
                    confidence=0.8,
                    method="rule"
                )
        
        for pattern in one_hop_patterns:
            if re.search(pattern, query_lower):
                return HopDecision(
                    hop_depth=1,
                    reasoning=f"Direct relationship query detected: '{pattern}'",
                    confidence=0.8,
                    method="rule"
                )
        
        for pattern in zero_hop_patterns:
            if re.search(pattern, query_lower):
                return HopDecision(
                    hop_depth=0,
                    reasoning=f"Direct entity query detected: '{pattern}'",
                    confidence=0.8,
                    method="rule"
                )
        
        # Default fallback
        return HopDecision(
            hop_depth=1,
            reasoning="No clear pattern detected, defaulting to 1-hop",
            confidence=0.3,
            method="rule"
        )

    def select_hop_depth(self, query: str) -> HopDecision:
        """Select optimal hop depth for query processing"""
        rule_decision = self._rule_based_selection(query)
        
        # Use LLM if confidence is low and LLM is enabled
        if (rule_decision.confidence < self.use_llm_threshold and self.enable_llm):
            try:
                result = self._hop_chain.invoke({"query": query})
                return HopDecision(
                    hop_depth=result.hop_depth,
                    reasoning=f"LLM: {result.reasoning}",
                    confidence=0.9,
                    method="llm"
                )
            except Exception:
                return rule_decision
        
        return rule_decision


class RelationshipPredictor:
    """Schema-aware relationship predictor using UCKG schema."""

    def __init__(self, llm=None, schema_file: str = None):
        self.llm = llm or ChatOllama(model="llama3:8b", temperature=0)
        self.schema_file = schema_file
        
        # Load schema
        self.schema_content = ""
        if schema_file and os.path.exists(schema_file):
            with open(schema_file, 'r') as f:
                self.schema_content = f.read()
        
        self._rel_parser = PydanticOutputParser(pydantic_object=RelationshipPrediction)
        self._rel_prompt = PromptTemplate(
            template="""You are a cybersecurity expert analyzing queries for a GraphRAG system that searches a cybersecurity knowledge graph.

TASK: Predict which relationship types are most relevant for answering the cybersecurity query.

CONTEXT: The system uses a cybersecurity knowledge graph (UCKG) with the following schema:

UCKG Schema:
{schema_content}

EXPLANATION: Different queries require different relationship types to find relevant information. Your job is to identify which relationship patterns will be most useful for answering the specific query.

ANALYSIS PROCESS:
1. **Entity Identification**: Identify the main cybersecurity entities in the query (CVE, CWE, CAPEC, ATT&CK, etc.)
2. **Relationship Analysis**: Determine what type of information the query is seeking (attacks, mitigations, relationships, etc.)
3. **Schema Mapping**: Map the query intent to specific relationship types from the UCKG schema
4. **Relevance Ranking**: Select 2-4 most relevant relationship types that would help answer the query
5. **Output Format**: For each relationship, specify the start and end node types

EXAMPLES OF QUERY-RELATIONSHIP MAPPING:

Query: "What attacks exploit SQL injection vulnerabilities?"
- Entities: SQL injection (CWE), attacks (CAPEC/ATT&CK)
- Intent: Find attack patterns that exploit specific weaknesses
- Relevant Relationships: UCOEXHASRELATEDWEAKNESS (CAPEC→CWE), UCOEXHASRELATEDATTACK (CWE→CAPEC)

Query: "How can I defend against phishing attacks?"
- Entities: phishing (CAPEC/ATT&CK), defense (D3FEND/mitigations)
- Intent: Find defensive measures for specific attacks
- Relevant Relationships: UCOEXMITIGATES (mitigations→attacks), UCOEXHASMITREATTACK (D3FEND→ATT&CK)

Query: "What software does APT28 use?"
- Entities: APT28 (threat group), software
- Intent: Find software/tools used by threat actors
- Relevant Relationships: UCOEXGROUPUSESSOFTWARE (groups→software), UCOEXSOFTWAREUSESTECHNIQUE (software→techniques)

Query: {query}

{format_instructions}

Analyze the query and identify the most relevant relationship types for focused graph traversal.""",
            input_variables=["query"],
            partial_variables={
                "format_instructions": self._rel_parser.get_format_instructions(),
                "schema_content": self.schema_content
            }
        )
        self._rel_chain = self._rel_prompt | self.llm | self._rel_parser

    def predict_relationships(self, query: str) -> Dict[str, Any]:
        """Predict relevant relationship types for query"""
        if not self.llm:
            return {"primary_relationships": [], "method": "disabled"}
        
        try:
            result = self._rel_chain.invoke({"query": query})
            return {
                "primary_relationships": result.primary_relationships,
                "reasoning": result.reasoning,
                "method": "llm_prediction"
            }
        except Exception as e:
            return {
                "primary_relationships": [],
                "reasoning": f"Error: {str(e)}",
                "method": "error"
            }


class QueryRouter:
    """Routes queries to appropriate GraphRAG modes."""

    def __init__(self, llm=None):
        self.llm = llm or ChatOllama(model="llama3:8b", temperature=0)
        
        self.graphrag_patterns = [
            r'\bhow does.*affect\b', r'\bwhat.*mitigates?\b', r'\bwhich.*exploit\b',
            r'\bcomplete.*path\b', r'\battack chain\b'
        ]

    def route_query(self, query: str) -> Tuple[str, int]:
        """Route query to appropriate mode and determine top_k"""
        query_lower = query.lower()
        
        for pattern in self.graphrag_patterns:
            if re.search(pattern, query_lower):
                return "graphrag", 5
        
        return "hybrid", 5


# Convenience functions
def create_hop_selector(llm=None, schema_file: str = None, **kwargs) -> HopSelector:
    return HopSelector(llm=llm, schema_file=schema_file, **kwargs)


def create_relationship_predictor(llm=None, schema_file: str = None) -> RelationshipPredictor:
    return RelationshipPredictor(llm=llm, schema_file=schema_file)


def create_query_router(llm=None) -> QueryRouter:
    return QueryRouter(llm=llm)