import os
import requests
import PyPDF2
import tempfile
import json
import logging
from typing import List, Dict
from neo4j import GraphDatabase
from dotenv import load_dotenv
from rag_utils import get_relevant_context, generate_response

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

load_dotenv()

class AARProcessor:
    def __init__(self):
        self.neo4j_uri = os.getenv("NEO4J_URI", "bolt://neo4j:7687")
        self.neo4j_user = os.getenv("NEO4J_USER", "neo4j")
        self.neo4j_pass = os.getenv("NEO4J_PASS", "abcd90909090")
        self.driver = GraphDatabase.driver(self.neo4j_uri, auth=(self.neo4j_user, self.neo4j_pass))
        
        self.triple_prompt = """
        You are a cybersecurity expert analyzing an After-Action Report (AAR). Extract specific, detailed triples from the text.
        Focus on concrete facts and avoid generic statements.

        For each triple, ensure:
        1. Subjects and objects are specific entities (e.g., "Trend Micro APEX One service" not just "service")
        2. Predicates are action-oriented and specific (e.g., "exploited_vulnerability" not just "has")
        3. Include specific dates, versions, or identifiers when available
        4. Confidence is based on explicit mentions in the text

        Example of good triples:
        {
            "subject": "Trend Micro APEX One v1.2",
            "predicate": "contained_vulnerability",
            "object": "CVE-2023-1234",
            "confidence": "high",
            "source": "page 5"
        }

        Focus on extracting these specific types of information:
        1. Technical Details:
           - Specific software versions and components
           - Exact vulnerability identifiers (CVE, CWE)
           - Technical attack vectors and methods
           - Affected systems and configurations

        2. Timeline and Impact:
           - Specific dates and times of events
           - Quantified impact (e.g., "5000 systems affected")
           - Specific business processes impacted
           - Financial or operational metrics

        3. Response Actions:
           - Specific mitigation steps taken
           - Exact patch versions applied
           - Specific security controls implemented
           - Detailed incident response procedures

        4. Lessons and Recommendations:
           - Specific gaps identified
           - Concrete improvement recommendations
           - Specific training or process changes
           - Exact policy or procedure updates

        Return a JSON array of these triples. Each triple must be specific and detailed.
        """

    def process_pdf(self, pdf_url: str, store_in_neo4j: bool = True) -> Dict:
        """Process a PDF and extract triples"""
        try:
            # Download and extract text from PDF
            text = self._download_and_extract_pdf(pdf_url)
            if not text:
                return {"error": "Failed to process PDF"}

            # Extract triples using RAG
            triples = self._extract_triples_with_rag(text)
            
            # Store in Neo4j if requested
            if store_in_neo4j and triples:
                self._store_triples_in_neo4j(triples)
            
            return {
                "status": "success",
                "triples": triples,
                "total_triples": len(triples)
            }
            
        except Exception as e:
            logger.error(f"Error processing PDF: {e}")
            return {"error": str(e)}

    def _download_and_extract_pdf(self, url: str) -> str:
        """Download PDF and extract text"""
        try:
            response = requests.get(url)
            response.raise_for_status()
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_file:
                temp_file.write(response.content)
                temp_path = temp_file.name
            
            text = ""
            with open(temp_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                for page in pdf_reader.pages:
                    text += page.extract_text() + "\n"
            
            os.unlink(temp_path)
            return text
            
        except Exception as e:
            logger.error(f"Error processing PDF: {e}")
            return ""

    def _extract_triples_with_rag(self, text: str) -> List[Dict]:
        """Extract triples using LLM without RAG context"""
        try:
            # Split text into meaningful chunks (by paragraphs or sections)
            chunks = self._split_into_meaningful_chunks(text)
            
            all_triples = []
            for chunk in chunks:
                # Process each chunk directly with the LLM
                response = generate_response(
                    query=self.triple_prompt + f"\n\nText to analyze:\n{chunk}",
                    context=[],  # Don't use RAG context
                    graph_context=False
                )
                
                try:
                    triples = json.loads(response)
                    if isinstance(triples, list):
                        # Filter out generic or low-quality triples
                        filtered_triples = [
                            t for t in triples 
                            if self._is_quality_triple(t)
                        ]
                        all_triples.extend(filtered_triples)
                except json.JSONDecodeError:
                    logger.warning(f"Failed to parse JSON from LLM response: {response}")
            
            # Deduplicate triples
            return self._deduplicate_triples(all_triples)
            
        except Exception as e:
            logger.error(f"Error extracting triples: {e}")
            return []

    def _split_into_meaningful_chunks(self, text: str) -> List[str]:
        """Split text into meaningful chunks based on content structure"""
        # Split by double newlines (paragraphs)
        paragraphs = [p.strip() for p in text.split('\n\n') if p.strip()]
        
        chunks = []
        current_chunk = []
        current_size = 0
        
        for para in paragraphs:
            if current_size + len(para) > 2000:
                if current_chunk:
                    chunks.append('\n\n'.join(current_chunk))
                current_chunk = [para]
                current_size = len(para)
            else:
                current_chunk.append(para)
                current_size += len(para) + 2  # +2 for the newlines
        
        if current_chunk:
            chunks.append('\n\n'.join(current_chunk))
        
        return chunks

    def _is_quality_triple(self, triple: Dict) -> bool:
        """Check if a triple is of good quality"""
        # Check for specific entities (not generic)
        if any(x in triple['subject'].lower() for x in ['incident', 'attack', 'vulnerability']):
            return False
        
        # Check for specific predicates
        if any(x in triple['predicate'].lower() for x in ['has', 'is', 'was', 'were']):
            return False
        
        # Check for specific objects
        if any(x in triple['object'].lower() for x in ['incident', 'attack', 'vulnerability']):
            return False
        
        # Check for minimum length
        if len(triple['subject'].split()) < 2 or len(triple['object'].split()) < 2:
            return False
        
        return True

    def _deduplicate_triples(self, triples: List[Dict]) -> List[Dict]:
        """Remove duplicate or very similar triples"""
        seen = set()
        unique_triples = []
        
        for triple in triples:
            # Create a unique key for the triple
            key = (triple['subject'].lower(), 
                  triple['predicate'].lower(), 
                  triple['object'].lower())
            
            if key not in seen:
                seen.add(key)
                unique_triples.append(triple)
        
        return unique_triples

    def _store_triples_in_neo4j(self, triples: List[Dict]):
        """Store extracted triples in Neo4j"""
        with self.driver.session() as session:
            for triple in triples:
                query = """
                MERGE (s:Entity {name: $subject})
                MERGE (o:Entity {name: $object})
                MERGE (s)-[r:RELATION {type: $predicate}]->(o)
                SET r.confidence = $confidence,
                    r.source = $source
                """
                session.run(query, 
                          subject=triple['subject'],
                          predicate=triple['predicate'],
                          object=triple['object'],
                          confidence=triple.get('confidence', 'medium'),
                          source=triple.get('source', 'AAR')) 