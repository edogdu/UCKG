import requests
from typing import List, Any
import json
import numpy as np
from neo4j import GraphDatabase

class OllamaEmbedder:
    def __init__(self, model: str = "nomic-embed-text", ollama_url: str = "http://localhost:11434/api/embeddings"):
        self.model = model
        self.ollama_url = ollama_url

    def embed(self, texts: List[str]) -> List[Any]:
        embeddings = []
        for text in texts:
            payload = {
                "model": self.model,
                "prompt": text
            }
            response = requests.post(self.ollama_url, json=payload)
            response.raise_for_status()
            data = response.json()
            embeddings.append(data["embedding"])
        return embeddings

def store_in_neo4j(chunk_data, uri="bolt://localhost:7687", user="neo4j", password="password"):
    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        for t in chunk_data:
            if isinstance(t['triple'], list):
                for triple in t['triple']:
                    if (
                        isinstance(triple, dict) and
                        all(k in triple for k in ['subject', 'predicate', 'object'])
                    ):
                        session.write_transaction(
                            create_triple, triple['subject'], triple['predicate'], triple['object'], t['context']
                        )
            elif (
                isinstance(t['triple'], dict) and
                all(k in t['triple'] for k in ['subject', 'predicate', 'object'])
            ):
                triple = t['triple']
                session.write_transaction(
                    create_triple, triple['subject'], triple['predicate'], triple['object'], t['context']
                )
    driver.close()

def create_triple(tx, subject, predicate, object_, context):
    tx.run(
        """
        MERGE (s:Entity {name: $subject})
        MERGE (o:Entity {name: $object})
        MERGE (s)-[r:RELATION {type: $predicate, context: $context}]->(o)
        """,
        subject=subject, predicate=predicate, object_=object_, context=context
    )

if __name__ == "__main__":
    
    with open("cti-analysis/chunk_data.json", "r", encoding="utf-8") as f:
        chunk_data = json.load(f)

    print("Storing triples in Neo4j...")
    store_in_neo4j(chunk_data)
    print("Triples stored in Neo4j.\n")

    texts = []
    triple_refs = []

    for t in chunk_data:
        if isinstance(t['triple'], list):
            for triple in t['triple']:
                if (
                    isinstance(triple, dict) and
                    all(k in triple for k in ['subject', 'predicate', 'object'])
                ):
                    text = f"{triple['subject']} {t['context']}"
                    texts.append(text)
                    triple_refs.append((triple, t['context']))
        elif (
            isinstance(t['triple'], dict) and
            all(k in t['triple'] for k in ['subject', 'predicate', 'object'])
        ):
            text = f"{t['triple']['subject']} {t['context']}"
            texts.append(text)
            triple_refs.append((t['triple'], t['context']))

    print(f"Preparing to embed {len(texts)} texts...")

    embedder = OllamaEmbedder()
    embeddings = []
    for idx, text in enumerate(texts, 1):
        print(f"Embedding {idx}/{len(texts)}: {text[:60]}{'...' if len(text) > 60 else ''}")
        embedding = embedder.embed([text])[0]
        embeddings.append(embedding)
    print("All embeddings generated.\n")

    embedding_results = []
    for idx, (triple_info, context) in enumerate(triple_refs):
        result = {
            'context': context,
            'subject': triple_info['subject'],
            'predicate': triple_info['predicate'],
            'object': triple_info['object'],
            'text': f"{triple_info['subject']} {context}",
            'embedding': embeddings[idx]
        }
        embedding_results.append(result)
    
    print(f"Successfully generated embeddings for {len(embedding_results)} triples")
    print("\n" + "="*50)
    print("EMBEDDING RESULTS:")
    print("="*50)
    
    for i, result in enumerate(embedding_results):
        print(f"\n{i+1}. Triple: {result['subject']} —{result['predicate']}→ {result['object']} ({result['context']})")
        print(f"   Subject: {result['subject']}")
        print(f"   Predicate: {result['predicate']}")
        print(f"   Object: {result['object']}")
        print(f"   Context: {result['context']}")
        print(f"   Embedding (first 10 values): {result['embedding'][:10]}")
        print(f"   Embedding length: {len(result['embedding'])}")
        print("-" * 30)
