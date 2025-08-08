from neo4j import GraphDatabase
import requests
from typing import List, Any
import json
import numpy as np

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

def store_in_neo4j(chunk_data, uri="bolt://localhost:7687", user="neo4j", password="abcd90909090"):
    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        for d in chunk_data:
            triples = d.get('triple', [])
            context = d.get('context', '')
            if isinstance(triples, list):
                for triple in triples:
                    if (
                        isinstance(triple, dict) and
                        all(k in triple for k in ['subject', 'predicate', 'object'])
                    ):
                        subj = triple['subject']
                        obj = triple['object']

                        # Null checks for subject and object
                        if subj is None or obj is None:
                            print("Skipping triple due to null subject or object.")
                            continue

                        subj_name = subj['name'] if isinstance(subj, dict) and 'name' in subj else subj
                        subj_type = subj.get('type', '') if isinstance(subj, dict) else ''
                        obj_name = obj['name'] if isinstance(obj, dict) and 'name' in obj else obj
                        obj_type = obj.get('type', '') if isinstance(obj, dict) else ''

                        # Additional null/empty checks for names
                        if not subj_name or not obj_name:
                            print("Skipping triple due to empty subject or object name.")
                            continue

                        print(f"Adding subject node: name='{subj_name}', type='{subj_type}', context='{context}'")
                        print(f"Adding object node: name='{obj_name}', type='{obj_type}', context='{context}'")
                        print(f"Adding relationship: {subj_name} -[{triple['predicate']}]-> {obj_name}")
                        session.write_transaction(
                            create_triple, subj_name, subj_type, triple['predicate'], obj_name, obj_type, context
                        )
            elif (
                isinstance(triples, dict) and
                all(k in triples for k in ['subject', 'predicate', 'object'])
            ):
                subj = triples['subject']
                obj = triples['object']

                # Null checks for subject and object
                if subj is None or obj is None:
                    print("Skipping triple due to null subject or object.")
                    continue

                subj_name = subj['name'] if isinstance(subj, dict) and 'name' in subj else subj
                subj_type = subj.get('type', '') if isinstance(subj, dict) else ''
                obj_name = obj['name'] if isinstance(obj, dict) and 'name' in obj else obj
                obj_type = obj.get('type', '') if isinstance(obj, dict) else ''

                # Additional null/empty checks for names
                if not subj_name or not obj_name:
                    print("Skipping triple due to empty subject or object name.")
                    continue

                print(f"Adding subject node: name='{subj_name}', type='{subj_type}', context='{context}'")
                print(f"Adding object node: name='{obj_name}', type='{obj_type}', context='{context}'")
                print(f"Adding relationship: {subj_name} -[{triples['predicate']}]-> {obj_name}")
                session.write_transaction(
                    create_triple, subj_name, subj_type, triples['predicate'], obj_name, obj_type, context
                )
    driver.close()

def create_triple(tx, subject, sub_type, predicate, object_, obj_type, context):
    tx.run(
        """
        MERGE (s:Entity {type: $sub_type, name: $subject})
        ON CREATE SET s.context = $context
        ON MATCH SET s.context = coalesce(s.context, $context)
        MERGE (o:Entity {type: $obj_type, name: $object})
        ON CREATE SET o.context = $context
        ON MATCH SET o.context = coalesce(o.context, $context)
        MERGE (s)-[r:RELATION {type: $predicate}]->(o)
        """,
        subject=subject, sub_type=sub_type, predicate=predicate, object=object_, obj_type=obj_type, context=context
    )

if __name__ == "__main__":
    
    with open("cti-analysis/extracted_triples/chunk_data_gemma2_9b.json", "r", encoding="utf-8") as f:
        chunk_json = json.load(f)
        chunk_data = chunk_json["data"] if "data" in chunk_json else chunk_json

    print("Storing triples in Neo4j...")
    store_in_neo4j(chunk_data)
    print("Triples stored in Neo4j.\n")

    # --- Embedding steps: only nodes (subject/object), not relationships ---
    node_texts = []
    node_refs = []

    # Collect unique nodes with their type and all contexts
    node_dict = {}
    for t in chunk_data:
        triples = t.get('triple', [])
        context = t.get('context', '')
        if isinstance(triples, list):
            for triple in triples:
                if (
                    isinstance(triple, dict) and
                    all(k in triple for k in ['subject', 'predicate', 'object'])
                ):
                    for node, node_type in [(triple['subject'], 'subject'), (triple['object'], 'object')]:
                        if node is None:
                            continue
                        name = node['name'] if isinstance(node, dict) and 'name' in node else node
                        ntype = node.get('type', '') if isinstance(node, dict) else ''
                        key = (name, ntype)
                        if not name:
                            continue
                        if key not in node_dict:
                            node_dict[key] = set()
                        if context:
                            node_dict[key].add(context)
        elif (
            isinstance(triples, dict) and
            all(k in triples for k in ['subject', 'predicate', 'object'])
        ):
            for node, node_type in [(triples['subject'], 'subject'), (triples['object'], 'object')]:
                if node is None:
                    continue
                name = node['name'] if isinstance(node, dict) and 'name' in node else node
                ntype = node.get('type', '') if isinstance(node, dict) else ''
                key = (name, ntype)
                if not name:
                    continue
                if key not in node_dict:
                    node_dict[key] = set()
                if context:
                    node_dict[key].add(context)

    for (name, ntype), contexts in node_dict.items():
        # Combine all contexts for this node
        context_str = " | ".join(sorted(contexts))
        text = f"type: {ntype}\nname: {name}\ncontext: {context_str}"
        node_texts.append(text)
        node_refs.append({'name': name, 'type': ntype, 'contexts': context_str})

    print(f"Preparing to embed {len(node_texts)} unique nodes...")

    embedder = OllamaEmbedder()
    embeddings = []
    for idx, text in enumerate(node_texts, 1):
        print(f"Embedding node {idx}/{len(node_texts)}: {text[:60]}{'...' if len(text) > 60 else ''}")
        embedding = embedder.embed([text])[0]
        embeddings.append(embedding)
    print("All node embeddings generated.\n")

    embedding_results = []
    for idx, node in enumerate(node_refs):
        result = {
            'name': node['name'],
            'type': node['type'],
            'contexts': node['contexts'],
            'text': node_texts[idx],
            'embedding': embeddings[idx]
        }
        embedding_results.append(result)

    print(f"Successfully generated embeddings for {len(embedding_results)} nodes")
    print("\n" + "="*50)
    print("NODE EMBEDDING RESULTS:")
    print("="*50)

    for i, result in enumerate(embedding_results):
        print(f"\n{i+1}. Node: {result['name']} (type: {result['type']})")
        print(f"   Context(s): {result['contexts']}")
        print(f"   Embedding (first 10 values): {result['embedding'][:10]}")
        print(f"   Embedding length: {len(result['embedding'])}")
        print("-" * 30)
