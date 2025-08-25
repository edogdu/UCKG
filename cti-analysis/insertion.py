from neo4j import GraphDatabase
import requests
from typing import List, Any
import json
import numpy as np
import hashlib

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

def make_det_id(name: str, ntype: str) -> str:
    key = f"{(ntype or '').strip().lower()}|{(name or '').strip().lower()}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()

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

                        if subj is None or obj is None:
                            print("Skipping triple due to null subject or object.")
                            continue

                        subj_name = subj['name'] if isinstance(subj, dict) and 'name' in subj else subj
                        subj_type = subj.get('type', '') if isinstance(subj, dict) else ''
                        obj_name = obj['name'] if isinstance(obj, dict) and 'name' in obj else obj
                        obj_type = obj.get('type', '') if isinstance(obj, dict) else ''

                        if not subj_name or not obj_name:
                            print("Skipping triple due to empty subject or object name.")
                            continue

                        print(f"Adding subject node: name='{subj_name}', class='{subj_type}', context='{context}'")
                        print(f"Adding object node: name='{obj_name}', class='{obj_type}', context='{context}'")
                        print(f"Adding relationship: {subj_name} -[{triple['predicate']}]-> {obj_name}")
                        subj_id = make_det_id(subj_name, subj_type)
                        obj_id = make_det_id(obj_name, obj_type)
                        session.execute_write(
                            create_triple,
                            subj_id, subj_name, subj_type,
                            triple['predicate'],
                            obj_id, obj_name, obj_type,
                            context,
                        )
            elif (
                isinstance(triples, dict) and
                all(k in triples for k in ['subject', 'predicate', 'object'])
            ):
                subj = triples['subject']
                obj = triples['object']


                if subj is None or obj is None:
                    print("Skipping triple due to null subject or object.")
                    continue

                subj_name = subj['name'] if isinstance(subj, dict) and 'name' in subj else subj
                subj_type = subj.get('type', '') if isinstance(subj, dict) else ''
                obj_name = obj['name'] if isinstance(obj, dict) and 'name' in obj else obj
                obj_type = obj.get('type', '') if isinstance(obj, dict) else ''

                if not subj_name or not obj_name:
                    print("Skipping triple due to empty subject or object name.")
                    continue

                print(f"Adding subject node: name='{subj_name}', type='{subj_type}', context='{context}'")
                print(f"Adding object node: name='{obj_name}', type='{obj_type}', context='{context}'")
                print(f"Adding relationship: {subj_name} -[{triples['predicate']}]-> {obj_name}")
                subj_id = make_det_id(subj_name, subj_type)
                obj_id = make_det_id(obj_name, obj_type)
                session.execute_write(
                    create_triple,
                    subj_id, subj_name, subj_type,
                    triples['predicate'],
                    obj_id, obj_name, obj_type,
                    context,
                )
    driver.close()

def create_triple(tx, subject_id, subject, sub_type, predicate, object_id, object_, obj_type, context):
    tx.run(
        """
        MERGE (s:CTIEntity {id: $subject_id})
        ON CREATE SET s.name = $subject,
                      s.type = $sub_type,
                      s.contexts = [$context]
        ON MATCH  SET s.type = coalesce(s.type, $sub_type),
                      s.name = coalesce(s.name, $subject),
                      s.contexts = CASE
                          WHEN s.contexts IS NULL THEN [$context]
                          ELSE s.contexts + CASE WHEN $context IN s.contexts THEN [] ELSE [$context] END
                      END
        MERGE (o:CTIEntity {id: $object_id})
        ON CREATE SET o.name = $object,
                      o.type = $obj_type,
                      o.contexts = [$context]
        ON MATCH  SET o.type = coalesce(o.type, $obj_type),
                      o.name = coalesce(o.name, $object),
                      o.contexts = CASE
                          WHEN o.contexts IS NULL THEN [$context]
                          ELSE o.contexts + CASE WHEN $context IN o.contexts THEN [] ELSE [$context] END
                      END
        MERGE (s)-[r:RELATION {type: $predicate}]->(o)
        """,
        subject_id=subject_id,
        subject=subject,
        sub_type=sub_type,
        predicate=predicate,
        object_id=object_id,
        object=object_,
        obj_type=obj_type,
        context=context,
    )

def embed_cti_entities_from_chunk(chunk_data,
                                  uri: str = "bolt://localhost:7687",
                                  user: str = "neo4j",
                                  password: str = "abcd90909090",
                                  model: str = "nomic-embed-text",
                                  ollama_url: str = "http://localhost:11434/api/embeddings"):

    # Aggregate contexts per (name, type)
    node_dict = {}
    for t in chunk_data:
        triples = t.get('triple', [])
        context = t.get('context', '')
        if isinstance(triples, list):
            it = triples
        elif isinstance(triples, dict) and all(k in triples for k in ['subject','predicate','object']):
            it = [triples]
        else:
            it = []
        for triple in it:
            if not (isinstance(triple, dict) and all(k in triple for k in ['subject','predicate','object'])):
                continue
            for node in (triple['subject'], triple['object']):
                if node is None:
                    continue
                name = node['name'] if isinstance(node, dict) and 'name' in node else node
                ntype = node.get('type', '') if isinstance(node, dict) else ''
                if not name:
                    continue
                key = (name, ntype)
                if key not in node_dict:
                    node_dict[key] = set()
                if context:
                    node_dict[key].add(context)

    # Persist aggregated contexts into Neo4j (idempotent add)
    driver = GraphDatabase.driver(uri, auth=(user, password))
    with driver.session() as session:
        for (name, ntype), contexts in node_dict.items():
            nid = make_det_id(name, ntype)
            session.run(
                """
                MATCH (n:CTIEntity {id:$id})
                SET n.contexts = coalesce(n.contexts, []) + [x IN $contexts WHERE NOT x IN coalesce(n.contexts, [])]
                """,
                id=nid,
                contexts=sorted(contexts),
            )

    # Build texts for embedding
    node_texts = []
    node_refs = []
    for (name, ntype), contexts in node_dict.items():
        context_text = "\n".join(sorted(contexts))
        text = f"name: {name}\ntype: {ntype}\ncontexts:\n{context_text}".strip()
        node_texts.append(text)
        node_refs.append({'name': name, 'type': ntype, 'contexts': context_text})

    # Compute embeddings
    embedder = OllamaEmbedder(model=model, ollama_url=ollama_url)
    embeddings = embedder.embed(node_texts) if node_texts else []

    # Write embeddings back
    with driver.session() as session:
        for idx, node in enumerate(node_refs):
            name = node['name']
            ntype = node['type']
            nid = make_det_id(name, ntype)
            session.run(
                """
                MATCH (n:CTIEntity {id: $id})
                SET n.embedding = $embedding, n:Vectorized
                """,
                id=nid,
                embedding=embeddings[idx],
            )
    driver.close()

    # Return a simple summary for callers if they want it
    return [{
        'name': ref['name'],
        'type': ref['type'],
        'embedding_len': len(embeddings[i]) if i < len(embeddings) else 0
    } for i, ref in enumerate(node_refs)]

if __name__ == "__main__":
    
    with open("cti-analysis/extracted_triples/chunk_data_gemma2_9b.json", "r", encoding="utf-8") as f:
        chunk_json = json.load(f)
        chunk_data = chunk_json["data"] if "data" in chunk_json else chunk_json

    print("Storing triples in Neo4j...")
    store_in_neo4j(chunk_data)
    print("Triples stored in Neo4j. Now embedding CTIEntity nodes...")

    results = embed_cti_entities_from_chunk(
        chunk_data,
        uri="bolt://localhost:7687",
        user="neo4j",
        password="abcd90909090",
        model="nomic-embed-text",
        ollama_url="http://localhost:11434/api/embeddings",
    )
    print(f"Embedded {len(results)} CTIEntity nodes.")
