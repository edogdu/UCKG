

import os
import json
from typing import List, Dict, Any
import numpy as np
from neo4j import GraphDatabase

# Config
NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASS = os.getenv("NEO4J_PASS", "abcd90909090")

OUTPUT_DIR = os.getenv("SIM_OUTPUT_DIR", os.path.join(os.path.dirname(__file__), "outputs"))
BY_NODE_JSON = os.path.join(OUTPUT_DIR, "similarity_results_by_node.json")
LEADERBOARD_JSON = os.path.join(OUTPUT_DIR, "similarity_leaderboard.json")
TOP_K = int(os.getenv("SIM_TOP_K", "5"))
INDEX_NAME = os.getenv("SIM_INDEX_NAME", "node_embedding_vec")
INDEX_LABEL = os.getenv("SIM_INDEX_LABEL", "Vectorized")
INDEX_PROPERTY = os.getenv("SIM_INDEX_PROPERTY", "embedding")
SIM_FUNC = os.getenv("SIM_FUNC", "cosine")  # cosine | euclidean | dot (Neo4j supports cosine and euclidean)

def ensure_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)


def _get_any_vector_dim(session) -> int:
    """Infer vector dimension from any node that has an embedding."""
    rec = session.run(
        f"""
        MATCH (n)
        WHERE n.{INDEX_PROPERTY} IS NOT NULL
        RETURN size(n.{INDEX_PROPERTY}) AS dim
        LIMIT 1
        """
    ).single()
    if not rec or rec["dim"] is None:
        raise RuntimeError("No embeddings found in the graph to infer vector dimension.")
    return int(rec["dim"])


def ensure_vectorized_label(session) -> None:
    """Ensure all nodes with embeddings carry the INDEX_LABEL for indexing."""
    session.run(
        f"""
        MATCH (n)
        WHERE n.{INDEX_PROPERTY} IS NOT NULL AND NOT n:{INDEX_LABEL}
        SET n:{INDEX_LABEL}
        """
    )


def ensure_vector_index(session, dim: int) -> None:
    """Create the vector index if it does not exist."""
    # Neo4j does not allow parameters inside schema options reliably, so inline the dimension.
    session.run(
         f"""
        CREATE VECTOR INDEX {INDEX_NAME} IF NOT EXISTS
        FOR (n:{INDEX_LABEL}) ON (n.{INDEX_PROPERTY})
        OPTIONS {{
          indexConfig: {{
            `vector.dimensions`: {dim},
            `vector.similarity_function`: '{SIM_FUNC}'
          }}
        }}
        """
    )


def fetch_sources(session) -> List[Dict[str, Any]]:
    res = session.run(
        f"""
        MATCH (n:CTIEntity)
        WHERE n.{INDEX_PROPERTY} IS NOT NULL
        RETURN n.id AS uid, n.name AS name, n.type AS type, labels(n) AS labels, n.{INDEX_PROPERTY} AS embedding
        """
    )
    return [dict(r) for r in res]


def topk_from_db(session, embedding: List[float], src_uid: str, k: int) -> List[Dict[str, Any]]:
    # Ask for K+1, exclude self, then take K
    query = f"""
    CALL db.index.vector.queryNodes('{INDEX_NAME}', $kplus, $embedding)
    YIELD node, score
    WITH node, score
    WHERE NOT node:CTIEntity AND coalesce(node.id, elementId(node)) <> $src_id
    RETURN coalesce(node.id, elementId(node)) AS uid,
           node.name AS name,
           node.type AS type,
           labels(node) AS labels,
           node.{INDEX_PROPERTY} AS embedding,
           score AS cosine
    ORDER BY cosine DESC
    LIMIT $k
    """
    return [dict(r) for r in session.run(query, kplus=k + 1, embedding=embedding, src_id=src_uid, k=k)]

def run_similarity() -> None:
    ensure_output_dir()
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))

    with driver.session() as session:
        # Make sure label & index are present
        ensure_vectorized_label(session)
        dim = _get_any_vector_dim(session)
        ensure_vector_index(session, dim)

        sources = fetch_sources(session)

        if not sources:
            print("No CTIEntity sources with embeddings found.")
            return

        by_node: Dict[str, Any] = {}
        leaderboard: List[Dict[str, Any]] = []

        for s in sources:
            s_id = s["uid"] if s.get("uid") is not None else ""
            s_vec = s["embedding"]

            candidates = topk_from_db(session, s_vec, s_id, TOP_K)

            # Compute extra metrics locally for just these K
            s_np = np.asarray(s_vec, dtype=np.float32)
            s_norm = float(np.linalg.norm(s_np)) or 1.0

            top_entries = []
            for c in candidates:
                t_np = np.asarray(c["embedding"], dtype=np.float32)
                dot = float(np.dot(s_np, t_np))
                euc = float(np.linalg.norm(s_np - t_np))
                # cosine from DB is already provided according to SIM_FUNC; if SIM_FUNC != cosine,
                # the field still stores the DB's score but we recompute cosine here for consistency.
                # We'll keep the DB score under key 'db_score' and provide an explicit 'cosine'.
                db_score = float(c["cosine"]) if "cosine" in c else None
                # recompute cosine explicitly
                t_norm = float(np.linalg.norm(t_np)) or 1.0
                cos = float(dot / (s_norm * t_norm))

                entry = {
                    "source": {
                        "uid": s_id,
                        "name": s.get("name"),
                        "type": s.get("type"),
                        "labels": s.get("labels", []),
                    },
                    "target": {
                        "uid": str(c["uid"]),
                        "name": c.get("name"),
                        "type": c.get("type"),
                        "labels": c.get("labels", []),
                    },
                    "scores": {
                        "cosine": cos,
                        "dot": dot,
                        "euclidean": euc,
                        "db_score": db_score,
                    },
                }
                top_entries.append(entry)
                leaderboard.append(entry)

            by_node[str(s_id)] = {
                "source": {
                    "uid": s_id,
                    "name": s.get("name"),
                    "type": s.get("type"),
                    "labels": s.get("labels", []),
                },
                "top_k": top_entries,
            }

    # Sort leaderboard by cosine desc, then dot desc (consistent with NumPy post-metrics)
    leaderboard_sorted = sorted(
        leaderboard,
        key=lambda x: (x["scores"]["cosine"], x["scores"]["dot"]),
        reverse=True,
    )

    with open(BY_NODE_JSON, "w", encoding="utf-8") as f:
        json.dump(by_node, f, ensure_ascii=False, indent=2)
    with open(LEADERBOARD_JSON, "w", encoding="utf-8") as f:
        json.dump(leaderboard_sorted, f, ensure_ascii=False, indent=2)

    print(f"Saved per-node results to: {BY_NODE_JSON}")
    print(f"Saved global leaderboard to: {LEADERBOARD_JSON}")


if __name__ == "__main__":
    run_similarity()