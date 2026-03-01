import json
import argparse
import logging
import os
from sft_engine.models.storage.graph.kuzu_storage import KuzuStorage

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_description(props, label):
    """Simple description extraction (No baking)."""
    # Just grab the main description field
    desc_keys = ['Description', 'description', 'summary', 'definition', 'ucoexDescription']
    name_keys = ['Name', 'name', 'title', 'id', 'label', 'ucoexNAME', 'ucoexCAPEC_name']
    
    name = next((str(props[k]) for k in name_keys if k in props), f"Entity ({label})")
    
    # Only grab the primary description
    desc_val = next((str(props[k]) for k in desc_keys if k in props and props[k]), "")
    
    if desc_val:
        return f"{name}: {desc_val}"
    return name

def load_data(input_file, working_dir):
    logger.info(f"[Clean Graph] Initializing KuzuDB at {working_dir}/graph_kuzu")
    os.makedirs(working_dir, exist_ok=True)
    kuzu_storage = KuzuStorage(working_dir=working_dir, namespace="graph")
    
    logger.info(f"Loading data from {input_file}...")
    
    count = 0
    nodes_seen = set()
    
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            row = json.loads(line)
            
            # --- Load Nodes (Simple) ---
            for node_key, label in [("c", "UcoexCAPEC"), ("a", "UcoexMITREATTACK"), ("m", "UcoexMITIGATIONS")]:
                nid = row[f"{node_key}_id"]
                if nid not in nodes_seen:
                    # Note: We still store ALL props in 'data', but 'description' is simple
                    data = {
                        "entity_type": label,
                        "description": get_description(row[node_key], label),
                        "source_id": "uckg_neo4j",
                        **row[node_key]
                    }
                    kuzu_storage.upsert_node(nid, data)
                    nodes_seen.add(nid)

            # --- Load Relationships ---
            # CAPEC -> ATT&CK
            r1 = row["r1"]
            r1_type = "IS_A" if r1["type"] == "UCOEXHASTAXONOMYMAPPING" else r1["type"]
            kuzu_storage.upsert_edge(r1["start"], r1["end"], {
                "relation_type": r1_type, 
                "description": r1_type,
                "source_id": "uckg_neo4j"
            })
            
            # Mitigation -> ATT&CK
            r2 = row["r2"]
            r2_type = "MITIGATES" if r2["type"] == "UCOEXMITIGATES" else r2["type"]
            kuzu_storage.upsert_edge(r2["start"], r2["end"], {
                "relation_type": r2_type, 
                "description": r2_type,
                "source_id": "uckg_neo4j"
            })
            
            count += 1
            if count % 100 == 0:
                logger.info(f"Loaded {count} paths...")
                
    logger.info(f"Finished loading. Processed {count} paths.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Load Clean UCKG Data (Pure Graph)")
    parser.add_argument("--input", default="clean_data.jsonl")
    parser.add_argument("--dir", default="cache")
    args = parser.parse_args()
    
    load_data(args.input, args.dir)
