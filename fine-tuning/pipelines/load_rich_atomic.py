import json
import argparse
import logging
import os
from sft_engine.models.storage.graph.kuzu_storage import KuzuStorage

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_description(props, label):
    """Heuristic to generate a description string with rich context."""
    name_keys = ['Name', 'name', 'title', 'id', 'label', 'ucoexNAME', 'ucoexCAPEC_name']
    name = next((str(props[k]) for k in name_keys if k in props), f"Entity ({label})")
    
    lines = []
    # 1. Main Description
    # Check simplified keys first, then original keys
    desc_val = props.get('Description') or props.get('ucoexDescription') or props.get('ucoexDESCRIPTION')
    if desc_val:
        lines.append(f"Description: {desc_val}")

    # 2. Rich Context Fields - COMMENTED OUT FOR THIN NODE EXPERIMENT
    # Map of Display Header -> Property Key(s) to check
    # rich_fields = {
    #     "Mitigations": ["Mitigations", "ucoexMitigations", "ucopotentialMitigations"],
    #     "Technique Steps": ["Technique", "ucoexExecutionFlowTechnique"],
    #     "Prerequisites": ["Prerequisites", "ucoexPrerequisites"],
    #     "Example": ["Example", "ucoexExample"],
    #     "Consequences": ["Consequences", "ucoexConsequences"]
    # }

    # for header, keys in rich_fields.items():
    #     # Find the first key that exists
    #     val = next((props[k] for k in keys if k in props and props[k]), None)
    #     if val:
    #         if isinstance(val, list):
    #             # Join list items with bullets
    #             val_str = "\n- ".join(str(x) for x in val)
    #             lines.append(f"{header}:\n- {val_str}")
    #         else:
    #             lines.append(f"{header}: {val}")

    full_desc = "\n\n".join(lines)
    
    if full_desc:
        return f"{name}\n\n{full_desc}"
    return name

def load_data(input_file, working_dir):
    logger.info(f"Initializing KuzuDB at {working_dir}/graph_kuzu")
    os.makedirs(working_dir, exist_ok=True)
    kuzu_storage = KuzuStorage(working_dir=working_dir, namespace="graph")
    
    # Optional: Clear existing data
    # kuzu_storage.clear() 
    
    logger.info(f"Loading data from {input_file}...")
    
    # Load allowed CAPEC names
    allowed_names_file = os.path.join(os.path.dirname(__file__), "test_set_capec_names.txt")
    allowed_names = set()
    if os.path.exists(allowed_names_file):
        with open(allowed_names_file, 'r') as f:
            allowed_names = {line.strip() for line in f if line.strip()}
        logger.info(f"Loaded {len(allowed_names)} allowed CAPEC names for filtering.")
    else:
        logger.warning(f"Allowed names file not found at {allowed_names_file}. Proceeding without filtering.")

    count = 0
    nodes_seen = set()
    
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            row = json.loads(line)
            
            # --- Load Nodes ---
            # CAPEC
            c_id = row["c_id"]
            
            # FILTER: Only load if in allowed list (if list exists)
            if allowed_names and c_id not in allowed_names:
                continue

            if c_id not in nodes_seen:
                data = {
                    "entity_type": "UcoexCAPEC",
                    "description": get_description(row["c"], "UcoexCAPEC"),
                    "source_id": "uckg_neo4j",
                    **row["c"]
                }
                kuzu_storage.upsert_node(c_id, data)
                nodes_seen.add(c_id)
                
            # ATT&CK - COMMENTED OUT FOR CAPEC-ONLY EXPERIMENT
            # a_id = row["a_id"]
            # if a_id not in nodes_seen:
            #     data = {
            #         "entity_type": "UcoexMITREATTACK",
            #         "description": get_description(row["a"], "UcoexMITREATTACK"),
            #         "source_id": "uckg_neo4j",
            #         **row["a"]
            #     }
            #     kuzu_storage.upsert_node(a_id, data)
            #     nodes_seen.add(a_id)
                
            # Mitigation - COMMENTED OUT FOR CAPEC-ONLY EXPERIMENT
            # m_id = row["m_id"]
            # if m_id not in nodes_seen:
            #     data = {
            #         "entity_type": "UcoexMITIGATIONS",
            #         "description": get_description(row["m"], "UcoexMITIGATIONS"),
            #         "source_id": "uckg_neo4j",
            #         **row["m"]
            #     }
            #     kuzu_storage.upsert_node(m_id, data)
            #     nodes_seen.add(m_id)
                
            # --- Load Relationships ---
            # CAPEC -> ATT&CK - COMMENTED OUT
            # r1 = row["r1"]
            # r1_type = r1["type"]
            # # Polish Relationship Names for LLM readability
            # if r1_type == "UCOEXHASTAXONOMYMAPPING":
            #     r1_type = "IS_A"
            
            # r1_data = {
            #     "relation_type": r1_type,
            #     "description": r1_type,
            #     "source_id": "uckg_neo4j",
            #     **r1.get("props", {})
            # }
            # kuzu_storage.upsert_edge(r1["start"], r1["end"], r1_data)
            
            # Mitigation -> ATT&CK - COMMENTED OUT
            # r2 = row["r2"]
            # r2_type = r2["type"]
            # if r2_type == "UCOEXMITIGATES":
            #     r2_type = "MITIGATES"

            # r2_data = {
            #     "relation_type": r2_type,
            #     "description": r2_type,
            #     "source_id": "uckg_neo4j",
            #     **r2.get("props", {})
            # }
            # kuzu_storage.upsert_edge(r2["start"], r2["end"], r2_data)
            
            count += 1
            if count % 100 == 0:
                logger.info(f"Loaded {count} paths...")
                
    logger.info(f"Finished loading. Processed {count} paths.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Load Clean UCKG Data to GraphGen")
    parser.add_argument("--input", default="clean_data.jsonl")
    parser.add_argument("--dir", default="cache")
    args = parser.parse_args()
    
    load_data(args.input, args.dir)
