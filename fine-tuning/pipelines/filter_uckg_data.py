import json
import argparse
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Define which properties to KEEP for each node type
# We use the key prefix to identify the node type in the dictionary or just check common fields
WHITELIST = {
    "c": { # CAPEC
        "ucoexCAPEC_name", 
        "ucoexDescription", 
        "ucoexExample", 
        "ucoexExecutionFlowTechnique", 
        "ucoexMitigations", 
        "ucoexPrerequisites",
        "ucoexSkill_Level",
        "ucoexConsequences"
    },
    "a": { # ATT&CK
        "ucoexNAME", 
        "ucoexDESCRIPTION"
    },
    "m": { # MITIGATION
        "ucoexNAME", 
        "ucoexDESCRIPTION"
    }
}

def filter_dict(d, node_key):
    """Keep only whitelisted keys from the dictionary."""
    if not d:
        return {}
        
    filtered = {}
    allowed_keys = WHITELIST.get(node_key, set())
    
    for k, v in d.items():
        if k in allowed_keys:
            filtered[k] = v
            
    return filtered

def filter_data(input_file, output_file):
    logger.info(f"Filtering data from {input_file}...")
    
    count = 0
    with open(input_file, 'r', encoding='utf-8') as fin, \
         open(output_file, 'w', encoding='utf-8') as fout:
        
        for line in fin:
            raw_row = json.loads(line)
            
            # Apply filter to each node
            filtered_row = {
                "c": filter_dict(raw_row.get("c"), "c"),
                "a": filter_dict(raw_row.get("a"), "a"),
                "m": filter_dict(raw_row.get("m"), "m"),
                # Keep IDs and relationships as is (they are structural)
                "r1": raw_row["r1"],
                "r2": raw_row["r2"],
                "c_id": raw_row["c_id"],
                "a_id": raw_row["a_id"],
                "m_id": raw_row["m_id"]
            }
            
            fout.write(json.dumps(filtered_row) + "\n")
            count += 1
            if count % 1000 == 0:
                logger.info(f"Filtered {count} rows...")
                
    logger.info(f"Done. Filtered {count} rows. Saved to {output_file}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Filter UCKG Data Properties")
    parser.add_argument("--input", default="raw_data.jsonl")
    parser.add_argument("--output", default="filtered_data.jsonl")
    args = parser.parse_args()
    
    filter_data(args.input, args.output)
