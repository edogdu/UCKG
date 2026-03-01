import os
import logging
import csv
from neo4j import GraphDatabase
from dotenv import load_dotenv

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Load env from root
dotenv_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', '.env')
load_dotenv(dotenv_path=dotenv_path)

NEO4J_URI = os.getenv('NEO4J_URI', 'bolt://localhost:7687')
NEO4J_USER = os.getenv('NEO4J_USER', 'neo4j')
NEO4J_PASSWORD = os.getenv('NEO4J_PASSWORD')

def get_names_map(ids):
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    id_name_map = []
    
    with driver.session() as session:
        for node_id in ids:
            query = "MATCH (n) WHERE elementId(n) = $eid RETURN n.ucoexCAPEC_name as name"
            result = session.run(query, eid=node_id.strip())
            record = result.single()
            if record and record["name"]:
                id_name_map.append((node_id, record["name"]))
            else:
                logger.warning(f"Could not find name for ID: {node_id}")
                id_name_map.append((node_id, "Unknown"))
    
    driver.close()
    return id_name_map

if __name__ == "__main__":
    input_file = "test_set_capec_names.txt"
    output_file = "training_30_map.csv"
    
    if not os.path.exists(input_file):
        logger.error(f"Input file not found: {input_file}")
        exit(1)

    with open(input_file, 'r') as f:
        ids = [line.strip().strip('"') for line in f if line.strip()]
        
    logger.info(f"Mapping {len(ids)} IDs to Names...")
    mapping = get_names_map(ids)
    
    with open(output_file, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(["ID", "Name"])
        writer.writerows(mapping)
            
    logger.info(f"Done. Saved mapping to {output_file}")
