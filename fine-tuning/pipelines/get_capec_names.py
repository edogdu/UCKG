import os
import logging
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

def get_names(ids):
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    names = []
    
    with driver.session() as session:
        for node_id in ids:
            # Handle the format "4:uuid:123" -> we need the elementId
            # The grep output gave us the elementId directly
            query = "MATCH (n) WHERE elementId(n) = $eid RETURN n.ucoexCAPEC_name as name"
            result = session.run(query, eid=node_id.strip())
            record = result.single()
            if record and record["name"]:
                names.append(record["name"])
            else:
                logger.warning(f"Could not find name for ID: {node_id}")
    
    driver.close()
    return names

if __name__ == "__main__":
    input_file = "training_capec_list.txt"
    output_file = "training_capec_names.txt"
    
    with open(input_file, 'r') as f:
        ids = [line.strip().strip('"') for line in f if line.strip()]
        
    logger.info(f"Mapping {len(ids)} IDs to Names...")
    names = get_names(ids)
    
    with open(output_file, 'w') as f:
        for name in names:
            f.write(f"{name}\n")
            
    logger.info(f"Done. Saved {len(names)} names to {output_file}")
