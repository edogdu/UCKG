import json
import argparse
import logging
from neo4j import GraphDatabase

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def extract_raw_data(uri, user, password, output_file, limit):
    logger.info(f"Connecting to Neo4j at {uri}...")
    driver = GraphDatabase.driver(uri, auth=(user, password))
    
    query = """
        MATCH (c:UcoexCAPEC)-[r1:UCOEXHASTAXONOMYMAPPING]-(a:UcoexMITREATTACK)<-[r2:UCOEXMITIGATES]-(m:UcoexMITIGATIONS)
        RETURN c, r1, a, r2, m
    """
    if limit > 0:
        query += f" LIMIT {limit}"
        
    logger.info(f"Executing query (Limit: {limit})...")
    
    count = 0
    with driver.session() as session:
        result = session.run(query)
        with open(output_file, 'w', encoding='utf-8') as f:
            for record in result:
                # Convert Neo4j Node/Rel objects to standard dicts
                row_data = {
                    "c": dict(record["c"]),
                    "a": dict(record["a"]),
                    "m": dict(record["m"]),
                    "r1": {
                        "type": record["r1"].type, 
                        "props": dict(record["r1"]),
                        "start": record["r1"].start_node.element_id if hasattr(record["r1"].start_node, "element_id") else str(record["r1"].start_node.id),
                        "end": record["r1"].end_node.element_id if hasattr(record["r1"].end_node, "element_id") else str(record["r1"].end_node.id)
                    },
                    "r2": {
                        "type": record["r2"].type, 
                        "props": dict(record["r2"]),
                        "start": record["r2"].start_node.element_id if hasattr(record["r2"].start_node, "element_id") else str(record["r2"].start_node.id),
                        "end": record["r2"].end_node.element_id if hasattr(record["r2"].end_node, "element_id") else str(record["r2"].end_node.id)
                    },
                    # IDs are needed to reconstruct the graph later
                    "c_id": record["c"].element_id if hasattr(record["c"], "element_id") else str(record["c"].id),
                    "a_id": record["a"].element_id if hasattr(record["a"], "element_id") else str(record["a"].id),
                    "m_id": record["m"].element_id if hasattr(record["m"], "element_id") else str(record["m"].id),
                }
                
                # Dump to JSONL
                # Use default=str to handle Datetime objects if any
                f.write(json.dumps(row_data, default=str) + "\n")
                count += 1
                if count % 100 == 0:
                    logger.info(f"Extracted {count} paths...")

    logger.info(f"Done. Saved {count} raw paths to {output_file}")
    driver.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extract Raw UCKG Data to JSONL")
    parser.add_argument("--uri", default="bolt://localhost:7687")
    parser.add_argument("--user", default="neo4j")
    parser.add_argument("--password", default="abcd90909090")
    parser.add_argument("--output", default="raw_data.jsonl")
    parser.add_argument("--limit", type=int, default=1000)
    args = parser.parse_args()
    
    extract_raw_data(args.uri, args.user, args.password, args.output, args.limit)
