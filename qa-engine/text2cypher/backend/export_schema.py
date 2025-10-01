import json
from logger import get_logger
from neo4j import GraphDatabase

logger = get_logger()

NEO4J_URI = "bolt://localhost:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "abcd90909090"
SCHEMA_JSON_PATH = "cyber_schema.json"

# CYBER_LABELS = [
#     "UcoCVE", "UcoVulnerability", "UcoexCPE", "UcoCWE", "UcoexCAPEC", 
#     "UcoexMITREATTACK", "UcoexMITRED3FEND", "UcoexSOFTWARE", "UcoexGROUPS", 
#     "UcoexMITIGATIONS", "UcoexCAMPAIGNS", "UcoexTACTICS", "UcoexObservedExample"
# ]
# CYBER_RELS = [
#     "UCOHASWEAKNESS", "UCOHASCVE_ID", "UCOHASVULNERABILITY", "UCOEXHASCPE",
#     "UCOEXHASMITREATTACK", "UCOEXGROUPUSESTECHNIQUE", "UCOEXCAMPAIGNUSESTECHNIQUE",
#     "UCOEXSOFTWAREUSESTECHNIQUE", "UCOEXMITIGATES", "UCOEXGROUPUSESSOFTWARE",
#     "UCOEXCAMPAIGNUSESSOFTWARE", "UCOEXATTRIBUTEDTO", "UCOEXHASRELATEDWEAKNESS",
#     "UCOEXHASTAXONOMYMAPPING", "UCOHASOBSERVEDEXAMPLE"
# ]

def safe_ident(name: str) -> str:
    # remove backticks just in case
    return name.replace("`", "")

def export_schema():
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    schema = {"labels": {}, "relationships": {}}
    
    try:
        with driver.session() as session:
            # Get label names
            labels_result = session.run("CALL db.labels() YIELD label RETURN label ORDER BY label")
            labels = [rec["label"] for rec in labels_result]

            for label in labels:
                label_safe = safe_ident(label)
                q = f"MATCH (n:`{label_safe}`) RETURN keys(n) AS properties LIMIT 1"
                try:
                    rec = session.run(q).single()
                    props = rec["properties"] if rec and rec["properties"] else []
                except Exception:
                    props = []
                schema["labels"][label] = sorted(props)

            # Get relationship types
            rels_result = session.run("CALL db.relationshipTypes() YIELD relationshipType RETURN relationshipType ORDER BY relationshipType")
            rels = [rec["relationshipType"] for rec in rels_result]

            for rel in rels:
                rel_safe = safe_ident(rel)
                q = f"MATCH ()-[r:`{rel_safe}`]-() RETURN keys(r) AS properties LIMIT 1"
                try:
                    rec = session.run(q).single()
                    props = rec["properties"] if rec and rec["properties"] else []
                except Exception:
                    props = []
                schema["relationships"][rel] = sorted(props)

    finally:
        driver.close()

    with open(SCHEMA_JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)
    logger.info(f"Schema exported to {SCHEMA_JSON_PATH}")

if __name__ == "__main__":
    export_schema()