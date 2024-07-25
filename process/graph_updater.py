import os
import time
import logging
from neo4j import GraphDatabase

# Configure the logging module
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d, %(funcName)s)')

# Create a logger
logger = logging.getLogger('graph_updater_logger')

# Function to load TTL file
def load_ttl_file(driver, file_path):
       with driver.session() as session:
            try:
                session.write_transaction(_load_ttl, file_path)
                logger.info(f"Successfully loaded TTL file from {file_path}")
            except Exception as e:
                logger.info(f"Error loading TTL file: {e}")

def _load_ttl(tx, file_path):
    final_file_path = "file://" + file_path
    query = (
        "CALL n10s.rdf.import.fetch($file_path, 'Turtle')"
    )
    logger.info("################# Final File Path")
    logger.info(final_file_path)
    tx.run(query, file_path=final_file_path)

def create_constraint_if_not_exists(driver):
    label = 'Resource'
    property_name = 'uri'
    constraint_name = 'n10s_unique_uri'
    constraint_description = f"CONSTRAINT ON ({label.lower()}:{label}) ASSERT {label.lower()}.{property_name} IS UNIQUE"

    with driver.session() as session:
        # Query to check if the specific constraint exists
        result = session.run("SHOW CONSTRAINTS")
        constraints = [record["name"] for record in result]

        if any(constraint_name in constraint for constraint in constraints):
            logger.info("Constraint already exists.")
        else:
            # Create the constraint as it does not exist
            session.run(f"CREATE CONSTRAINT {constraint_name} ON ({label.lower()}:{label}) ASSERT {label.lower()}.{property_name} IS UNIQUE")
            logger.info("Constraint created.")

def is_graph_ready():
    uri = "bolt://neo4j:7687" 
    username = "neo4j"
    password = "abcd90909090"
    start_time = time.time()
    while time.time() - start_time < 60:
        try:
            # Attempt to create a Neo4j session
            driver = GraphDatabase.driver(uri, auth=(username, password))
            with driver.session() as session:
                # Run a simple query to check the connection
                session.run("RETURN 1")
                logger.info("Neo4j is ready.")
                return True
        except Exception:
            # If connection fails, wait for a bit before retrying
            logger.info("Waiting for Neo4j to start...")
            time.sleep(5)
        finally:
            # Ensure the driver is closed properly
            if 'driver' in locals():
                driver.close()
    logger.info("Timed out waiting for Neo4j to start.")
    return False


def update_graph():
    uco_ontology = os.environ['UCO_ONTO_PATH']
    root_folder = os.environ['ROOT_FOLDER']
    vol_path = os.environ['VOL_PATH']

    uri = "bolt://neo4j:7687" 
    username = "neo4j"
    password = "abcd90909090"


    # Connect to Neo4j
    driver = GraphDatabase.driver(uri, auth=(username, password))

    ttl_file_path = os.path.join(vol_path, "uco_with_instances.ttl")

    # Print the contents of the TTL file
    # print(f"Contents of {ttl_file_path}:")
    # with open(ttl_file_path, 'r') as file:
    #     print(file.read())

    # Make sure RDF constraint is added
    create_constraint_if_not_exists(driver)

    # Load the TTL file
    load_ttl_file(driver, ttl_file_path)

    # Remove uco_with_instances.ttl
    os.remove(ttl_file_path)
    logger.info(">>>>>>>>>>>>> removed uco_with_instances.ttl")



    driver.close()