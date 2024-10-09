import os
import time
import logging
from neo4j import GraphDatabase

# Configure the logging module for consistent and clear log messages
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d, %(funcName)s)')

# Create a logger specifically for the graph updater
logger = logging.getLogger('graph_updater_logger')

# Function to load TTL file into Neo4j
def load_ttl_file(driver, file_path: str) -> None:
    """Load a TTL file into the Neo4j database."""
    with driver.session() as session:
        try:
            session.write_transaction(_load_ttl, file_path)
            logger.info(f"Successfully loaded TTL file from {file_path}")
        except Exception as e:
            logger.error(f"Error loading TTL file: {e}")
            # Better error handling: Captures and logs detailed exception messages

# Helper function to perform the actual TTL import via Cypher
def _load_ttl(tx, file_path: str) -> None:
    """Transaction function to load TTL using Cypher."""
    final_file_path = "file://" + file_path
    query = (
        "CALL n10s.rdf.import.fetch($file_path, 'Turtle')"  # Using the Neo4j RDF procedure for importing TTL files
    )
    logger.info("################# Final File Path")  # Log file path for better traceability
    logger.info(final_file_path)
    tx.run(query, file_path=final_file_path)

# Function to check if a unique constraint exists and create it if not
def create_constraint_if_not_exists(driver) -> None:
    """Create a unique constraint on the Resource label if it doesn't already exist."""
    label = 'Resource'
    property_name = 'uri'
    constraint_name = 'n10s_unique_uri'  # Naming the constraint
    constraint_description = f"CONSTRAINT ON ({label.lower()}:{label}) ASSERT {label.lower()}.{property_name} IS UNIQUE"

    with driver.session() as session:
        result = session.run("SHOW CONSTRAINTS")
        constraints = [record["name"] for record in result]

        # Check if the specific constraint already exists
        if any(constraint_name in constraint for constraint in constraints):
            logger.info("Constraint already exists.")
        else:
            # Create the constraint if it doesn't exist
            session.run(f"CREATE CONSTRAINT {constraint_name} ON ({label.lower()}:{label}) ASSERT {label.lower()}.{property_name} IS UNIQUE")
            logger.info("Constraint created.")
        # DRY principle: Avoided repetitive constraint creation code by using a single function for checking and creating

# Function to check if Neo4j is ready to accept connections
def is_graph_ready() -> bool:
    """Check if Neo4j is ready by attempting to establish a connection."""
    uri = "bolt://neo4j:7687" 
    username = "neo4j"
    password = "abcd90909090"
    start_time = time.time()

    while time.time() - start_time < 60:
        try:
            # Attempt to connect to Neo4j
            driver = GraphDatabase.driver(uri, auth=(username, password))
            with driver.session() as session:
                session.run("RETURN 1")  # Simple query to verify connection
                logger.info("Neo4j is ready.")
                return True
        except Exception:
            # Retry if connection fails
            logger.info("Waiting for Neo4j to start...")
            time.sleep(5)
        finally:
            if 'driver' in locals():
                driver.close()  # Ensure driver is properly closed
    logger.error("Timed out waiting for Neo4j to start.")
    return False

# Main function to update the graph
def update_graph() -> None:
    """Update the graph in Neo4j by loading UCO ontology and instances."""
    uco_ontology = os.environ['UCO_ONTO_PATH']  # Load environment variables for file paths
    root_folder = os.environ['ROOT_FOLDER']
    vol_path = os.environ['VOL_PATH']

    uri = "bolt://neo4j:7687"
    username = "neo4j"
    password = "abcd90909090"

    # Connect to Neo4j
    driver = GraphDatabase.driver(uri, auth=(username, password))

    ttl_file_path = os.path.join(vol_path, "uco_with_instances.ttl")  # Construct file path for TTL

    # Make sure the RDF constraint is added if it doesn't exist
    create_constraint_if_not_exists(driver)

    # Load the TTL file into Neo4j
    load_ttl_file(driver, ttl_file_path)

    # Remove the TTL file after loading to clean up
    os.remove(ttl_file_path)
    logger.info(">>>>>>>>>>>>> removed uco_with_instances.ttl")

    driver.close()  # Ensure the driver is closed after all operations are done
