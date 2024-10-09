from owlready2 import *  # Importing owlready2 for ontology management
from rdflib import *  # Importing rdflib for RDF graph operations
import os
import logging

# Configure the logging module with a detailed format for better debugging and traceability
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Create a logger specifically for ontology updates
logger = logging.getLogger('ontology_updater_logger')

# Function to update the ontology, convert formats, and manage files
def update_ontology() -> bool:
    """Update ontology by parsing, converting formats, and syncing reasoners."""
    try:
        # Initialize an RDFLib Graph object
        g = Graph()

        # Retrieve file paths from environment variables for flexibility and configuration management
        uco_ontology = os.environ['UCO_ONTO_PATH']
        uco_extended_ontology = os.environ['UCO_ONTO_EXTEND_PATH']
        vol_path = os.environ['VOL_PATH']

        # Adding the base UCO ontology in Turtle format
        g.parse(uco_ontology, format="turtle")
        
        # Extending the base ontology by parsing additional ontology data
        g.parse(uco_extended_ontology)

        # Serialize the graph to OWL XML format
        write_path = os.path.join(vol_path, "uco.owl")
        g.serialize(write_path, format="xml")
        logger.info("Created file uco.owl")

        # Load the ontology using Owlready2 for further processing
        onto = get_ontology(write_path).load()

        # Switching to RDFLib to add instances to the ontology
        graph_2 = onto.world.as_rdflib_graph()

        with onto:
            # Parse the instance data from a Turtle file
            graph_2.parse(os.path.join(vol_path, "out.ttl"))

            # Serialize the graph with instances to OWL XML format
            write_path = os.path.join(vol_path, "uco_with_instances.owl")
            graph_2.serialize(write_path, format="xml")
            logger.info("Created file uco_with_instances.owl")

        # Load the final ontology again using Owlready2
        onto_final = get_ontology(write_path).load()

        # Synchronize the reasoner (for any ontology reasoning required)
        sync_reasoner()

        # Switching back to RDFLib to serialize ontology and instances as Turtle format
        graph_3 = onto_final.world.as_rdflib_graph()

        with onto_final:
            write_path = os.path.join(vol_path, "uco_with_instances.ttl")
            graph_3.serialize(write_path, format="turtle")
            logger.info("Created file uco_with_instances.ttl")

        # Remove intermediate OWL files to clean up the volume directory
        files_to_delete = ["uco.owl", "uco_with_instances.owl"]
        for file in files_to_delete:
            to_delete = os.path.join(vol_path, file)
            if os.path.exists(to_delete):
                os.remove(to_delete)
                logger.info(f"File '{to_delete}' has been deleted")
            else:
                logger.error(f"File '{to_delete}' does not exist")

        return True  # Return True indicating success

    except Exception as e:
        # Better error handling with detailed logging of the exception
        logger.error(f"An error occurred: {e}")
        return False  # Return False indicating failure

# Main entry point to trigger the ontology update process
if __name__ == "__main__":
    update_ontology()
