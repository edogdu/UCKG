from owlready2 import *
from rdflib import *
import os
import sys
import logging

# # Configure the logging module
logging.basicConfig(level=logging.DEBUG , format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# # Create a logger
logger = logging.getLogger('ontology_updater_logger')
# Create a graph to convert uco to owl xml format
def update_ontology():
    try:
        # Get the current working directory
        g = Graph()
        uco_ontology = os.environ['UCO_ONTO_PATH']
        uco_extended_ontology = os.environ['UCO_ONTO_EXTEND_PATH']
        root_folder = os.environ['ROOT_FOLDER']
        vol_path = os.environ['VOL_PATH']
        # Adding the base ontology
        g.parse(uco_ontology, format="turtle")
        # Extending the ontology
        g.parse(uco_extended_ontology)
        write_path = os.path.join(vol_path, "uco.owl")
        g.serialize(write_path, format="xml")
        logger.info("\nCreated file uco.owl\n")

        # Load the ontolgy
        onto = get_ontology(write_path).load()

        # Switch back to to rdflib so I can add the instances
        graph_2 = onto.world.as_rdflib_graph()

        with onto:
            graph_2.parse(os.path.join(vol_path, "out.ttl"))
            write_path = os.path.join(vol_path, "uco_with_instances.owl")
            graph_2.serialize(write_path, format="xml")
            logger.info("\nCreated file uco_with_instances.owl\n")

        # Switch back to owlready2 so I can use the sync_reasoner
        onto_final = get_ontology(write_path).load()
        sync_reasoner()
        # with onto_final:
            # sync_reasoner()

        # Finally switch back to rdflib so I can the ontology and instances as turtle format
        graph_3 = onto_final.world.as_rdflib_graph()

        with onto_final:
            write_path = os.path.join(vol_path, "uco_with_instances.ttl")
            graph_3.serialize(write_path, format="turtle")
            logger.info("\nCreated file uco_with_instances.ttl\n")

        files_to_delete = ["uco.owl", "uco_with_instances.owl"]

        for file in files_to_delete:
            to_delete = os.path.join(vol_path, file)
            if os.path.exists(to_delete):
                os.remove(to_delete)
                logger.info(f"\nFile '{to_delete}' has been deleted\n")
            else:
                logger.error(f"\nFile '{to_delete}' does not exist\n")
        return True
    except Exception as e:
        logger.error(e)
        return False

if __name__ == "__main__":
    update_ontology()