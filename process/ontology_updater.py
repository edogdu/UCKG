from owlready2 import *
from rdflib import *
import os
import sys
import logging

def validate_and_fix_datetime_literals(graph):
    # Iterate over all triples in the graph
    fixStringCount = 0
    logger.info(f"Checking for malformed dateTime Literals...")
    for s, p, o in graph.triples((None, None, None)):
        # Check if the object is a literal with a datatype of `xsd:dateTime`
        try:
            if (o.datatype == XSD.dateTime):
                # Convert dateTime to string, extract milliseconds position.
                dateTime = str(o)
                milliPos = dateTime.rfind(".")
                # Check if the milliseconds position has more than 3 digits
                if milliPos != -1 and len(dateTime[milliPos + 1:]) > 3:
                    # Fix the literal by truncating it completely
                    cleaned_value = dateTime[:milliPos]
                    graph.remove((s, p, o))
                    graph.add((s, p, Literal(cleaned_value, datatype=o.datatype)))
                    fixStringCount += 1
        except Exception as e:
            pass
    if fixStringCount > 0:
        logger.info(f"Malformed Strings Found, Corrected {fixStringCount} xsd:dateTime literals by truncating the milliseconds")
    else:
        logger.info(f"No malformed dateTime literals found")

# # Configure the logging module
logging.basicConfig(level=logging.DEBUG , format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# # Create a logger
logger = logging.getLogger('ontology_updater_logger')
# Create a graph to convert uco to owl xml format
def update_ontology(run_reasoner=False):
    try:
        # Get the current working directory
        g = Graph()
        uco_ontology = os.environ['UCO_ONTO_PATH']
        uco_extended_ontology = os.environ['UCO_ONTO_EXTEND_PATH']
        vol_path = os.environ['VOL_PATH']
        # Adding the base ontology
        g.parse(uco_ontology, format="turtle")
        # Extending the ontology
        g.parse(uco_extended_ontology)
        # Remove redundant imports which cause NTriples Parse error
        g.remove((None, OWL.imports, None))
        write_path = os.path.join(vol_path, "uco.owl")
        g.serialize(write_path, format="xml")
        logger.info(f"Created file uco.owl")

        # Load the ontolgy
        onto = get_ontology(write_path).load()

        # Switch back to to rdflib so I can add the instances
        graph_2 = onto.world.as_rdflib_graph()

        with onto:
            graph_2.parse(os.path.join(vol_path, "out.ttl"))
            write_path = os.path.join(vol_path, "uco_with_instances.owl")
            validate_and_fix_datetime_literals(graph_2)
            graph_2.serialize(write_path, format="xml")
            logger.info(f"Created file uco_with_instances.owl")

        # Switch back to owlready2 so I can use the sync_reasoner
        onto_final = get_ontology(write_path).load()
        if run_reasoner:
            logger.info(f"Running the reasoner")
            with onto_final:
                validate_and_fix_datetime_literals(onto_final.world.as_rdflib_graph())
                sync_reasoner()

        # Finally switch back to rdflib so I can the ontology and instances as turtle format
        graph_3 = onto_final.world.as_rdflib_graph()

        with onto_final:
            write_path = os.path.join(vol_path, "uco_with_instances.ttl")
            graph_3.serialize(write_path, format="turtle")
            logger.info(f"Created file uco_with_instances.ttl")

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
    success = update_ontology()
    sys.exit(0 if success else 1)