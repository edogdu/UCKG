import os
import sys
import logging
import subprocess
from data_collection import cve_collection as cve

# Configure the logging module
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# Create a logger
logger = logging.getLogger('collect_logger')

#Getting environment variables
uco_ontology = os.environ['UCO_ONTO_PATH']
root_folder = os.environ['ROOT_FOLDER']
vol_path = os.environ['VOL_PATH']

# Import ontology updater script
sys.path.append(os.path.join(root_folder, "/process")) 
from process import ontology_updater

# Import graph updater script
sys.path.append(os.path.join(root_folder, "/process")) 
from process import graph_updater

def call_ontology_updater():
    successfully_updated_ontology = ontology_updater.update_ontology()
    if successfully_updated_ontology:
        logger.info("successfully updated the ontology now going to try to insert into the db")
        graph_updater.update_graph()
    else:
        pass

def call_mapper_update(datasource):
    jar_path = "./mapping/mapper.jar"
    output_file = os.path.join(vol_path, "out.ttl")
    if datasource == "cve":
        mapping_file = "./mapping/cve/cve_rml.ttl"
    elif datasource == "cwe":
        mapping_file = "./mapping/cwe/cwe_rml.ttl"
    elif datasource == 'cpe':
        mapping_file = "./mapping/cpe/cpe_rml2.ttl"
    else:
        logger.info("Not a valid rml source...")
        return False
    # Construct the command
    command = ["java", "-jar", jar_path, "-m", mapping_file, "-s", "turtle"]

    with open(output_file, "w+") as file:
        # Run the command and redirect stdout to the file
        try:
            process = subprocess.Popen(command, stdout=file, stderr=subprocess.PIPE)
            # Wait for the command to complete and capture stderr
            _, stderr = process.communicate()
            if process.returncode != 0:
                logger.error("Error running rml mapping: " + str(stderr.decode()))
                return False
            else:
                logger.info("Command executed successfully, output saved to: " + str(output_file))
                return True
        except Exception as e:
            logger.info("In this error")
            logger.error(e)
    return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        data_source = sys.argv[1]
        if data_source == "cve_init":
            cve.cve_init()
        elif data_source == "cve_update":
            cve.cve_update()
        else:
            logger.info("ERROR: invalid data source. Please choose from one of the following: cve_init, cve_update")

    else:
        logger.info("Please provide a data source to update(example:python collect.py cve).")

