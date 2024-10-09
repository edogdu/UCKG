import os
import sys
import json
import logging
import subprocess  # For running external commands
import hashlib  # For generating file hashes (SHA-256)
import sqlite3  # For database handling
from data_collection import cve_collection as cve  # Importing a custom module for CVE data collection

# Configure the logging module with INFO level and log format
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('collect_logger')

# Fetch environment variables needed for paths
uco_ontology = os.environ['UCO_ONTO_PATH']
root_folder = os.environ['ROOT_FOLDER']
vol_path = os.environ['VOL_PATH']

# Append the process folder to sys.path so Python can find the scripts in that folder
sys.path.append(os.path.join(root_folder, "/process"))

# Import custom scripts for ontology and graph updating
from process import ontology_updater
from process import graph_updater

def call_ontology_updater():
    """Call the ontology updater script and, if successful, update the graph."""
    successfully_updated_ontology = ontology_updater.update_ontology()
    if successfully_updated_ontology:
        logger.info("Successfully updated the ontology. Now going to try to insert into the DB.")
        graph_updater.update_graph()  # Call the graph updater if the ontology update succeeded
    else:
        pass

# Function to write JSON data to a file
def write_file(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

# Function to calculate the SHA-256 hash of a file
def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):  # Reading the file in chunks
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()

# Function to format datetime strings
def format_datetime_string(datetime_string):
    """Format a datetime string to include milliseconds in a specific format."""
    date_part, time_part = datetime_string.split(" ")
    seconds_part, milliseconds_part = time_part.split(".")
    milliseconds_part = milliseconds_part[:3]  # Only keep first 3 digits for milliseconds
    formatted_datetime = f"{date_part}T{seconds_part}.{milliseconds_part}"
    return formatted_datetime

def call_mapper_update(datasource):
    """Run the mapper tool to update the graph for a specific data source."""
    jar_path = "./mapping/mapper.jar"
    output_file = os.path.join(vol_path, "out.ttl")
    
    # Choose the correct RML mapping file based on the data source
    if datasource == "cve":
        mapping_file = "./mapping/cve/cve_rml.ttl"
    elif datasource == "cwe":
        mapping_file = "./mapping/cwe/cwe_rml.ttl"
    elif datasource == 'cpe':
        mapping_file = "./mapping/cpe/cpe_rml2.ttl"
    elif datasource == "d3fend":
        mapping_file = "./mapping/d3fend/d3fend_rml.ttl"
    elif datasource == "attack":
        mapping_file = "./mapping/attack/attack_rml.ttl"
    elif datasource == "capec":
        mapping_file = "./mapping/capec/capec_rml.ttl"
    else:
        logger.info("Not a valid RML source...")
        return False

    # Construct the command to run the mapping jar
    command = ["java", "-jar", jar_path, "-m", mapping_file, "-s", "turtle"]

    # Run the command and write the output to the file
    with open(output_file, "w+") as file:
        try:
            process = subprocess.Popen(command, stdout=file, stderr=subprocess.PIPE)
            _, stderr = process.communicate()
            if process.returncode != 0:
                logger.error("Error running RML mapping: " + str(stderr.decode()))
                return False
            else:
                logger.info("Command executed successfully, output saved to: " + str(output_file))
                return True
        except Exception as e:
            logger.error(e)
    return False

def check_status(data_source):
    """Check the status of the data source files or database before processing."""
    current_directory = os.path.dirname(os.path.abspath(__file__))

    if data_source == "cve":
        cve_db_file = os.path.join(current_directory, './data/cve_database.db')
        with sqlite3.connect(cve_db_file) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cve_meta'")
            table_exists = cursor.fetchone()
            if table_exists:
                cursor.execute("SELECT init_finished FROM cve_meta")
                row = cursor.fetchone()
                init_finished = row[0]
                return init_finished
            else:
                return 3
    elif data_source == "cwe":
        return 3
    elif data_source == "d3fend":
        d3fend_file_path = os.path.join(vol_path, 'd3fend.json')
        if os.path.exists(d3fend_file_path):
            return 0
        else:
            return 3
    elif data_source == "attack":
        attack_file_path = os.path.join(vol_path, 'attack.json')
        if os.path.exists(attack_file_path):
            return 0
        else:
            return 3
    elif data_source == "capec":
        capec_file_path = os.path.join(vol_path, 'capec.json')
        if os.path.exists(capec_file_path):
            return 0
        else:
            return 3

if __name__ == "__main__":
    if len(sys.argv) > 1:
        data_source = sys.argv[1]
        if data_source == "cve_init":
            cve.cve_init()  # Initialize the CVE collection
        elif data_source == "cve_update":
            cve.cve_update()  # Update the CVE data
        else:
            logger.info("ERROR: invalid data source. Please choose from one of the following: cve_init, cve_update")
    else:
        logger.info("Please provide a data source to update (example: python collect.py cve).")
