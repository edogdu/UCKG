import os
import sys
import json
import logging
import subprocess
import hashlib
import sqlite3
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

def call_ontology_updater(reason=False):
    if reason:
        successfully_updated_ontology = ontology_updater.update_ontology(run_reasoner = reason)
    else:
        successfully_updated_ontology = ontology_updater.update_ontology()
    if successfully_updated_ontology:
        logger.info("successfully updated the ontology now going to try to insert into the db")
        graph_updater.update_graph()
    else:
        pass

# Move to tools file later
def write_file(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)

def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


def format_datetime_string(datetime_string):
    # Split the string into date and time components
    date_part, time_part = datetime_string.split(" ")

    # Split the time component into seconds and milliseconds
    seconds_part, milliseconds_part = time_part.split(".")

    # Keep only the first 3 decimal places (milliseconds)
    milliseconds_part = milliseconds_part[:3]

    # Concatenate the parts with "T" and the rounded milliseconds
    formatted_datetime = f"{date_part}T{seconds_part}.{milliseconds_part}"

    return formatted_datetime

def call_mapper_update(datasource):
    jar_path = "./mapping/mapper.jar"
    output_file = os.path.join(vol_path, "out.ttl")
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
        logger.info("Not a valid rml source...")
        return False
    
    # Get Java options from environment variable with fallback
    java_opts = os.environ.get('JAVA_OPTS', '')
    if not java_opts:
        # Fallback to default values if JAVA_OPTS is not set
        java_opts = "-Xmx12000M -Xms12000M"
    
    # Split Java options and ensure they are properly formatted
    java_opts_list = []
    for opt in java_opts.split():
        if opt.startswith('-Xmx') or opt.startswith('-Xms'):
            # Ensure the memory value is properly formatted
            try:
                value = int(opt[4:-1])  # Extract the number
                unit = opt[-1]  # Extract the unit (M or G)
                java_opts_list.append(f"{opt[:4]}{value}{unit}")
            except ValueError:
                logger.warning(f"Invalid Java memory option format: {opt}, using default")
                java_opts_list.extend(["-Xmx12000M", "-Xms12000M"])
        else:
            java_opts_list.append(opt)
    
    # Construct the command with Java options
    command = ["java"] + java_opts_list + ["-jar", jar_path, "-m", mapping_file, "-s", "turtle", "-d"]
    
    logger.info(f"Running Java command with options: {java_opts}")
    logger.info(f"Processing {datasource} data with mapping file: {mapping_file}")
    logger.info(f"Full command: {' '.join(command)}")

    # Check if mapping file exists
    if not os.path.exists(mapping_file):
        logger.error(f"Mapping file not found: {mapping_file}")
        return False

    # Check if jar file exists
    if not os.path.exists(jar_path):
        logger.error(f"JAR file not found: {jar_path}")
        return False

    with open(output_file, "w+") as file:
        # Run the command and redirect stdout to the file
        try:
            process = subprocess.Popen(command, stdout=file, stderr=subprocess.PIPE, universal_newlines=True)
            # Wait for the command to complete and capture stderr
            stdout, stderr = process.communicate()
            
            if process.returncode != 0:
                error_msg = stderr if stderr else "No error message available"
                logger.error(f"Error running RML mapping for {datasource}:")
                logger.error(f"Command failed with return code: {process.returncode}")
                logger.error(f"Error message: {error_msg}")
                
                # Check for specific error types
                if "NTriples parsing error" in error_msg:
                    logger.error("Ontology parsing error detected. Check if the ontology file is accessible and in the correct format.")
                elif "OutOfMemoryError" in error_msg:
                    logger.error("Java heap space error detected. Consider increasing the heap size.")
                elif "FileNotFoundException" in error_msg:
                    logger.error(f"Mapping file or data file not found. Check if {mapping_file} exists.")
                elif "JSONPath" in error_msg:
                    logger.error("JSONPath error detected. Check if the data structure matches the mapping file.")
                elif not error_msg.strip():
                    logger.error("Empty error message. This might indicate a silent failure in the Java process.")
                    logger.error("Check if the input data file exists and is in the correct format.")
                
                return False
            else:
                logger.info(f"Successfully processed {datasource} data")
                return True
        except Exception as e:
            logger.error(f"Exception occurred while running RML mapping for {datasource}:")
            logger.error(f"Exception type: {type(e).__name__}")
            logger.error(f"Exception message: {str(e)}")
            return False

def check_status(data_source):
    # Get the directory of the currently executing script (sub_script.py)
    current_directory = os.path.dirname(os.path.abspath(__file__))

    if data_source == "cve":
        # Define the relative path to the data file
        cve_db_file = os.path.join(current_directory, './data/cve_database.db')
        with sqlite3.connect(cve_db_file) as conn:
            # Create database cursor
            cursor = conn.cursor()
            cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='cve_meta'")
            table_exists = cursor.fetchone()
            if table_exists:
                cursor.execute(f"SELECT init_finished FROM cve_meta")
                row = cursor.fetchone()
                init_finished = row[0]
                return init_finished
            else:
                return 3
    elif data_source == "cwe":
        return 3
    elif data_source == "d3fend":
        # Define the relative path to the d3fend.json file
        d3fend_file_path = os.path.join(vol_path, 'd3fend.json')

        # Check if d3fend.json file exists
        if os.path.exists(d3fend_file_path):
            return 0  # File exists, return 0
        else:
            return 3  # File doesn't exist, return 3
    elif data_source == "attack":
        # Get the directory of the currently executing script
        current_directory = os.path.dirname(os.path.abspath(__file__))

        # Define the relative path to the attack.json file
        attack_file_path = os.path.join(vol_path, 'attack.json')

        # Check if attack.json file exists
        if os.path.exists(attack_file_path):
            return 0  # File exists, return 0
        else:
            return 3  # File doesn't exist, return 3
    elif data_source == "capec":
        # Get the directory of the currently executing script
        current_directory = os.path.dirname(os.path.abspath(__file__))

        # Define the relative path to the attack.json file
        attack_file_path = os.path.join(vol_path, 'capec.json')

        # Check if attack.json file exists
        if os.path.exists(attack_file_path):
            return 0  # File exists, return 0
        else:
            return 3  # File doesn't exist, return 3

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

