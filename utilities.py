import os
import json
import hashlib
import subprocess
import sqlite3
from config import LOGGER, vol_file_path
from graph_updater import graph_updater
from process import ontology_updater
import xml.etree.ElementTree as ET


def calculate_file_hash(file_path):
    """Calculate the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            sha256_hash.update(chunk)
    return sha256_hash.hexdigest()


# Move to tools file later
def write_file(filename, data):
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)


def call_mapper_update(datasource):
    jar_path = "./rml_mapper/mapper.jar"
    output_file = os.path.join(os.environ['VOL_PATH'], "out.ttl")
    if datasource == "cve":
        mapping_file = "./rml_mapper/cve/cve_rml.ttl"
    elif datasource == "cwe":
        mapping_file = "./rml_mapper/cwe/cwe_rml.ttl"
    elif datasource == "d3fend":
        mapping_file = "./rml_mapper/d3fend/d3fend_rml.ttl"
    elif datasource == "attack":
        mapping_file = "./rml_mapper/attack/attack_rml.ttl"
    else:
        LOGGER.info("Not a valid rml source...")
        return False
    # Construct the command
    command = ["java", "-jar", jar_path, "-m", mapping_file, "-s", "turtle"]

    with open(output_file, "w") as file:
        # Run the command and redirect stdout to the file
        try:
            process = subprocess.Popen(command, stdout=file, stderr=subprocess.PIPE)
            # Wait for the command to complete and capture stderr
            _, stderr = process.communicate()
            if process.returncode != 0:
                LOGGER.error("Error running rml mapping: " + str(stderr.decode()))
                return False
            else:
                LOGGER.info("Command executed successfully, output saved to: " + str(output_file))
                return True
        except Exception as e:
            LOGGER.info("In this error")
            LOGGER.error(e)
    return False


def call_ontology_updater():
    successfully_updated_ontology = ontology_updater.update_ontology()
    if successfully_updated_ontology:
        LOGGER.info("successfully updated the ontology now going to try to insert into the db")
        graph_updater.update_graph()
    else:
        pass


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


def get_cwe_id_list():
    # Parse the XML file
    xml_file_path = './rml_mapper/cwe_dict.xml'

    # Define the path to the target elements
    target_path = {
        'Weaknesses': './{http://cwe.mitre.org/cwe-7}Weaknesses',
        'Weakness': './{http://cwe.mitre.org/cwe-7}Weakness',
        'ID': './ID'
    }

    tree = ET.parse(xml_file_path)
    root = tree.getroot()

    # List to hold the extracted IDs
    extracted_ids = []

    # Navigate through the XML tree and extract elements
    for weaknesses in root.findall(target_path['Weaknesses']):
        for weakness in weaknesses.findall(target_path['Weakness']):
            id_value = weakness.get('ID')
            if id_value is not None:
                temp_id = "CWE-" + str(id_value)
                extracted_ids.append(temp_id.strip())

    return extracted_ids


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
        d3fend_file_path = os.path.join(vol_file_path, 'd3fend.json')

        # Check if d3fend.json file exists
        if os.path.exists(d3fend_file_path):
            return 0  # File exists, return 0
        else:
            return 3  # File doesn't exist, return 3
    elif data_source == "attack":
        # Get the directory of the currently executing script
        current_directory = os.path.dirname(os.path.abspath(__file__))

        # Define the relative path to the attack.json file
        attack_file_path = os.path.join(vol_file_path, 'attack.json')

        # Check if attack.json file exists
        if os.path.exists(attack_file_path):
            return 0  # File exists, return 0
        else:
            return 3  # File doesn't exist, return 3
    elif data_source == "capec":
        # Get the directory of the currently executing script
        current_directory = os.path.dirname(os.path.abspath(__file__))

        # Define the relative path to the attack.json file
        attack_file_path = os.path.join(vol_file_path, 'capec.json')

        # Check if attack.json file exists
        if os.path.exists(attack_file_path):
            return 0  # File exists, return 0
        else:
            return 3  # File doesn't exist, return 3