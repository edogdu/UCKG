import requests
import os
import json
import time
import datetime
import sqlite3
import logging
import xml.etree.ElementTree as ET
from process import shared_functions as sf

# Configure the logging module
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d, %(funcName)s)')

# Create a logger
logger = logging.getLogger('collect_logger')

#Getting environment variables
uco_ontology = os.environ['UCO_ONTO_PATH']
root_folder = os.environ['ROOT_FOLDER']
vol_path = os.environ['VOL_PATH']

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
    xml_file_path = './data/cwe/cwe_dict.xml'

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

    with open("./data/cwe/cwes.json", "w") as json_file:
        json.dump(cwes, json_file, indent=4)

    logger.info("\n############################")
    logger.info("CWE Data extraction completed")
    logger.info("############################\n")
    # logger.info(f"Database Meta-Table: cves_meta")
    # logger.info(f"Total Records: {total_records}")
    # logger.info(f"Records Added: {records_added}")
    # logger.info(f"Database initialization finished: {init_finished}\n")

# function to collect data from cve.mitre.org
def cve_init():

    vol_path = os.environ['VOL_PATH']
    # Define the relative path to the data file
    cve_db_file = os.path.join(vol_path, 'cve_database.db')
    with sqlite3.connect(cve_db_file) as conn:
        uco_ontology = os.environ['UCO_ONTO_PATH']
        root_folder = os.environ['ROOT_FOLDER']
        vol_path = os.environ['VOL_PATH']
        # Create database cursor
        cursor = conn.cursor()

        logger.info("############################################################################")
        logger.info("Starting data extraction of CVE data from National Vulnerability Database")
        logger.info("############################################################################\n")
        start_index = 0

        # Check if the meta table exists
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='cve_meta'")
        table_exists = cursor.fetchone()
        if table_exists:
            logger.info("Reading cve_meta table data...")
            cursor.execute(f"SELECT init_finished FROM cve_meta")
            row = cursor.fetchone()
            init_finished = row[0]
            if init_finished == 1:
                logger.info("###############################################")
                logger.info("CVE initializtion already complete exiting now")
                logger.info("###############################################\n")
                return
            cursor.execute(f"SELECT offset FROM cve_meta")
            row = cursor.fetchone()
            start_index = row[0]
        else: 
            logger.info("Table cve_meta does not exist. Creating table...")
            # Create cve_meta table
            cursor.execute('''CREATE TABLE IF NOT EXISTS cve_meta 
                            (id INTEGER PRIMARY KEY, offset INTEGER, last_modified TEXT, init_finished INTEGER DEFAULT 0)''')
            current_time = format_datetime_string(str(datetime.datetime.now()))
            cursor.execute("INSERT INTO cve_meta (id, offset, last_modified) VALUES (?, ?, ?)", (12345, start_index, current_time))
            conn.commit()
            
        logger.info(f"Reading in cve data starting with index {start_index}...")

        # get the data from the website
        cve_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex=" 
        logger.info(f"{cve_api_url}{start_index}&resultsPerPage=2000")
        response = requests.get(f"{cve_api_url}{start_index}&resultsPerPage=2000")
        init_finished = False 
        original_offset = start_index

        cves = {"cves": []}
        cwe_id_list = get_cwe_id_list()
        # logger.info(cwe_id_list)
        while (response.status_code == 200 or response.status_code == 403 or response.status_code == 503) and init_finished == False:
            early_exit = False
            if response.status_code == 403 or response.status_code == 503:
                for i in range(4):
                    if i == 3:
                        logger.info("Unable to recieve response from API, saving results and exiting...")
                        early_exit = True

                    logger.info(f"Retry #{i + 1}: Waiting for 10 seconds, due to API throttling...")
                    time.sleep(10)
                    response = requests.get(f"{cve_api_url}{start_index}&resultsPerPage=2000")
                    if response.status_code == 200:
                        logger.info("Retry Successful! Continuing processing...")
                        break

            if early_exit:
                break
            
            begining_index = start_index
            json_data = response.json()

            # Check if we are done after this loop
            # If there are less than 2000 vulnerabilities given from a response,
            # then that means there are no remaining records to retrieve
            vul_count = len(json_data["vulnerabilities"])

            if vul_count < 2000:
                init_finished = True

            for cve in json_data["vulnerabilities"]:
                cwes = []
                cpes = []
                try: 
                    for weakness in cve['cve']['weaknesses']:
                        for desc in weakness['description']:
                            weakness_value = desc['value'].strip()
                            if weakness_value in cwe_id_list:
                                # logger.info(f"Found CWE match for CVE: {cve['cve']['id']} - hasCWE -> {str(desc['value'])}")
                                cwes.append({"cwe": {"id": desc['value'], "cve_id": cve['cve']['id']}})
                    for product in cve['cve']['configurations']:
                        # Access the dictionary within the list
                        cpeMeta = product['nodes'][0]
                        # Go one step further, access the dictionary within the list.
                        # A lot of key-values where values are lists...
                        cpeMetaInfo = cpeMeta['cpeMatch'][0]
                        if (cpeMetaInfo['criteria']):
                            # logger.info(f"Found CPE match for CVE: {cve['cve']['id']} - hasCPE -> {cpeMetaInfo['criteria']}")
                            cpes.append({"cpe": {"cpeName": cpeMetaInfo['criteria'], "cve_id": cve['cve']['id']}})

                except Exception:
                    pass

                start_index += 1

                cves["cves"].append({"cve":{
                    "id": cve['cve']["id"],
                    "lastModified":cve['cve']["lastModified"],
                    "published":cve['cve']["published"],
                    "descriptions": cve['cve']['descriptions'],
                    "cwes": cwes,
                    "cpes": cpes
                    }})

            with open("./data/cve/cves.json", "w+") as json_file:
                json.dump(cves, json_file, indent=4)

            successfully_mapped = sf.call_mapper_update("cve")
            #successfully_mapped2 = sf.call_mapper_update("cpe")
            successfully_mapped2 = True
            if successfully_mapped and successfully_mapped2:
                sf.call_ontology_updater()



            current_time = format_datetime_string(str(datetime.datetime.now()))
            cursor.execute("UPDATE cve_meta SET offset=?, last_modified=? WHERE id=12345", (start_index, current_time))
            conn.commit()
            logger.info(f"Completed batch with startIndex={begining_index}")

            # Wait 5 seconds to avoid throttling
            time.sleep(5)

            response = requests.get(f"{cve_api_url}{start_index}&resultsPerPage=2000")

        
        if init_finished == True:
            cursor.execute("UPDATE cve_meta SET init_finished=1 WHERE id=12345")
            conn.commit()

        total_records = start_index 
        records_added = total_records - original_offset

        logger.info("############################")
        logger.info("Data extraction completed")
        logger.info("############################\n")
        logger.info(f"Database Meta-Table: cves_meta")
        logger.info(f"Total Records: {total_records}")
        logger.info(f"Records Added: {records_added}")
        logger.info(f"Database initialization finished: {init_finished}\n")


def cve_update():
    logger.info("Not added yet...")

# This funnction is used to determine if the cve table initialization is complete init (1), not complete init (0), not started yet (3), or complete init and dataload into neo4j
def check_cve_status():
    # Get the directory of the currently executing script (sub_script.py)
    current_directory = os.path.dirname(os.path.abspath(__file__))

    # Define the relative path to the data file
    cve_db_file = os.path.join(current_directory, '../data/cve_database.db')
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