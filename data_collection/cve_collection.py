import requests
import os
import json
import time
import datetime
import sqlite3
import logging
import xml.etree.ElementTree as ET
from process import shared_functions as sf
from time import sleep
import concurrent.futures

# Configure the logging module
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s (%(filename)s:%(lineno)d, %(funcName)s)')

# Create a logger
logger = logging.getLogger('collect_logger')

#Getting environment variables
uco_ontology = os.environ['UCO_ONTO_PATH']
root_folder = os.environ['ROOT_FOLDER']
vol_path = os.environ['VOL_PATH']

# Function to handle API retries
def try_call(api_url, parameters_arg, header):
    for i in range(5):  # Retry up to 5 times
        response = requests.get(api_url, params=parameters_arg, headers=header)
        if response.status_code == 200:
            return response
        logger.warning(f"API call failed with status {response.status_code}. Retrying in 10 seconds...")
        time.sleep(10)  # Wait before retrying
    return response  # Return the last response, even if it failed

def count_cpes_in_sqlite(db_path):
    """Count total CPEs in SQLite database."""
    try:
        # Check if database file exists
        if not os.path.exists(db_path):
            logger.info("CPE database does not exist yet.")
            return 0
            
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='cpe_data'")
        if not cursor.fetchone():
            logger.info("CPE data table does not exist yet.")
            conn.close()
            return 0
            
        cursor.execute("SELECT COUNT(*) FROM cpe_data")
        count = cursor.fetchone()[0]
        conn.close()
        logger.info(f"Total CPEs in SQLite database: {count}")
        return count
    except Exception as e:
        logger.error(f"Error counting CPEs in SQLite: {e}")
        return 0

def count_cpes_in_nvd():
    """Get total CPEs from NVD API."""
    header = {
        'apiKey': 'ccba97f5-3cb8-4bec-bd96-f5084eb8034e'
    }
    response = requests.get('https://services.nvd.nist.gov/rest/json/cpes/2.0?resultsPerPage=1', headers=header)
    if response.status_code != 200:
        logger.warning(f"NVD API returned error code {response.status_code}")
        return None
    
    data = response.json()
    nvd_total = data.get('totalResults', 0)
    logger.info(f"Total CPEs in NVD: {nvd_total}")
    return nvd_total

# Function to download and save CPE data into SQLite
def download_cpe_data_to_db(db_path):
    """Download CPE data from the NVD API and save it into the SQLite database."""
    # Initialize SQLite database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Check if the 'cpe_data' table exists and has data
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS cpe_data (
            cpeName TEXT PRIMARY KEY,
            cpeNameId TEXT,
            lastModified TEXT,
            titles TEXT
        )
    """)
    
    # Get current count from SQLite
    sqlite_count = count_cpes_in_sqlite(db_path)
    nvd_count = count_cpes_in_nvd()
    
    if nvd_count is None:
        logger.error("Failed to fetch NVD data. Skipping collection.")
        conn.close()
        return
        
    if nvd_count <= sqlite_count and sqlite_count > 0:
        logger.info(f"No need to update CPE data. NVD has {nvd_count} CPEs vs SQLite's {sqlite_count}")
        conn.close()
        return
    
    # If we have no data yet or NVD has more, proceed with download
    if sqlite_count == 0:
        logger.info("No existing CPE data found. Starting fresh download...")
        start_index = 0
    else:
        logger.info(f"Running CPE collection - NVD has {nvd_count} CPEs vs SQLite's {sqlite_count}")
        logger.info(f"Will update CPEs starting from index {sqlite_count + 1}")
        start_index = sqlite_count + 1
    
    # CPE API URL and headers
    cpe_url = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'
    header = {
        'apiKey': 'ccba97f5-3cb8-4bec-bd96-f5084eb8034e'
    }
    parameters = {
        'startIndex': str(start_index),  # Start from 0 for fresh download or next index for update
        'resultsPerPage': '10000'  # Explicitly set the maximum limit per request
    }

    # Initial API call to get total results
    logger.info("Starting API call to fetch CPEs...")
    cpe_response = requests.get(cpe_url, params=parameters, headers=header)
    if cpe_response.status_code != 200:
        cpe_response = try_call(cpe_url, parameters, header)
        if cpe_response.status_code != 200:
            logger.error(f"Initial API call failed with status {cpe_response.status_code}. Exiting.")
            return

    # Parse the response to get total results
    cpe_dict = cpe_response.json()
    total_results = cpe_dict.get('totalResults', 0)
    remaining_results = total_results - start_index
    logger.info(f"Remaining CPE records to fetch: {remaining_results}")

    # Pagination setup for remaining results
    increments = [str(num * 10000 + start_index) for num in range((remaining_results // 10000) + 1)]

    # Multithreading setup
    logger.info("Starting multithreaded CPE data collection...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        # Submit all API call tasks
        # Store futures mapped to their parameters for contextual logging on error/completion
        future_to_params = {}
        for increment_val in increments:
            # Create a distinct copy of parameters for each submitted task
            current_parameters = parameters.copy()
            current_parameters['startIndex'] = increment_val
            
            future = executor.submit(try_call, cpe_url, current_parameters, header)
            future_to_params[future] = current_parameters

        processed_count = 0
        total_calls = len(future_to_params)
        if total_calls == 0:
            logger.info("No new CPE records to fetch based on current startIndex and totalResults.")
        else:
            logger.info(f"All {total_calls} CPE API calls submitted. Processing responses as they arrive...")

        # Process futures as they complete
        for future in concurrent.futures.as_completed(future_to_params):
            params_for_this_call = future_to_params[future] # Get original params for this future
            try:
                response = future.result()  # Blocks until this specific future is done
                if response and response.status_code == 200:
                    cpe_data = response.json()
                    for product in cpe_data.get("products", []):
                        cpe = product.get("cpe", {})
                        cpe_name = cpe.get("cpeName")
                        cpe_name_id = cpe.get("cpeNameId")
                        last_modified = cpe.get("lastModified")
                        
                        # Store titles as JSON string of the list of title objects
                        titles_list = cpe.get("titles", [])
                        titles_json_string = json.dumps(titles_list)

                        if cpe_name:
                            # Insert or replace the data into the database
                            cursor.execute("""
                                INSERT OR REPLACE INTO cpe_data (cpeName, cpeNameId, lastModified, titles)
                                VALUES (?, ?, ?, ?)
                            """, (cpe_name, cpe_name_id, last_modified, titles_json_string))
                elif response: # try_call returned a response, but it's an error
                    logger.error(f"API call for startIndex {params_for_this_call['startIndex']} failed with status {response.status_code} after retries.")
                else: # try_call failed all retries and returned None
                    logger.error(f"API call for startIndex {params_for_this_call['startIndex']} failed catastrophically (no response object returned from try_call).")

            except Exception as e:
                # Catches exceptions from future.result() (e.g., task raised an exception) or from the processing block
                logger.error(f"Error processing result for API call (startIndex {params_for_this_call['startIndex']}): {e}", exc_info=True)
            
            processed_count += 1
            # Log progress periodically and at the very end
            if processed_count % 100 == 0 or processed_count == total_calls:
                if total_calls > 0 : # Avoid division by zero or logging if no calls made
                    logger.info(f"Processed {processed_count}/{total_calls} CPE API responses.")

    conn.commit()
    conn.close()
    logger.info("CPE data collection completed successfully.")

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
    
def get_cpe_data_from_db(cpe_name, db_path):
    """Fetch detailed CPE data from the SQLite database."""
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Query the database for the specific cpeName
        cursor.execute("SELECT cpeName, cpeNameId, lastModified, titles FROM cpe_data WHERE cpeName = ?", (cpe_name,))
        result = cursor.fetchone()

        conn.close()

        if result:            
            # Convert titles from JSON string to array, then transform to language-keyed dictionary
            titles = json.loads(result[3])

            return {
                "cpeName": result[0],
                "cpeNameId": result[1],
                "lastModified": result[2],
                "titles": titles
            }
        else:
            return None
    except Exception as e:
        logger.error(f"Error querying the database for CPE {cpe_name}: {e}")
        return None

# function to collect data from cve.mitre.org
def cve_init():

    vol_path = os.environ['VOL_PATH']
    # Define the relative path to the data file
    cve_db_file = os.path.join(vol_path, 'cve_database.db')
    cpe_db_file = os.path.join(vol_path, 'cpe_data.db')
    
    # Step 1: Download and save CPE data into the SQLite database
    logger.info("Downloading and saving CPE data into the database...")
    download_cpe_data_to_db(db_path=cpe_db_file)
    
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

            cves = {"cves": []}

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
                            # cpes.append({"cpe": {"cpeName": cpeMetaInfo['criteria'], "matchCriteriaId": cpeMetaInfo['matchCriteriaId'],"cve_id": cve['cve']['id']}})
                            cpe_name = cpeMetaInfo['criteria']
                            cpe_data = get_cpe_data_from_db(cpe_name, db_path=cpe_db_file)
                            if cpe_data:
                                titles = json.dumps({t.get("lang", ""): t.get("title", "") for t in cpe_data.get("titles", [])})
                                cpes.append({
                                    "cpe": {
                                        "cpeName": cpe_data.get("cpeName", ""),
                                        "cpeNameId": cpe_data.get("cpeNameId", ""),
                                        "lastModified": cpe_data.get("lastModified", ""),
                                        "titles": titles,
                                        "cve_id": cve['cve']['id'],
                                        "dictionary_found": True
                                    }
                                })
                            else:
                                cpes.append({
                                    "cpe": {
                                        "cpeName": cpe_name,
                                        "cve_id": cve['cve']['id'],
                                        "dictionary_found": False
                                    }
                                })
                                
                except Exception:
                    pass

                start_index += 1

                metrics = cve['cve'].get('metrics', {}).get('cvssMetricV2', [{}])[0]
                cvss_data = metrics.get('cvssData', {})
                evaluator_solution = cve['cve'].get('evaluatorSolution', "")

                cves["cves"].append({"cve":{
                    "id": cve['cve']["id"],
                    "lastModified": cve['cve']["lastModified"],
                    "published": cve['cve']["published"],
                    "descriptions": cve['cve']['descriptions'],
                    "vulnStatus": cve['cve'].get("vulnStatus", ""),
                    "vectorString": cvss_data.get("vectorString", ""),
                    "baseSeverity": metrics.get("baseSeverity", ""),
                    "exploitabilityScore": metrics.get("exploitabilityScore", ""),
                    "impactScore": metrics.get("impactScore", ""),
                    "obtainAllPrivilege": metrics.get("obtainAllPrivilege", False),
                    "userInteractionRequired": metrics.get("userInteractionRequired", False),
                    "cwes": cwes,
                    "cpes": cpes,
                    "evaluatorSolution": evaluator_solution
                    }})

            with open("./data/cve/cves.json", "w+") as json_file:
                json.dump(cves, json_file, indent=4)

            successfully_mapped = sf.call_mapper_update("cve")
            #successfully_mapped2 = sf.call_mapper_update("cpe")
            successfully_mapped2 = True
            if successfully_mapped and successfully_mapped2:
                if vul_count < 2000:
                    sf.call_ontology_updater(reason = True)
                else:
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