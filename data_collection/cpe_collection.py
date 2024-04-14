import requests
import concurrent.futures
import os
import json
import sqlite3
import logging
import time

#Getting environment variables
uco_ontology = os.environ['UCO_ONTO_PATH']
root_folder = os.environ['ROOT_FOLDER']
vol_path = os.environ['VOL_PATH']

# function to handle when api calls fail. Returns status code of call.
def try_call(api_url, parameters_arg, header):
    # Try 5 calls before throwing in the towel.
    parameters=parameters_arg.copy()
    for i in range(5):
        response = requests.get(api_url, params = parameters, headers = header)
        # Desired outcome, break return early.
        if (response.status_code == 200):
            return response
        # Sleep for 10 seconds, then retry
        time.sleep(10)
    # return response regardless...
    return response

# Function to check status of API call
def check_status(api_response):
    status = api_response.status_code
    return status

# Configure the logging module
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
# Create a logger
logger = logging.getLogger('collect_logger')

def cpe_init():
    vol_path = os.environ['VOL_PATH']
    # Define the relative path to the data file
    cpe_db_file = os.path.join(vol_path, 'cpe_database.db')
    with sqlite3.connect(cpe_db_file) as conn:
        uco_ontology = os.environ['UCO_ONTO_PATH']
        root_folder = os.environ['ROOT_FOLDER']
        vol_path = os.environ['VOL_PATH']
        # Create database cursor
        cursor = conn.cursor()

        logger.info("############################################################################")
        logger.info("Starting data extraction of CPE data from National Vulnerability Database")
        logger.info("############################################################################\n")
        # Check if table exists, if not, create it.
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='cpes'")
        # fetchone() returns none if the table does not exist
        table_exists = cursor.fetchone()
        if (False):
            logger.info("CPE TABLE EXISTS\n")
            return
        else:
            # Step 1: Start the API call and get the first batch of data
                # While we have not reached the end of the totalResults returned by the API
                # Populate the table using the data from the API Call
                # Increment the API call (It does 10000 results at a time, increment by 10000)
            # Step 1 - MITRE API URL to retrieve CPE data
            cpe_url = 'https://services.nvd.nist.gov/rest/json/cpes/2.0'
            header = {
                'apiKey':'ccba97f5-3cb8-4bec-bd96-f5084eb8034e'
            }
            parameters = {
                'startIndex':'0'
            }

            # First Call for initialization
            cpe_response = requests.get(cpe_url, params = parameters, headers = header)
            # Bad Call, retrying call 5 times.
            if (check_status(cpe_response) != 200):
                cpe_response = try_call(cpe_url, parameters, header)
                if (check_status(cpe_response) != 200):
                    logger.info(f'API CALL UNSUCCESSFUL, CODE - {cpe_response.status_code} EXITING')
                    return

            # Converts API response into python object (A dictionary in this case)
            cpeJsonText = cpe_response.text
            # Create jsonFile (Placeholder) and dump the initial text
            jsonFile = open("./data/cpe/cpes.json", "w+")
            json.dump(cpeJsonText, jsonFile, indent=4)
            jsonFile.close()
            logger.info(f"JSON FILE CREATED")
            # Loading Json for Pagination handling
            cpeDict = json.loads(cpe_response.text)
            # Get startIndex/totalResults for Increment List
            startIndex, totalResults = cpeDict['startIndex'], cpeDict['totalResults']

            # Multithreading setup, API rate limit is 50 calls per 30 second rolling window.
            # Pagination is in 10000 set increments. We make the API call, grabbing 10000 at a time
            increments = [str(num * 10000) for num in range((totalResults // 10000) + 1)]

            logger.info(f'STARTING CPE COLLECTION, TOTAL CPES TO RECORD: {totalResults}')
            with concurrent.futures.ThreadPoolExecutor() as executor:
                # Start the load operations and mark each future with its URL
                future_to_api_call = []
                for increment in increments:
                    # Update startIndex
                    parameters['startIndex'] = increment
                    # This is important for multithreading, you NEED to pass a shallow copy here and in
                    # the try call function.
                    parameters_arg = parameters.copy()
                    # Appends future objects to this list.
                    future_to_api_call.append(executor.submit(try_call, cpe_url, parameters_arg, header))
                    # Wait for 11 calls to finish, then move on.
                    if (len(future_to_api_call) % 11 == 0):
                        logger.info(f'''Requests submitted to retrieve {parameters['startIndex']} records''')
                        concurrent.futures.wait(future_to_api_call, timeout=None, return_when='ALL_COMPLETED')
                logger.info('FINISHED')
            # Checking if we have duplicate sets
            sort = []
            # Try to load the response from the future object
            for i in future_to_api_call:
                try:
                    response = json.loads(i.result().text)
                except:
                    pass
                sort.append(response['startIndex'])
            # Sort the list containing the startIndecies from all our API calls
            sort = sorted(sort)
            for num in range(len(increments)):
                increments[num] = int(increments[num])
            # Compare the lists, if they have the same startIndecies, then we got unique API calls
            # in between sets, data collection was correct.
            if (increments == sort):
                logger.info(f"COLLECTION OF CPEs SUCCESSFUL, NO MISSING SETS")
            else:
                logger.info("Error collecting API sets")
            # Database population
            logger.info(f"COLLECTING RESULTS AND STORING QUERIES {startIndex} THROUGH {totalResults} IN A JSON FILE")
            for future in future_to_api_call:
                json_text = future.result().text
                cpeJsonText = json_text
                # Output the file (Placeholder)
                with open("./data/cpe/cpes.json", "a+") as json_file:
                    json.dump(cpeJsonText, json_file, indent=4)
    return

def check_cpe_status():
    # Mirroring the last 2 'check' functions
    # Get the directory of the currently executing script (sub_script.py)
    current_directory = os.path.dirname(os.path.abspath(__file__))
    # Get the relative path to cpe_database.db
    cpe_db_file = os.path.join(vol_path, 'cpe_database.db')
    with sqlite3.connect(cpe_db_file) as conn:
        # Create database cursor
        cursor = conn.cursor()
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='cpes'")
        table_exists = cursor.fetchone()
        logger.info(f'STATUS = {table_exists}')
        # If table exists, return 1 for now.
        if (False):
            cursor.execute(f"SELECT COUNT(*) FROM cpes")
            logger.info(f"TABLE EXISTS WITH {cursor.fetchone()} ENTRIES")
            return 1
        # Table not found, return 3
        else:
            return 3