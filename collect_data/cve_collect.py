import requests
import os
import json
import datetime
import sqlite3
import time
from config import vol_file_path as vol_path, LOGGER
from utilities import format_datetime_string, call_mapper_update, call_ontology_updater, get_cwe_id_list


def cve_update():
    LOGGER.info("cve_collect.cve_update Not added yet...")


# function to collect data from cve.mitre.org
def cve_init():
    # Define the relative path to the data file
    cve_db_file = os.path.join(vol_path, 'cve_database.db')
    with sqlite3.connect(cve_db_file) as conn:
        # Create database cursor
        cursor = conn.cursor()

        LOGGER.info("############################################################################")
        LOGGER.info("Starting data extraction of CVE data from National Vulnerability Database")
        LOGGER.info("############################################################################\n")

        start_index = 100000

        # Check if the meta table exists
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='cve_meta'")
        table_exists = cursor.fetchone()
        if table_exists:
            LOGGER.info("Reading cve_meta table data...")
            cursor.execute(f"SELECT init_finished FROM cve_meta")
            row = cursor.fetchone()
            init_finished = row[0]
            if init_finished == 1:
                LOGGER.info("###############################################")
                LOGGER.info("CVE initialization already complete exiting now")
                LOGGER.info("###############################################\n")
                return
            cursor.execute(f"SELECT offset FROM cve_meta")
            row = cursor.fetchone()
            start_index = row[0]
        else:
            LOGGER.info("Table cve_meta does not exist. Creating table...")
            # Create cve_meta table
            cursor.execute('''CREATE TABLE IF NOT EXISTS cve_meta
                            (id INTEGER PRIMARY KEY, offset INTEGER, last_modified TEXT, init_finished INTEGER DEFAULT 0)''')
            current_time = format_datetime_string(str(datetime.datetime.now()))
            cursor.execute("INSERT INTO cve_meta (id, offset, last_modified) VALUES (?, ?, ?)", (12345, start_index, current_time))
            conn.commit()

        LOGGER.info(f"Reading in cve data starting with index {start_index}...")

        # get the data from the website
        cve_api_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?startIndex="
        LOGGER.info(f"{cve_api_url}{start_index}&resultsPerPage=2000")
        response = requests.get(f"{cve_api_url}{start_index}&resultsPerPage=2000")
        init_finished = False
        original_offset = start_index

        cves = {"cves": []}
        cwe_id_list = get_cwe_id_list()
        # LOGGER.info(cwe_id_list)
        while (response.status_code == 200 or response.status_code == 403 or response.status_code == 503
        ) and init_finished == False and start_index < 104000:
            early_exit = False
            if response.status_code == 403 or response.status_code == 503:
                for i in range(4):
                    if i == 3:
                        LOGGER.info("Unable to receive response from API, saving results and exiting...")
                        early_exit = True

                    LOGGER.info(f"Retry #{i + 1}: Waiting for 10 seconds, due to API throttling...")
                    time.sleep(10)
                    response = requests.get(f"{cve_api_url}{start_index}&resultsPerPage=2000")
                    if response.status_code == 200:
                        LOGGER.info("Retry Successful! Continuing processing...")
                        break

            if early_exit:
                break

            beginning_index = start_index
            json_data = response.json()

            # Check if we are done after this loop
            vul_count = len(json_data["vulnerabilities"])

            if vul_count < 2000:
                init_finished = True

            for cve in json_data["vulnerabilities"]:
                cwes = []
                try:
                    for weakness in  cve['cve']['weaknesses']:
                        for desc in weakness['description']:
                            weakness_value = desc['value'].strip()
                            if weakness_value in cwe_id_list:
                                LOGGER.info(f"Found CWE match for CVE: {cve['cve']['id']} - hasCWE -> {str(desc['value'])}")
                                cwes.append({"cwe": {"id": desc['value']}})
                except Exception as e:
                    pass

                start_index += 1

                cves["cves"].append({"cve":{
                    "id": cve['cve']["id"],
                    "lastModified":cve['cve']["lastModified"],
                    "published":cve['cve']["published"],
                    "descriptions": cve['cve']['descriptions'],
                    "cwes": cwes
                    }})

            with open("./rml_mapper/cve/cves.json", "w") as json_file:
                json.dump(cves, json_file, indent=4)

            successfully_mapped = call_mapper_update("cve")
            if successfully_mapped:
                call_ontology_updater()

            current_time = format_datetime_string(str(datetime.datetime.now()))
            cursor.execute("UPDATE cve_meta SET offset=?, last_modified=? WHERE id=12345", (start_index, current_time))
            LOGGER.info(f"Completed batch with startIndex={beginning_index}")

            # Wait 5 seconds to avoid throttling
            time.sleep(5)

            response = requests.get(f"{cve_api_url}{start_index}&resultsPerPage=2000")

        if init_finished:
            cursor.execute("UPDATE cve_meta SET init_finished=1 WHERE id=12345")

        total_records = start_index
        records_added = total_records - original_offset

        LOGGER.info("############################")
        LOGGER.info("Data extraction completed")
        LOGGER.info("############################\n")
        LOGGER.info(f"Database Meta-Table: cves_meta")
        LOGGER.info(f"Total Records: {total_records}")
        LOGGER.info(f"Records Added: {records_added}")
        LOGGER.info(f"Database initialization finished: {init_finished}\n")
