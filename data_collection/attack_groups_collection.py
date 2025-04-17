import os
import requests
import json
import pandas as pd
import numpy as np
from io import BytesIO
from config import LOGGER
from parse import parse_groups_file
from process import shared_functions as sf
from bs4 import BeautifulSoup
# from utilities import check_status, write_file, calculate_file_hash, call_mapper_update, call_ontology_updater

def download_groups_json_file():

    url = 'https://attack.mitre.org/resources/attack-data-and-tools/'
    try:
        # Download Excel files from the HTML page and convert them to JSON.
        # Fetch the HTML page from the URL
        html_response = requests.get(url)
        html_response.raise_for_status()
        html = html_response.text

        # Parse HTML using BeautifulSoup
        soup = BeautifulSoup(html, 'html.parser')
        # Base URL is needed to build full links from relative paths.
        base_url = "https://attack.mitre.org"

        # Define the exact Excel file paths we need
        excel_paths = [
            "/docs/enterprise-attack-v16.1/enterprise-attack-v16.1.xlsx",
            "/docs/mobile-attack-v16.1/mobile-attack-v16.1.xlsx",
            "/docs/ics-attack-v16.1/ics-attack-v16.1.xlsx"
        ]

        # Search for <a> tags whose href matches one of our required paths.
        excel_files = {}
        for a in soup.find_all('a', href=True):
            href = a.get("href")
            if href in excel_paths:
                if "enterprise-attack" in href:
                    excel_files["enterprise-attack"] = base_url + href
                elif "mobile-attack" in href:
                    excel_files["mobile-attack"] = base_url + href
                elif "ics-attack" in href:
                    excel_files["ics-attack"] = base_url + href

        if len(excel_files) < 3:
            LOGGER.info("Not all required Excel links were found!")

        # For each Excel file, download and convert it to JSON
        all_data = []
        for domain, file_url in excel_files.items():
            LOGGER.info(f"Downloading {file_url}")
            file_response = requests.get(file_url)
            file_response.raise_for_status()
            # Use BytesIO to load the Excel content directly
            df = pd.read_excel(BytesIO(file_response.content), sheet_name="groups")
            # Replace any NaN values with None (so they become JSON null)
            df = df.replace({np.nan: None})
            # Convert DataFrame rows to dictionaries and add them to our list.
            records = df.to_dict(orient='records')
            all_data.extend(records)

        # Set the combined JSON data from the Excel files
            json_data = {"@graph": all_data}

            # Set the filename and volume path
            vol_path = os.environ['VOL_PATH']
            final_filename = os.path.join(vol_path, "groups.json")

            # Check if the file already exists and process accordingly
            if os.path.exists(final_filename):
                if sf.check_status("groups") == 0:
                    LOGGER.info("groups.json exists...")
                    tmp_filename = os.path.join(vol_path, "tmp_groups.json")
                    LOGGER.info("Writing tmp_groups.json")
                    sf.write_file(tmp_filename, json_data)

                    # Calculate the hashes for tmp and final.
                    tmp_file_hash = sf.calculate_file_hash(tmp_filename)
                    final_file_hash = sf.calculate_file_hash(final_filename)

                    # Compare hashes and update if necessary.
                    if tmp_file_hash == final_file_hash:
                        os.remove(tmp_filename)
                        LOGGER.info("The new file is identical to the existing file. Deleted tmp_groups.json.")
                    else:
                        os.remove(final_filename)
                        os.rename(tmp_filename, final_filename)
                        LOGGER.info("The new file is different from the existing file. Replaced groups.json with tmp_groups.json.")
                else:
                    LOGGER.info("groups.json DOES NOT exist...")
                    LOGGER.info("Writing groups.json")
                    sf.write_file(final_filename, json_data)

                LOGGER.info(f"File '{final_filename}' downloaded and saved successfully.")
            else:
                # If the file does not exist, simply write the json_data.
                LOGGER.info("groups.json does not exist. Writing new file.")
                sf.write_file(final_filename, json_data)
                LOGGER.info(f"File '{final_filename}' written successfully.")

            LOGGER.info("Beginning JSON data parse for groups")
            groups_json_data = parse_groups_file(final_filename)
            groups_parsed_filename = "./data/attack/groups.json"
            LOGGER.info(f"Beginning JSON data parse save {groups_parsed_filename}")
            sf.write_file(groups_parsed_filename, groups_json_data)
            LOGGER.info(f"{groups_parsed_filename} saved successfully")
    except requests.exceptions.RequestException as e:
        # Handle any API request errors
        LOGGER.info(f"Error making API request: {e}")

def groups_init():
    LOGGER.info("############################")
    LOGGER.info("Beginning groups Data Download")
    LOGGER.info("############################\n")

    # Download latest groups data by converting the Excel files to JSON.
    download_groups_json_file()
    '''
    LOGGER.info("groups Data Download Complete")
    LOGGER.info("Beginning groups Data Call Mapper Update")
    successfully_mapped = sf.call_mapper_update("groups")
    LOGGER.info("groups Data Call Mapper Update Complete")

    if successfully_mapped:
        LOGGER.info("groups Data Successfully Mapped")
        LOGGER.info("Beginning groups Ontology Updater")
        sf.call_ontology_updater(reason=True)
        LOGGER.info("groups Ontology Updater Complete")
        LOGGER.info("############################\n")
    else:
        LOGGER.info("############################")
        LOGGER.info("groups Ontology Update Failed")
        LOGGER.info("############################\n")
    '''