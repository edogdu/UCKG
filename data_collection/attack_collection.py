import os
import requests
import json
import pandas as pd
import numpy as np
from io import BytesIO
from config import LOGGER
from process import shared_functions as sf
from bs4 import BeautifulSoup
from fnmatch import fnmatch


# Import your parse functions
from parse import (
    parse_attack_file,
    parse_mitigations_file,
    parse_campaigns_file,
    parse_software_file,
    parse_tactics_file,
    parse_groups_file,
    parse_relationships_file
)


# Per-dataset config: just sheet_name, parse fn, and output name
DATASETS = [
    {
        "name":        "attack",
        "sheet_name":  None,
        "parse_fn":    parse_attack_file,
        "output_json": "attack.json",
    },
    {
        "name":        "mitigations",
        "sheet_name":  "mitigations",
        "parse_fn":    parse_mitigations_file,
        "output_json": "mitigations.json",
    },
    {
        "name":        "campaigns",
        "sheet_name":  "campaigns",
        "parse_fn":    parse_campaigns_file,
        "output_json": "campaigns.json",
    },
    {
        "name":        "software",
        "sheet_name":  "software",
        "parse_fn":    parse_software_file,
        "output_json": "software.json",
    },
    {
        "name":        "tactics",
        "sheet_name":  "tactics",
        "parse_fn":    parse_tactics_file,
        "output_json": "tactics.json",
    },
    {
        "name":        "groups",
        "sheet_name":  "groups",
        "parse_fn":    parse_groups_file,
        "output_json": "groups.json",
    },
    {
        "name":        "relationships",
        "sheet_name":  "relationships",
        "parse_fn":    parse_relationships_file,
        "output_json": "relationships.json",
    },
]

def download_attack_json_file(cfg):

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
        # Dynamically grab whichever versioned Excel files exist
        prefixes = ["enterprise-attack", "mobile-attack", "ics-attack"]
        excel_files = {}
        for a in soup.find_all("a", href=True):
            href = a["href"]
            for prefix in prefixes:
                # match any version, but we'll filter by hyphens next
                pattern = f"/docs/{prefix}-v*/{prefix}-v*.xlsx"
                if fnmatch(href, pattern):
                    # grab just the filename portion
                    filename = href.rsplit("/", 1)[-1]
                    # split on '-' – the "pure" file has exactly 3 parts:
                    #   ['mobile', 'attack', 'v*.xlsx']
                    # everything else (matrices, mitigations, …) has 4+ parts
                    if len(filename.split("-")) == 3:
                        excel_files[prefix] = base_url + href
                    break

        if len(excel_files) < 3:
            LOGGER.info("Not all required Excel links were found!")

        # For each Excel file, download and convert it to JSON
        all_data = []
        for domain, file_url in excel_files.items():
            LOGGER.info(f"Downloading {file_url}")
            file_response = requests.get(file_url)
            file_response.raise_for_status()
            # Use BytesIO to load the Excel content directly
            sheet = cfg["sheet_name"] if cfg["sheet_name"] is not None else 0
            df = pd.read_excel(BytesIO(file_response.content), sheet_name=sheet)
            #df = pd.read_excel(BytesIO(file_response.content), sheet_name=cfg["sheet_name"])
            # Replace any NaN values with None (so they become JSON null)
            df = df.replace({np.nan: None})
            # Convert DataFrame rows to dictionaries and add them to our list.
            records = df.to_dict(orient='records')
            all_data.extend(records)

        # Set the combined JSON data from the Excel files
            json_data = {"@graph": all_data}

            # Set the filename and volume path
            vol_path = os.environ['VOL_PATH']
            final_filename = os.path.join(vol_path, cfg["output_json"])

            # Check if the file already exists and process accordingly
            if os.path.exists(final_filename):
                if sf.check_status(cfg["name"]) == 0:
                    LOGGER.info(cfg["output_json"]+" exists...")
                    tmp_filename = os.path.join(vol_path, "tmp_" + cfg["output_json"])
                    LOGGER.info("Writing tmp_"+ cfg["output_json"])
                    sf.write_file(tmp_filename, json_data)

                    # Calculate the hashes for tmp and final.
                    tmp_file_hash = sf.calculate_file_hash(tmp_filename)
                    final_file_hash = sf.calculate_file_hash(final_filename)

                    # Compare hashes and update if necessary.
                    if tmp_file_hash == final_file_hash:
                        os.remove(tmp_filename)
                        LOGGER.info("The new file is identical to the existing file. Deleted tmp_"+ cfg["output_json"] + ".")
                    else:
                        os.remove(final_filename)
                        os.rename(tmp_filename, final_filename)
                        LOGGER.info("The new file is different from the existing file. Replaced" + cfg["output_json"] + "with tmp_" + cfg["output_json"] + ".")
                else:
                    LOGGER.info(cfg["output_json"] + " DOES NOT exist...")
                    LOGGER.info("Writing " + cfg["output_json"])
                    sf.write_file(final_filename, json_data)

                LOGGER.info(f"File '{final_filename}' downloaded and saved successfully.")
            else:
                # If the file does not exist, simply write the json_data.
                LOGGER.info(cfg["output_json"] + " does not exist. Writing new file.")
                sf.write_file(final_filename, json_data)
                LOGGER.info(f"File '{final_filename}' written successfully.")

            LOGGER.info("Beginning JSON data parse for " + cfg["name"])
            json_data = cfg["parse_fn"](final_filename)
            parsed_filename = "./data/attack/" + cfg["output_json"]
            LOGGER.info(f"Beginning JSON data parse save {parsed_filename}")
            sf.write_file(parsed_filename, json_data)
            LOGGER.info(f"{parsed_filename} saved successfully")
    except requests.exceptions.RequestException as e:
        # Handle any API request errors
        LOGGER.info(f"Error making API request: {e}")

def attack_init():
    LOGGER.info("############################")
    LOGGER.info("Beginning ATTACK Data Downloads")
    LOGGER.info("############################\n")
    for cfg in DATASETS:
        download_attack_json_file(cfg)

    # Now call mapper + ontology just once
    LOGGER.info("ATT&CK Data Download Complete")
    LOGGER.info("Beginning ATT&CK Data Call Mapper Update")
    success = sf.call_mapper_update("attack")
    LOGGER.info("ATTACK Data Call Mapper Update Complete")

    if success:
        LOGGER.info("ATT&CK Data Successfully Mapped")
        LOGGER.info("Beginning ATT&CK Ontology Updater")
        sf.call_ontology_updater(reason=True)
        LOGGER.info("ATT&CK Ontology Updater Complete")
        LOGGER.info("############################\n")
    else:
        LOGGER.info("############################\n")
        LOGGER.error("ATT&CK Ontology Update Failed")
        LOGGER.info("############################\n")