import os
import requests
import json
import pandas as pd
import numpy as np
import re
from io import BytesIO
from config import LOGGER
from process import shared_functions as sf
from bs4 import BeautifulSoup
from packaging import version


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

        # Step 1: Find all available versions and get the latest
        version_pattern = r'/docs/attack-excel-files/v([\d.]+)/'
        versions = set()
        for a in soup.find_all("a", href=True):
            match = re.search(version_pattern, a["href"])
            if match:
                versions.add(match.group(1))
        
        if not versions:
            raise ValueError("No ATT&CK versions found on the page")
        
        # Get the latest version
        latest_version = max(versions, key=lambda v: version.parse(v))
        LOGGER.info(f"ATT&CK v{latest_version} - {cfg['name']}")

        # Step 2: Find the base Excel files for the latest version
        prefixes = ["enterprise-attack", "mobile-attack", "ics-attack"]
        excel_files = {}
        
        # Pattern to match base files: /docs/attack-excel-files/v{VERSION}/{PREFIX}/{PREFIX}-v{VERSION}.xlsx
        for prefix in prefixes:
            # Build the expected URL for this prefix with the latest version
            expected_url = f"/docs/attack-excel-files/v{latest_version}/{prefix}/{prefix}-v{latest_version}.xlsx"
            
            # Verify this URL exists in the page
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href == expected_url:
                    excel_files[prefix] = base_url + href
                    break

        if len(excel_files) < 3:
            LOGGER.warning(f"Only found {len(excel_files)}/3 ATT&CK files: {list(excel_files.keys())}")

        # Step 3: Download and convert each Excel file to JSON
        all_data = []
        for domain, file_url in excel_files.items():
            file_response = requests.get(file_url)
            file_response.raise_for_status()
            
            # Use BytesIO to load the Excel content directly
            sheet = cfg["sheet_name"] if cfg["sheet_name"] is not None else 0
            df = pd.read_excel(BytesIO(file_response.content), sheet_name=sheet)
            
            # Replace any NaN values with None (so they become JSON null)
            df = df.replace({np.nan: None})
            
            # Convert DataFrame rows to dictionaries and add them to our list.
            records = df.to_dict(orient='records')
            all_data.extend(records)

        # Step 4: Combine all data and save to file (AFTER all downloads)
        json_data = {"@graph": all_data}
        LOGGER.info(f"Downloaded {len(all_data)} records")

        # Set the filename and volume path
        vol_path = os.environ['VOL_PATH']
        final_filename = os.path.join(vol_path, cfg["output_json"])

        # Check if the file already exists and process accordingly
        if os.path.exists(final_filename):
            if sf.check_status(cfg["name"]) == 0:
                tmp_filename = os.path.join(vol_path, "tmp_" + cfg["output_json"])
                sf.write_file(tmp_filename, json_data)

                # Calculate the hashes for tmp and final.
                tmp_file_hash = sf.calculate_file_hash(tmp_filename)
                final_file_hash = sf.calculate_file_hash(final_filename)

                # Compare hashes and update if necessary.
                if tmp_file_hash == final_file_hash:
                    os.remove(tmp_filename)
                else:
                    os.remove(final_filename)
                    os.rename(tmp_filename, final_filename)
                    LOGGER.info(f"Updated {cfg['output_json']}")
            else:
                sf.write_file(final_filename, json_data)
        else:
            # If the file does not exist, simply write the json_data.
            sf.write_file(final_filename, json_data)

        # Step 5: Parse the JSON data
        json_data = cfg["parse_fn"](final_filename)
        parsed_filename = "./data/attack/" + cfg["output_json"]
        sf.write_file(parsed_filename, json_data)
        
    except requests.exceptions.RequestException as e:
        # Handle any API request errors
        LOGGER.error(f"Error making API request: {e}")
    except Exception as e:
        # Handle any other errors
        LOGGER.error(f"Error processing ATT&CK data: {e}")

def attack_init():
    LOGGER.info("Starting ATT&CK data collection...")
    for cfg in DATASETS:
        download_attack_json_file(cfg)

    # Now call mapper + ontology just once
    success = sf.call_mapper_update("attack")

    if success:
        sf.call_ontology_updater(reason=True)
        LOGGER.info("ATT&CK data collection complete")
    else:
        LOGGER.error("ATT&CK mapping failed")