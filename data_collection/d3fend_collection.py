import os
import requests
from config import LOGGER
from parse import parse_d3fend_file
from process import shared_functions as sf
# from utilities import check_status, write_file, calculate_file_hash, call_mapper_update, call_ontology_updater


def download_d3fend_json_file():

    url = 'https://d3fend.mitre.org/api/technique/all.json'

    try:
        # Make API call to retrieve JSON data
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors
        json_data = response.json()

        # Set the filename
        final_filename = os.path.join(os.environ['VOL_PATH'], "d3fend.json")

        # Check if the request was successful
        if response.status_code == 200:
            if sf.check_status("d3fend") == 0:
                LOGGER.info("d3fend.json exists...")
                filename = os.path.join(os.environ['VOL_PATH'], "tmp_d3fend.json")
                LOGGER.info("Writing tmp_d3fend.json")
                sf.write_file(filename, json_data)

                # Calculate the hashes for tmp and final.
                tmp_file_hash = sf.calculate_file_hash(filename)
                final_file_hash = sf.calculate_file_hash(final_filename)

                # Compare hashes
                if tmp_file_hash == final_file_hash:
                    # Hashes are the same, delete tmp file
                    os.remove(filename)
                    LOGGER.info("The new file is identical to the existing file. Deleted tmp_d3fend.json.")
                else:
                    # Hashes are different, replace existing file
                    os.remove(final_filename)
                    os.rename(filename, "/vol/data/d3fend.json")
                    LOGGER.info("The new file is different from the existing file. Replaced d3fend.json with "
                                "tmp_d3fend.json.")
            else:
                LOGGER.info("d3fend.json DOES NOT exist...")
                filename = os.path.join(os.environ['VOL_PATH'], "d3fend.json")
                LOGGER.info("Writing d3fend.json")
                sf.write_file(filename, json_data)

            LOGGER.info(f"File '{filename}' downloaded and saved successfully.")
        else:
            LOGGER.info("Failed to download the D3FEND JSON file.")

        LOGGER.info("Beginning JSON data parse for d3fend")
        d3fend_json_data = parse_d3fend_file(final_filename)
        d3fend_parsed_filename = "./data/d3fend/d3fend.json"
        LOGGER.info(f"Beginning JSON data parse save {d3fend_parsed_filename}")
        sf.write_file(d3fend_parsed_filename, d3fend_json_data)
        LOGGER.info(f"{d3fend_parsed_filename} saved successfully")
    except requests.exceptions.RequestException as e:
        # Handle any API request errors
        LOGGER.info(f"Error making API request: {e}")


def d3fend_init():
    LOGGER.info("############################")
    LOGGER.info("Beginning D3FEND Data Download")
    LOGGER.info("############################\n")

    # Download latest D3FEND json from mitre.
    download_d3fend_json_file()

    LOGGER.info("D3FEND Data Download Complete")
    LOGGER.info("Beginning D3FEND Data Call Mapper Update")

    successfully_mapped = sf.call_mapper_update("d3fend")

    if successfully_mapped:
        LOGGER.info("D3FEND Data Successfully Mapped")
        LOGGER.info("Beginning D3FEND Ontology Updater")
        sf.call_ontology_updater()
        LOGGER.info("############################\n")
        LOGGER.info("D3FEND Ontology Updater Complete")
        LOGGER.info("############################\n")
    else:
        LOGGER.info("############################")
        LOGGER.info("D3FEND Ontology Update Failed")
        LOGGER.info("############################\n")