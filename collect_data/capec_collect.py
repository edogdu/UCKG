import os
import requests
from config import LOGGER
from parse import parse_d3fend_file
from utilities import check_status, write_file, calculate_file_hash, call_mapper_update, call_ontology_updater



def download_capec_json_file():
    pass
    # LOGGER.info("############################")
    # LOGGER.info("Beginning CAPEC Data Download")
    # LOGGER.info("############################\n")
    #
    # url = 'https://d3fend.mitre.org/api/dao/artifacts.json'
    #
    # # Send a GET request to fetch the JSON file
    # response = requests.get(url)
    # json_data = response.json()
    #
    # # Set the filename
    # final_filename = os.path.join(os.environ['VOL_PATH'], "d3fend.json")
    #
    # # Check if the request was successful
    # if response.status_code == 200:
    #     if check_status("d3fend") == 0:
    #         LOGGER.info("d3fend.json exists...")
    #         filename = os.path.join(os.environ['VOL_PATH'], "tmp_d3fend.json")
    #         LOGGER.info("Writing tmp_d3fend.json")
    #         write_file(filename, json_data)
    #
    #         # Calculate the hashes for tmp and final.
    #         tmp_file_hash = calculate_file_hash(filename)
    #         final_file_hash = calculate_file_hash(final_filename)
    #
    #         # Compare hashes
    #         if tmp_file_hash == final_file_hash:
    #             # Hashes are the same, delete tmp file
    #             os.remove(filename)
    #             LOGGER.info("The new file is identical to the existing file. Deleted tmp_d3fend.json.")
    #         else:
    #             # Hashes are different, replace existing file
    #             os.remove(final_filename)
    #             os.rename(filename, "d3fend.json")
    #             LOGGER.info("The new file is different from the existing file. Replaced d3fend.json with tmp_d3fend.json.")
    #     else:
    #         LOGGER.info("d3fend.json DOES NOT exist...")
    #         filename = os.path.join(os.environ['VOL_PATH'], "d3fend.json")
    #         LOGGER.info("Writing d3fend.json")
    #         write_file(filename, json_data)
    #
    #     LOGGER.info(f"File '{filename}' downloaded and saved successfully.")
    #     LOGGER.info("############################\n")
    # else:
    #     LOGGER.info("Failed to download the D3FEND JSON file.")
    #
    # LOGGER.info("Beginning JSON data parse for d3fend")
    # d3fend_json_data = parse_d3fend_file(final_filename)
    # d3fend_parsed_filename = os.path.join(os.environ['ROOT_FOLDER'], "rml_mapper/d3fend/d3fend.json")
    # LOGGER.info(f"Beginning JSON data parse save {d3fend_parsed_filename}")
    # write_file(d3fend_parsed_filename, d3fend_json_data)
    # LOGGER.info(f"{d3fend_parsed_filename} saved successfully")


def capec_init():
    pass
    # # Download latest capec data.
    # download_capec_json_file()
    #
    # successfully_mapped = call_mapper_update("capec")
    # if successfully_mapped:
    #     call_ontology_updater()
