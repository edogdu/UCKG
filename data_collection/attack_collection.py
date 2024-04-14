import os
import requests
from config import LOGGER
from parse import parse_attack_file
from process import shared_functions as sf
# from utilities import check_status, write_file, calculate_file_hash, call_mapper_update, call_ontology_updater

def download_attack_json_file():

    url = 'https://d3fend.mitre.org/api/offensive-technique/all.json'

    try:

        # Send a GET request to fetch the JSON file
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors
        json_data = response.json()

        # Set the filename
        vol_path = os.environ['VOL_PATH']
        final_filename = os.path.join(vol_path, "attack.json")
        # Check if the request was successful
        if response.status_code == 200:
            if sf.check_status("attack") == 0:
                LOGGER.info("attack.json exists...")
                filename = os.path.join(vol_path, "tmp_attack.json")
                LOGGER.info("Writing tmp_attack.json")
                sf.write_file(filename, json_data)

                # Calculate the hashes for tmp and final.
                tmp_file_hash = sf.calculate_file_hash(filename)
                final_file_hash = sf.calculate_file_hash(final_filename)

                # Compare hashes
                if tmp_file_hash == final_file_hash:
                    # Hashes are the same, delete tmp file
                    os.remove(filename)
                    LOGGER.info("The new file is identical to the existing file. Deleted tmp_att&ck.json.")
                else:
                    # Hashes are different, replace existing file
                    os.remove(final_filename)
                    os.rename(filename, "/vol/data/attack.json")
                    LOGGER.info("The new file is different from the existing file. Replaced attack.json with "
                                "tmp_att&ck.json.")
            else:
                LOGGER.info("attack.json DOES NOT exist...")
                filename = os.path.join(vol_path, "attack.json")
                LOGGER.info("Writing attack.json")
                sf.write_file(filename, json_data)

            LOGGER.info(f"File '{filename}' downloaded and saved successfully.")
        else:
            LOGGER.info("Failed to download the ATTACK JSON file.")

        LOGGER.info("Beginning JSON data parse for attack")
        attack_json_data = parse_attack_file(final_filename)
        #attack_parsed_filename = os.path.join(os.environ['VOL_PATH'], "attack.json")
        attack_parsed_filename = "./data/attack/attack.json"
        LOGGER.info(f"Beginning JSON data parse save {attack_parsed_filename}")
        sf.write_file(attack_parsed_filename, attack_json_data)
        LOGGER.info(f"{attack_parsed_filename} saved successfully")
    except requests.exceptions.RequestException as e:
        # Handle any API request errors
        LOGGER.info(f"Error making API request: {e}")


def attack_init():
    LOGGER.info("############################")
    LOGGER.info("Beginning ATT&CK Data Download")
    LOGGER.info("############################\n")

    # Download latest D3FEND json from mitre.
    download_attack_json_file()

    LOGGER.info("ATT&CK Data Download Complete")
    LOGGER.info("Beginning ATT&CK Data Call Mapper Update")
    successfully_mapped = sf.call_mapper_update("attack")

    if successfully_mapped:
        LOGGER.info("ATT&CK Data Successfully Mapped")
        LOGGER.info("Beginning ATT&CK Ontology Updater")
        sf.call_ontology_updater()
        LOGGER.info("ATT&CK Ontology Updater Complete")
        LOGGER.info("############################\n")
    else:
        LOGGER.info("############################")
        LOGGER.info("ATT&CK Ontology Update Failed")
        LOGGER.info("############################\n")