# File: collect.py
# Purpose: This Python script parses an XML file, extracts specific elements
# based on predefined paths, formats the extracted elements into a JSON object,
# and writes the JSON object to a file.
#
# Functions:
#     extract_specific_elements(xml_file, target_path): Parses the XML file and
#                                                       extracts specific
#                                                       elements based on the
#                                                       provided target path.
#                                                       Returns a list of
#                                                       extracted elements.
#
# Variables:
# xml_file: Path to the XML file to be parsed.
# target_path: Dictionary containing XPath expressions for the target elements.
#
# Main Logic:
#   Defines the path to the XML file and the target elements.
#   Calls the extract_specific_elements function to extract specific elements from the XML file.
#   Formats the extracted elements into a JSON object containing CWE IDs.
#   Writes the JSON object to a file named "cwes.json" in the specified directory.
#
# Last Updated (by):

import xml.etree.ElementTree as ET
import json
from config import LOGGER

import requests


# Function to parse XML file and extract specific elements
def extract_cwe_elements():

    # Specify the path to your XML file
    xml_file_path = './rml_mapper/cwe_dict.xml'

    # Parse the XML file
    tree = ET.parse(xml_file_path)
    root = tree.getroot()

    # Define the path to the target elements
    target_path = {
        'Weaknesses': './{http://cwe.mitre.org/cwe-7}Weaknesses',
        'Weakness': './{http://cwe.mitre.org/cwe-7}Weakness',
        'ID': './ID'
    }

    # List to hold the extracted elements
    extracted_elements = []

    # Navigate through the XML tree and extract elements
    for weaknesses in root.findall(target_path['Weaknesses']):
        for weakness in weaknesses.findall(target_path['Weakness']):
            id_value = weakness.get('ID')
            if id_value is not None:
                extracted_elements.append(id_value)

    cwes = {"cwes": []}
    # Print the extracted IDs
    for ID in extracted_elements:
        cwes["cwes"].append({"cwe": {
            "id": "CWE-" + str(ID)
        }})

    for cwe in cwes['cwes']:
        print(cwe)

    with open("./rml_mapper/cwe/cwes.json", "w") as json_file:
        json.dump(cwes, json_file, indent=4)


def parse_d3fend_file(file_path):

    parsed_data = []

    try:
        with open(file_path, 'r') as file:
            json_data = json.load(file)
            for item in json_data['@graph']:
                entry = {'@id': item.get('@id', ''), '@type': item.get('@type', ''),
                         '@d3f:f3fend-id': item.get('d3f:d3fend-id', ''),
                         '@rdfs:label': item.get('rdfs:label', '')}
                api_url = f"https://d3fend.mitre.org/api/technique/{item['@id']}.json"

                try:
                    # Make API call to retrieve JSON data
                    response = requests.get(api_url)
                    response.raise_for_status()  # Raise an exception for HTTP errors
                    json_data = response.json()

                    # Parse JSON data for off_tech_id
                    bindings = json_data['def_to_off']['results']['bindings']
                    off_tech_id = ""
                    for binding in bindings:
                        off_tech_id = binding.get('off_tech_id', {}).get('value', '')
                        if off_tech_id:
                            break  # Assuming there's only one off_tech_id
                    entry['off_tech_id'] = off_tech_id
                except requests.exceptions.RequestException as e:
                    # Handle any API request errors
                    print(f"Error making off_tech_id API request: {e}")
                parsed_data.append(entry)
            return parsed_data
    except Exception as e:
        # Handle any API request errors
        LOGGER.info(f"Error parsing D3FEND file: {e}")
        return None


def parse_attack_file(file_path):

    parsed_data = []

    try:
        with open(file_path, 'r') as file:
            json_data = json.load(file)
            graph = json_data.get('@graph', [])

            for item in graph:
                entry = {'@id': item['@id'], 'd3f:attack-id': item['d3f:attack-id'], 'rdfs:label': item['rdfs:label']}
                parsed_data.append(entry)

        return parsed_data
    except Exception as e:
        # Handle any API request errors
        LOGGER.info(f"Error parsing D3FEND file: {e}")
        return None
