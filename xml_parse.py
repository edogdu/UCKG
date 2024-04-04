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

# Function to parse XML file and extract specific elements
def extract_specific_elements(xml_file, target_path):
    # Parse the XML file
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # List to hold the extracted elements
    extracted_elements = []

    # Navigate through the XML tree and extract elements
    for weaknesses in root.findall(target_path['Weaknesses']):
        for weakness in weaknesses.findall(target_path['Weakness']):
            id_value = weakness.get('ID')
            if id_value is not None:
                extracted_elements.append(id_value)

    return extracted_elements

# Specify the path to your XML file
xml_file_path = './rml_mapper/cwe_dict.xml'

# Define the path to the target elements
target_path = {
    'Weaknesses': './{http://cwe.mitre.org/cwe-7}Weaknesses',
    'Weakness': './{http://cwe.mitre.org/cwe-7}Weakness',
    'ID': './ID'
}



# Extract the specific elements
extracted_ids = extract_specific_elements(xml_file_path, target_path)

cwes = {"cwes": []}
# Print the extracted IDs
for id in extracted_ids:
    cwes["cwes"].append({"cwe":{
        "id": "CWE-" + str(id)
        }})

for cwe in cwes['cwes']:
    print(cwe)

with open("./rml_mapper/cwe/cwes.json", "w") as json_file:
    json.dump(cwes, json_file, indent=4)
