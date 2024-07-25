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
xml_file_path = '../data/cwe/cwe_dict.xml'

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

with open("../mapping/cwe/cwes.json", "w") as json_file:
    json.dump(cwes, json_file, indent=4)
