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


import xml.etree.ElementTree as ET


def parse_capec_file(file_path):
    try:
        # Parse XML file
        tree = ET.parse(file_path)
        root = tree.getroot()

        # Define namespaces
        namespaces = {
            'xmlns': 'http://capec.mitre.org/capec-3',
            'xhtml': 'http://www.w3.org/1999/xhtml',
        }

        # Initialize list to store parsed data
        parsed_data = []

        # Extract attack patterns
        attack_patterns = root.findall('.//xmlns:Attack_Pattern', namespaces)
        for attack_pattern in attack_patterns:
            attack = {}
            attack['ID'] = attack_pattern.get('ID')
            attack['Name'] = attack_pattern.get('Name')
            attack['Abstraction'] = attack_pattern.get('Abstraction')
            attack['Status'] = attack_pattern.get('Status')

            # Description
            description = attack_pattern.find('.//xmlns:Description', namespaces)
            attack['Description'] = description.text if description is not None else ''

            # Likelihood of Attack
            likelihood = attack_pattern.find('.//xmlns:Likelihood_Of_Attack', namespaces)
            attack['Likelihood_Of_Attack'] = likelihood.text if likelihood is not None else ''

            # Typical Severity
            severity = attack_pattern.find('.//xmlns:Typical_Severity', namespaces)
            attack['Typical_Severity'] = severity.text if severity is not None else ''

            # Related Attack Patterns
            related_patterns = attack_pattern.findall('.//xmlns:Related_Attack_Patterns/xmlns:Related_Attack_Pattern',
                                                      namespaces)
            attack['Related_Attack_Patterns'] = [related_pattern.get('CAPEC_ID') for related_pattern in
                                                 related_patterns]

            # Execution Flow
            execution_flow = attack_pattern.findall('.//xmlns:Execution_Flow/xmlns:Attack_Step', namespaces)
            attack['Execution_Flow'] = [{'Step': step.findtext('xmlns:Step', namespaces),
                                         'Phase': step.findtext('xmlns:Phase', namespaces),
                                         'Description': step.findtext('xmlns:Description', namespaces),
                                         'Techniques': [technique.text for technique in
                                                        step.findall('xmlns:Technique', namespaces)]}
                                        for step in execution_flow]

            # Prerequisites
            prerequisites = attack_pattern.findall('.//xmlns:Prerequisites/xmlns:Prerequisite', namespaces)
            attack['Prerequisites'] = [prerequisite.text for prerequisite in prerequisites]

            # Skills Required
            skills_required = attack_pattern.findall('.//xmlns:Skills_Required/xmlns:Skill', namespaces)
            attack['Skills_Required'] = [{'Level': skill.get('Level'), 'Description': skill.text} for skill in
                                         skills_required]

            # Resources Required
            resources_required = attack_pattern.findall('.//xmlns:Resources_Required/xmlns:Resource', namespaces)
            attack['Resources_Required'] = [resource.text for resource in resources_required]

            # Consequences
            consequences = attack_pattern.findall('.//xmlns:Consequences/xmlns:Consequence', namespaces)
            attack['Consequences'] = [{'Scope': consequence.findtext('xmlns:Scope', namespaces),
                                       'Impact': consequence.findtext('xmlns:Impact', namespaces)}
                                      for consequence in consequences]

            # Mitigations
            mitigations = attack_pattern.findall('.//xmlns:Mitigations/xmlns:Mitigation', namespaces)
            attack['Mitigations'] = [mitigation.text for mitigation in mitigations]

            # Example Instances
            example_instances = attack_pattern.findall('.//xmlns:Example_Instances/xmlns:Example', namespaces)
            attack['Example_Instances'] = [example.text for example in example_instances]

            # Related Weaknesses
            related_weaknesses = attack_pattern.findall('.//xmlns:Related_Weaknesses/xmlns:Related_Weakness',
                                                        namespaces)
            attack['Related_Weaknesses'] = ["CWE-" + weakness.get('CWE_ID') for weakness in related_weaknesses]

            # Taxonomy Mappings
            taxonomy_mappings = attack_pattern.findall('.//xmlns:Taxonomy_Mappings/xmlns:Taxonomy_Mapping', namespaces)
            attack['Taxonomy_Mappings'] = []
            for mapping in taxonomy_mappings:
                entry_ids = mapping.findall('xmlns:Entry_ID', namespaces)
                attack['Taxonomy_Mappings'].extend([entry_id.text for entry_id in entry_ids])

            # Append parsed attack pattern to list
            parsed_data.append(attack)

        return parsed_data

    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return None