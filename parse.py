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
import math


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
                if item.get("d3f:d3fend-id") is None:
                    continue
                entry = {'@id': item.get('@id', ''), 'd3f:definition': item.get('d3f:definition', ''),
                         'd3f:d3fend-id': item.get('d3f:d3fend-id', ''),
                         'rdfs:label': item.get('rdfs:label', '')}
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
                    continue  # Skip this entry if API call fails
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
                #entry = {'@id': item['@id'], 'd3f:attack-id': item['d3f:attack-id'], 'rdfs:label': item['rdfs:label']}
                entry = {'ID': item['ID'], 'name': item['name'], 'description': item['description'], 'url': item['url'], 'domain': item['domain']}
                parsed_data.append(entry)

        return parsed_data
    except Exception as e:
        # Handle any API request errors
        LOGGER.info(f"Error parsing ATTACK file: {e}")
        return None
    
def parse_mitigations_file(file_path):
    parsed_data = []

    try:
        with open(file_path, 'r') as file:
            json_data = json.load(file)
            graph = json_data.get('@graph', [])

            for item in graph:
                entry = {'ID': item['ID'], 'name': item['name'], 'description': item['description'], 'url': item['url'], 'domain': item['domain']}
                parsed_data.append(entry)

        return parsed_data
    except Exception as e:
        # Handle any API request errors
        LOGGER.info(f"Error parsing ATTACK file: {e}")
        return None

def parse_campaigns_file(file_path):
    parsed_data = []

    try:
        with open(file_path, 'r') as file:
            json_data = json.load(file)
            graph = json_data.get('@graph', [])

            for item in graph:
                entry = {'ID': item['ID'], 'name': item['name'], 'description': item['description'], 'url': item['url'], 'domain': item['domain']}
                parsed_data.append(entry)

        return parsed_data
    except Exception as e:
        # Handle any API request errors
        LOGGER.info(f"Error parsing ATTACK file: {e}")
        return None
def parse_groups_file(file_path):
    parsed_data = []

    try:
        with open(file_path, 'r') as file:
            json_data = json.load(file)
            graph = json_data.get('@graph', [])

            for item in graph:
                entry = {'ID': item['ID'], 'name': item['name'], 'description': item['description'], 'url': item['url'], 'domain': item['domain']}
                parsed_data.append(entry)

        return parsed_data
    except Exception as e:
        # Handle any API request errors
        LOGGER.info(f"Error parsing ATTACK file: {e}")
        return None

def parse_software_file(file_path):
    parsed_data = []

    try:
        with open(file_path, 'r') as file:
            json_data = json.load(file)
            graph = json_data.get('@graph', [])

            for item in graph:
                entry = {'ID': item['ID'], 'name': item['name'], 'description': item['description'], 'url': item['url'], 'domain': item['domain']}
                parsed_data.append(entry)

        return parsed_data
    except Exception as e:
        # Handle any API request errors
        LOGGER.info(f"Error parsing ATTACK file: {e}")
        return None
def parse_tactics_file(file_path):
    parsed_data = []

    try:
        with open(file_path, 'r') as file:
            json_data = json.load(file)
            graph = json_data.get('@graph', [])

            for item in graph:
                entry = {'ID': item['ID'], 'name': item['name'], 'description': item['description'], 'url': item['url'], 'domain': item['domain']}
                parsed_data.append(entry)

        return parsed_data
    except Exception as e:
        # Handle any API request errors
        LOGGER.info(f"Error parsing ATTACK file: {e}")
        return None


def parse_relationships_file(file_path):
    parsed_data = []

    try:
        with open(file_path, 'r') as file:
            json_data = json.load(file)
            graph = json_data.get('@graph', [])

            for item in graph:
                source_id = item.get('source ID')
                # skip missing or NaN source IDs
                if source_id is None or (isinstance(source_id, float) and math.isnan(source_id)):
                    continue

                # now you know source_id is valid
                entry = {
                    'source ID': source_id,
                    'source type': item.get('source type'),
                    'target ID': item.get('target ID'),
                    'target type': item.get('target type')
                }
                parsed_data.append(entry)

        return parsed_data
    except Exception as e:
        # Handle any API request errors
        LOGGER.info(f"Error parsing ATTACK file: {e}")
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
            if description is not None:
                # Try direct text first
                description_text = description.text.strip() if description.text else ""

                # If no direct text, look for all <xhtml:p> children
                if not description_text:
                    paras = description.findall('.//xhtml:p', namespaces)
                    description_texts = [p.text.strip() for p in paras if p is not None and p.text]
                    description_text = " ".join(description_texts)
            else:
                description_text = ""
            attack['Description'] = description_text

            # Extended Description
            extended_description = attack_pattern.find('.//xmlns:Extended_Description', namespaces)
            # If not directly, check nested xhtml:p for it
            if extended_description is not None:
                extendeds = extended_description.findall('.//xhtml:p', namespaces)
                extended_texts = [p.text.strip() for p in extendeds if p is not None and p.text]
            else:
                extended_texts = []
            attack['Extended_Description'] = extended_texts

            # Likelihood of Attack
            likelihood = attack_pattern.find('.//xmlns:Likelihood_Of_Attack', namespaces)
            attack['Likelihood_Of_Attack'] = likelihood.text if likelihood is not None else ''

            # Typical Severity
            severity = attack_pattern.find('.//xmlns:Typical_Severity', namespaces)
            attack['Typical_Severity'] = severity.text if severity is not None else ''

            # Related Attack Patterns
            related_patterns = attack_pattern.findall('.//xmlns:Related_Attack_Patterns/xmlns:Related_Attack_Pattern',
                                                    namespaces)
            # Related patterns are stored as a list of strings with format "{Nature} CAPEC-{ID}"
            attack['Related_Attack_Patterns'] = [f"{related_pattern.get('Nature')} CAPEC-{related_pattern.get('CAPEC_ID')}" for related_pattern in
                                               related_patterns if related_pattern.get('CAPEC_ID')]

            # Execution Flow
            execution_flow = attack_pattern.findall('.//xmlns:Execution_Flow/xmlns:Attack_Step', namespaces)
            flow_items = []
            # Reconstruct the execution flow, including techniques, and Clean up the text
            for step in execution_flow:
                # Extract step elements directly using findtext
                step_num = step.findtext('./xmlns:Step', '', namespaces)
                phase = step.findtext('./xmlns:Phase', '', namespaces)
                desc = step.findtext('./xmlns:Description', '', namespaces)
                
                # Clean up the text values
                step_num = step_num.strip() if isinstance(step_num, str) else ''
                phase = phase.strip() if isinstance(phase, str) else ''
                desc = desc.strip() if isinstance(desc, str) else ''
                
                if step_num and phase and desc:
                    # Start with the step information
                    step_info = [f"STEP-{step_num} ({phase}): {desc}"]
                    # Collect all techniques for this step
                    techniques = step.findall('./xmlns:Technique', namespaces)
                    for idx, technique in enumerate(techniques, 1):
                        if technique is not None and technique.text:
                            tech_text = technique.text.strip()
                            if tech_text:
                                step_info.append(f"TECHNIQUE-{idx}: {tech_text}")
                    
                    # Join all information with semicolons
                    flow_items.append(" | ".join(step_info))
            attack['Execution_Flow'] = flow_items

            # Prerequisites
            prerequisites = attack_pattern.findall('.//xmlns:Prerequisites/xmlns:Prerequisite', namespaces)
            attack['Prerequisites'] = [prerequisite.text for prerequisite in prerequisites]

            # Skills Required
            skills_required = attack_pattern.findall('.//xmlns:Skills_Required/xmlns:Skill', namespaces)
            attack['Skills_Required'] = []
            # Clean up the text values and format as "Level:level - Description:description"
            for skill in skills_required:
                level = skill.get('Level', '')
                description = skill.text.strip() if skill.text else ''
                if level and description:
                    attack['Skills_Required'].append(f"Level:{level} - Description:{description}")

            # Resources Required
            resources_required = attack_pattern.findall('.//xmlns:Resources_Required/xmlns:Resource', namespaces)
            resource_texts = []
            # Flatten all <xhtml:p> from each <Resource> into a list of strings
            for resource in resources_required:
                paras = resource.findall('.//xhtml:p', namespaces)
                for p in paras:
                    if p is not None and p.text:
                        resource_texts.append(p.text.strip())
            attack['Resources_Required'] = resource_texts

            # Consequences
            consequences = attack_pattern.findall('.//xmlns:Consequences/xmlns:Consequence', namespaces)
            attack['Consequences'] = []
            # Clean up the text values and format as "SCOPE:scope1,scope2,scope3 - IMPACT:impact_text"
            for consequence in consequences:
                # Get all scopes for this consequence
                scopes = consequence.findall('./xmlns:Scope', namespaces)
                impact = consequence.findtext('./xmlns:Impact', '', namespaces)
                
                if scopes and impact:
                    # Clean and collect all scope texts
                    scope_texts = []
                    for idx, scope in enumerate(scopes, 1):
                        if scope.text:
                            scope_texts.append(scope.text.strip())
                    
                    if scope_texts:
                        # Format as "SCOPE:scope1,scope2,scope3 - IMPACT:impact_text"
                        scope_str = ",".join(scope_texts)
                        attack['Consequences'].append(f"SCOPE:{scope_str} - IMPACT:{impact.strip()}")

            # Mitigations
            mitigations = attack_pattern.findall('.//xmlns:Mitigations/xmlns:Mitigation', namespaces)
            attack['Mitigations'] = [mitigation.text for mitigation in mitigations]

            # Example Instances
            example_instances = attack_pattern.findall('.//xmlns:Example_Instances/xmlns:Example', namespaces)
            attack['Example_Instances'] = []
            for example in example_instances:
                # Try to get direct text first
                example_text = example.text.strip() if example.text else ""
                
                # If direct text is empty, try nested <xhtml:p>
                if not example_text:
                    para = example.find('.//xhtml:p', namespaces)
                    example_text = para.text.strip() if para is not None and para.text else ""

                # Only add non-empty examples
                if example_text:
                    attack['Example_Instances'].append(example_text)

            # Related Weaknesses
            related_weaknesses = attack_pattern.findall('.//xmlns:Related_Weaknesses/xmlns:Related_Weakness', namespaces)
            attack['Related_Weaknesses'] = ["CWE-" + weakness.get('CWE_ID') for weakness in related_weaknesses]

            # Taxonomy Mappings
            taxonomy_mappings = attack_pattern.findall('.//xmlns:Taxonomy_Mappings/xmlns:Taxonomy_Mapping[@Taxonomy_Name="ATTACK"]', namespaces)
            attack['Taxonomy_Mappings'] = []
            # Extract Entry_ID and Entry_Name from each mapping only to those with ATTACK taxonomy of MITRE ATT&CK
            for mapping in taxonomy_mappings:
                entry_id = mapping.findtext('./xmlns:Entry_ID', '', namespaces)
                entry_name = mapping.findtext('./xmlns:Entry_Name', '', namespaces)
                if entry_id and entry_name:
                    if isinstance(entry_id, str) and isinstance(entry_name, str):
                        # Combine ID and Name into a single string
                        attack['Taxonomy_Mappings'].append(f"T{entry_id.strip()}")

            # Append parsed attack pattern to list
            parsed_data.append(attack)

        return parsed_data

    except ET.ParseError as e:
        print(f"Error parsing XML: {e}")
        return None