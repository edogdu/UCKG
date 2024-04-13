import json
import xml.etree.ElementTree as ET
from config import LOGGER
from utilities import call_mapper_update, call_ontology_updater


def cwe_update():
    LOGGER.info("cwe_collect.cwe_update Not added yet...")


def cwe_init():
    # Parse the XML file
    xml_file_path = '..rml_mapper/cwe_dict.xml'

    # Define the path to the target elements
    target_path = {
        'Weaknesses': './{http://cwe.mitre.org/cwe-7}Weaknesses',
        'Weakness': './{http://cwe.mitre.org/cwe-7}Weakness',
        'ucodescription': './{http://cwe.mitre.org/cwe-7}Description',
        'ucocommonConsequences': './{http://cwe.mitre.org/cwe-7}Common_Consequences',
        'contentHistory': './{http://cwe.mitre.org/cwe-7}Content_History',
        'submission': './{http://cwe.mitre.org/cwe-7}Submission',
        'ucotimeOfIntroduction': './{http://cwe.mitre.org/cwe-7}Submission_Date',
        'ucocweSummary': './{http://cwe.mitre.org/cwe-7}Description',
        'ucocweExtendedSummary': './{http://cwe.mitre.org/cwe-7}Extended_Description',
        'ucocweID': 'ID',
        'ucocweName': 'Name'
    }

    tree = ET.parse(xml_file_path)
    root = tree.getroot()

    # List to hold the extracted CWEs
    cwes = {'cwes': []}

    # Navigate through the XML tree and extract elements
    for weaknesses in root.findall(target_path['Weaknesses']):
        for weakness in weaknesses.findall(target_path['Weakness']):
            id_value = str(weakness.get(target_path['ucocweID']))
            id_value = "CWE-" + id_value.strip()
            description = weakness.find(target_path['ucodescription'])
            if description is not None:
                description = description.text
            common_consequences = weakness.find(target_path['ucocommonConsequences'])
            if common_consequences is not None:
                common_consequences = str(ET.tostring(common_consequences))
            time_of_introduction = None
            content_history = weakness.find(target_path['contentHistory'])
            if content_history is not None:
                submission = content_history.find(target_path['submission'])
                if submission is not None:
                    time_of_introduction = submission.find(target_path['ucotimeOfIntroduction']).text
            summary = weakness.find(target_path['ucocweSummary'])
            if summary is not None:
                summary = summary.text
            name = weakness.get(target_path['ucocweName'])
            extended_summary = weakness.find(target_path['ucocweExtendedSummary'])
            if extended_summary is not None:
                if len(extended_summary.findall("./")) == 0:
                    extended_summary = extended_summary.text
                else:
                    extended_summary = str(ET.tostring(extended_summary))

            # print(f"id_value: {id_value}")
            # print(f"description: {description}")
            # print(f"common_consequences: {common_consequences}")
            # print(f"time_of_introduction: {time_of_introduction}")
            # print(f"summary: {summary}")
            # print(f"name: {name}")
            # print(f"extended_summary: {extended_summary}")

            cwes['cwes'].append(
                {
                    "cwe": {
                        "id_value": id_value,
                        "description": description,
                        "common_consequences": common_consequences,
                        "time_of_introduction": time_of_introduction,
                        "summary": summary,
                        "name": name,
                        "extended_summary": extended_summary
                    }

                }
            )

    with open("..rml_mapper/cwe/cwes.json", "w") as json_file:
        json.dump(cwes, json_file, indent=4)

    successfully_mapped = call_mapper_update("cwe")
    if successfully_mapped:
        LOGGER.info("Successfully mapped CWEs to RML mapper")
        call_ontology_updater()

    LOGGER.info("############################")
    LOGGER.info("CWE Data extraction completed")
    LOGGER.info("############################\n")
    # logger.info(f"Database Meta-Table: cves_meta")
    # logger.info(f"Total Records: {total_records}")
    # logger.info(f"Records Added: {records_added}")
    # logger.info(f"Database initialization finished: {init_finished}\n")
