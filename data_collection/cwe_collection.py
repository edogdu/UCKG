import os
import json
import logging
import xml.etree.ElementTree as ET

from config import LOGGER
from process import shared_functions as sf
import requests
import zipfile
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# Configure the logging module
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Create a logger
logger = logging.getLogger('collect_logger')

# Getting environment variables
uco_ontology = os.environ['UCO_ONTO_PATH']
root_folder = os.environ['ROOT_FOLDER']
vol_path = os.environ['VOL_PATH']


def download_xml_zip():
    url = "https://cwe.mitre.org/data/downloads.html"
    save_path = os.path.join(vol_path, "CWE_Comprehensive_View_XML.zip")
    filename = os.path.join(vol_path, "tmp_cwe_dict.xml")
    final_filename = os.path.join(vol_path, "cwe_dict.xml")

    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for HTTP errors
        if response.status_code == 200:
            soup = BeautifulSoup(response.content, 'html.parser')
            # Find the table row containing "CWE Comprehensive View"
            rows = soup.find_all('tr')
            for row in rows:
                if "CWE Comprehensive View" in row.text:
                    # Find the link to the XML.zip file
                    xml_zip_link = row.find('a', string='XML.zip')['href']
                    xml_zip_url = urljoin(url, xml_zip_link)
                    # Download the XML.zip file
                    response_xml = requests.get(xml_zip_url)
                    if response_xml.status_code == 200:
                        # Write the downloaded ZIP file
                        with open(save_path, 'wb') as file:
                            file.write(response_xml.content)
                        LOGGER.info("XML.zip downloaded successfully.")
                        # Extract XML file from the ZIP archive
                        with zipfile.ZipFile(save_path, 'r') as zip_ref:
                            # Extract all contents to the current directory
                            zip_ref.extractall()
                        # Rename the XML file to cwe_dict.xml
                        extracted_files = os.listdir()
                        for file in extracted_files:
                            if file.endswith('.xml'):
                                os.rename(file, 'tmp_cwe_dict.xml')
                                LOGGER.info("cwe_dict.xml extracted and saved successfully.")
                                os.remove(save_path)
                                LOGGER.info("XML.zip deleted successfully.")
                                if sf.check_status("cwe") == 0:
                                    LOGGER.info("cwe_dict.xml exists...")
                                    tmp_file_hash = sf.calculate_file_hash(filename)
                                    final_file_hash = sf.calculate_file_hash(final_filename)
                                    if tmp_file_hash == final_file_hash:
                                        os.remove(filename)
                                        LOGGER.info("The new file is identical to the existing file. "
                                                    "Deleted tmp_cwe_dict.xml")
                                    else:
                                        os.remove(final_filename)
                                        os.rename(filename, "/vol/data/cwe_dict.xml")
                                        LOGGER.info(
                                            "The new file is different from the existing file. Replaced cwe_dict.xml "
                                            "with tmp_cwe_dict.xml.")
                                else:
                                    LOGGER.info("cwe_dict.xml DOES NOT exist...")
                                    LOGGER.info("Writing cwe_dict.xml")
                                    os.rename(filename, "/vol/data/cwe_dict.xml")
                                break
                    else:
                        LOGGER.info(f"Failed to download XML.zip from {xml_zip_url}. Status code:",
                                    response_xml.status_code)
            print("CWE Comprehensive View not found in the provided URL.")
        else:
            print(f"Failed to fetch {url}. Status code:", response.status_code)
    except Exception as e:
        print(f"An error occurred: {str(e)}")


def cwe_init():
    # Download xml_zip(), extract, and compare if it is an update or not.
    download_xml_zip()

    # Parse the XML file
    xml_file_path = os.path.join(vol_path, "cwe_dict.xml")

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
    cwes = {"cwes": []}

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

    with open("./data/cwe/cwes.json", "w+") as json_file:
        json.dump(cwes, json_file, indent=4)
        logger.info(">>>>>>>>>>>>>>>>>>>>created cwes.json")

    successfully_mapped = sf.call_mapper_update("cwe")
    if successfully_mapped:
        logger.info("Successfully mapped CWEs to RML mapper")
        sf.call_ontology_updater()

    logger.info("############################")
    logger.info("CWE Data extraction completed")
    logger.info("############################\n")
    # logger.info(f"Database Meta-Table: cves_meta")
    # logger.info(f"Total Records: {total_records}")
    # logger.info(f"Records Added: {records_added}")
    # logger.info(f"Database initialization finished: {init_finished}\n")
