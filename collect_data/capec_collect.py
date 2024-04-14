import os
import zipfile
import requests
from config import LOGGER
from bs4 import BeautifulSoup
from parse import parse_capec_file
from utilities import check_status, write_file, calculate_file_hash, call_mapper_update, call_ontology_updater


def download_capec_xml_file():
    # Define the URL of the page containing the table
    url = "https://capec.mitre.org/data/downloads.html"

    # Send a GET request to the URL
    response = requests.get(url)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the HTML content of the page
        soup = BeautifulSoup(response.content, 'html.parser')

        # Find all rows within the table
        rows = soup.find_all('tr')

        # Iterate through each row
        for row in rows:
            # Find the first cell (td) within the row
            first_cell = row.find('td', {'class': 'FirstCell'})

            # Check if the first cell contains the text "ATT&CK Related Patterns"
            if first_cell and "ATT&CK Related Patterns" in first_cell.text:
                # Find the link for the XML.zip file within this row
                link = row.find('a', text='XML.zip')

                # Check if the link is found
                if link:
                    # Get the URL of the XML.zip file
                    xml_zip_url = link['href']

                    # Extract the filename from the URL
                    filename = "capec.xml"

                    try:
                        # Download the ZIP file to the current directory
                        with open(filename, 'wb') as f:
                            f.write(requests.get("https://capec.mitre.org" + xml_zip_url).content)
                        print(f"File '{filename}' downloaded successfully.")

                        # Extract the contents of the ZIP file
                        with zipfile.ZipFile(filename, 'r') as zip_ref:
                            # Extract only the XML file
                            xml_filename = [f for f in zip_ref.namelist() if f.endswith('.xml')][0]
                            zip_ref.extract(xml_filename)
                            print(f"XML file '{xml_filename}' extracted successfully.")

                        # Remove the ZIP file after extraction
                        os.remove(filename)
                        print(f"ZIP file '{filename}' removed.")

                        break  # Exit the loop after processing the first match
                    except Exception as e:
                        print(f"Failed to process ZIP file '{filename}': {e}")

        else:
            print("Row containing 'ATT&CK Related Patterns' not found")
    else:
        print(f"Failed to access URL: {url}")


def capec_init():
    LOGGER.info("############################")
    LOGGER.info("Beginning CAPEC Data Download")
    LOGGER.info("############################\n")
    download_capec_xml_file()

    LOGGER.info("CAPEC Data Download Complete")
    LOGGER.info("Beginning CAPEC Parse")


    #successfully_mapped = call_mapper_update("capec")
    #if successfully_mapped:
    #    call_ontology_updater()