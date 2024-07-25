import os
import zipfile
import requests
from config import LOGGER
from bs4 import BeautifulSoup
from parse import parse_capec_file
from process import shared_functions as sf
# from utilities import check_status, write_file, calculate_file_hash, call_mapper_update, call_ontology_updater


def download_capec_xml_file():
    # Define the URL of the page containing the table
    url = "https://capec.mitre.org/data/downloads.html"

    xml_filename = ""

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
                        LOGGER.info(f"File '{filename}' downloaded successfully.")

                        # Extract the contents of the ZIP file
                        with zipfile.ZipFile(filename, 'r') as zip_ref:
                            # Extract only the XML file
                            xml_filename = [f for f in zip_ref.namelist() if f.endswith('.xml')][0]
                            zip_ref.extract(xml_filename)
                            LOGGER.info(f"XML file '{xml_filename}' extracted successfully.")

                        # Remove the ZIP file after extraction
                        os.remove(filename)
                        LOGGER.info(f"ZIP file '{filename}' removed.")
                        LOGGER.info(f"FILENAME: {filename}")

                        break  # Exit the loop after processing the first match
                    except Exception as e:
                        LOGGER.info(f"Failed to process ZIP file '{filename}': {e}")

        else:
            LOGGER.info("Row containing 'ATT&CK Related Patterns' not found")
    else:
        LOGGER.info(f"Failed to access URL: {url}")

    # # Open the XML file and read its contents
    # with open(xml_filename, "r") as file:
    #     xml_content = file.read()

    # Call the parse function and pass the XML content
    capec_json_content = parse_capec_file(xml_filename)
    # Also write capec to data/capec folder
    sf.write_file("./data/capec/capec.json", capec_json_content)
    if sf.check_status("capec") == 0:
        filename = os.path.join(os.environ['VOL_PATH'], "tmp_capec.json")
        final_filename = os.path.join(os.environ['VOL_PATH'], "capec.json")
        LOGGER.info("Writing tmp_capec.json")
        sf.write_file(filename, capec_json_content)
        tmp_file_hash = sf.calculate_file_hash(filename)
        final_file_hash = sf.calculate_file_hash(final_filename)

        # Compare hashes
        if tmp_file_hash == final_file_hash:
            # Hashes are the same, delete tmp file
            os.remove(filename)
            LOGGER.info("The new file is identical to the existing file. Deleted tmp_capec.json.")
        else:
            # Hashes are different, replace existing file
            os.remove(final_filename)
            os.rename(filename, "/vol/data/capec.json")
            LOGGER.info("The new file is different from the existing file. Replaced capec.json with "
                        "tmp_capec.json.")
    elif sf.check_status("capec") == 3:
        LOGGER.info("capec.json DOES NOT exist...")
        LOGGER.info("Writing capec.json")
        final_filename = os.path.join(os.environ['VOL_PATH'], "capec.json")
        sf.write_file(final_filename, capec_json_content)

        LOGGER.info(f"File '{final_filename}' downloaded and saved successfully.")
    else:
        LOGGER.info("Failed to download the CAPEC JSON file.")



def capec_init():
    LOGGER.info("############################")
    LOGGER.info("Beginning CAPEC Data Download")
    LOGGER.info("############################\n")
    download_capec_xml_file()

    LOGGER.info("CAPEC Data Download Complete")
    LOGGER.info("Beginning CAPEC Parse")

    successfully_mapped = sf.call_mapper_update("capec")

    if successfully_mapped:
        LOGGER.info("CAPEC Data Successfully Mapped")
        LOGGER.info("Beginning CAPEC Ontology Updater")
        sf.call_ontology_updater()
        LOGGER.info("CAPEC Ontology Updater Complete")
        LOGGER.info("############################\n")
    else:
        LOGGER.info("############################")
        LOGGER.info("CAPEC Ontology Update Failed")
        LOGGER.info("############################\n")
