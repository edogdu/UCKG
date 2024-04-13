# File: collect.py
# Purpose: A Python script for collecting and updating data related to Common
# Vulnerabilities and Exposures (CVE), Common Weakness Enumeration (CWE), and
# D3FEND from respective sources.
#
# Functions:
#    cve_init(): Collects CVE data from the National Vulnerability Database and
#                updates the database.
#    cve_update(): Not implemented yet, placeholder for future functionality.
#    check_cve_status(): Determines the initialization status of the CVE table
#                        in the database.
#    check_cwe_status(): Determines the initialization status of the CWE table
#                        in the database.
#    cwe_init(): Extracts CWE data from an XML file, prepares it, and updates
#                the database.
#    get_cwe_id_list(): Extracts CWE IDs from an XML file and returns them as a
#                       list.
#    download_d3fend_json_file(): Downloads the latest D3FEND JSON file from
#                                 MITRE.
#    calculate_file_hash(file_path): Calculates the SHA-256 hash of a file.
#    handle_d3fend_file(): Handles the D3FEND JSON file based on its existence
#                          and content.
#    check_d3fend_status(): Checks the status of the D3FEND file.
#    d3fend_init(): Downloads and updates the D3FEND JSON file.
#    call_ontology_updater(): Calls the ontology updater script to update the
#                             ontology and database.
#    call_mapper_update(datasource): Calls the RML mapper with the appropriate
#                                    mapping file and data source.
#    format_datetime_string(datetime_string): Formats a datetime string.
#    __main__: Parses command-line arguments to determine the data source for
#             update and executes the corresponding function.
#
# Last Updated (by):

import sys
from ..config import LOGGER
import cve_collect
import cwe_collect
import capec_collect
import attack_collect
import d3fend_collect


if __name__ == "__main__":
    if len(sys.argv) > 1:
        data_source = sys.argv[1]
        if data_source == "cve_init":
            cve_collect.cve_init()
        elif data_source == "cve_update":
            cve_collect.cve_update()
        elif data_source == "d3fend":
            d3fend_collect.d3fend_init()
        elif data_source == "att&ck":
            attack_collect.attack_init()
        elif data_source == "capec":
            capec_collect.capec_init()
        elif data_source == "cwe":
            cwe_collect.cwe_init()
        else:
            LOGGER.info("ERROR: invalid data source. Please choose from one of the following: cve_init, cve_update")

    else:
        LOGGER.info("Please provide a data source to update(example:python collect.py cve).")
