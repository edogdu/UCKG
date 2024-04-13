# File: entry.py
# Purpose: A Python script for initializing data sources (CWE, CVE, D3FEND) for
# a system, waiting for Neo4j to start up, and then executing initialization
# routines for each data source.
#
# Functions:
#     __main__: Executes the main logic of the script, including initializing
#     data sources (CWE, CVE, D3FEND) using the collect module, waiting for
#     Neo4j to start up, checking the status of each data source, and executing
#     initialization routines accordingly.
#
# Last Updated (by):
import os
import time
from collect_data.attack_collect import attack_init
from collect_data.capec_collect import capec_init
from collect_data.cve_collect import cve_init
from collect_data.d3fend_collect import d3fend_init
from config import LOGGER, root_file_path, ontology_file_path
from utilities import check_status
from collect_data.cwe_collect import cwe_init

# Waiting for neo4j to startup
LOGGER.info("Waiting 2 minutes for neo4j to startup...")
time.sleep(120)

cve_data_status = check_status("cve")

if cve_data_status == 3:
    LOGGER.info("The CVE database has not been created yet, starting initialization now...\n")
    cve_init()
elif cve_data_status == 0:
    LOGGER.info("The CVE initialization has not finished yet, continuing now...\n")
    cve_init()

d3fend_data_status = check_status("d3fend")

if d3fend_data_status == 3:
    LOGGER.info("The D3FEND database has not been created yet, starting initialization now...\n")
    d3fend_init()
elif d3fend_data_status == 0:
    LOGGER.info("The D3FEND initialization has not finished yet, continuing now...\n")
    d3fend_init()

attack_data_status = check_status("attack")

if attack_data_status == 3:
    LOGGER.info("The ATT&CK database has not been created yet, starting initialization now...\n")
    attack_init()
elif attack_data_status == 0:
    LOGGER.info("The ATT&CK initialization has not finished yet, continuing now...\n")
    attack_init()

capec_data_status = check_status("capec")

if capec_data_status == 3:
    LOGGER.info("The CAPEC database has not been created yet, starting initialization now...\n")
    capec_init()
elif attack_data_status == 0:
    LOGGER.info("The CAPEC initialization has not finished yet, continuing now...\n")
    capec_init()

# cve_data_status = collect.check_status("cwe")

# if cve_data_status == 3:
#     LOGGER.info("The CWE database has not been created yet, starting initialization now...\n")
#     cwe_init()
# elif cve_data_status == 0:
#     LOGGER.info("The CWE initialization has not finished yet, continuing now...\n")
#     cwe_init()

LOGGER.info("###############################################")
LOGGER.info("All Data Sources Have Been Initialized!")
LOGGER.info("###############################################")


