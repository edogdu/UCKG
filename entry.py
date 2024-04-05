import sys
import os
import logging
import time
from process import shared_functions as sf
from process import cwe_collection as cwe
from process import cve_collection as cve
from process import cpe_collection as cpe
sys.path.append("./process") 

uco_abs_path = os.environ['UCO_ONTO_PATH']
root_folder_abs_path = os.environ['ROOT_FOLDER']

# Configure the logging module
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Create a logger
logger = logging.getLogger('entry_logger')

# Waiting for neo4j to startup
logger.info("Waiting 2 minutes for neo4j to startup...")
time.sleep(120)


cwe_data_status = cwe.check_cwe_status()
if cwe_data_status == 3:
    logger.info("The CWE database has not been created yet, starting initialization now...\n")
    cwe.cwe_init()
elif cwe_data_status == 0:
    logger.info("The CWE initialization has not finished yet, continuing now...\n")
    cwe.cwe_init()

cve_data_status = cve.check_cve_status()

if cve_data_status == 3:
    logger.info("The CVE database has not been created yet, starting initialization now...\n")
    cve.cve_init()
elif cve_data_status == 0:
    logger.info("The CVE initialization has not finished yet, continuing now...\n")
    cve.cve_init()

cpe_data_status = cpe.check_cpe_status()

if (cpe_data_status == 3):
    logger.info("The CPE database does not yet exist")
    cpe.cpe_init()
elif (cpe_data_status == 1):
    logger.info("The CPE table exists and is up to date")
elif cpe_data_status == 0:
    logger.info("The CPE initialization has not finished yet, continuing now...\n")
    cpe.cpe_init()

logger.info("###############################################")
logger.info("All Data Sources Have Been Initialized!")
logger.info("###############################################")

# cve_data_status = collect.check_cwe_status()

# if cve_data_status == 3:
#     logger.info("The CWE database has not been created yet, starting initilization now...\n")
#     collect.cwe_init()
# elif cve_data_status == 0:
#     logger.info("The CWE initialization has not finished yet, continuining now...\n")
#     collect.cwe_init()