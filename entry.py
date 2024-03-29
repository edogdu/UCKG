import sys
import os
import logging
import time
sys.path.append("./collect_data") 
from collect_data import collect

uco_abs_path = os.environ['UCO_ONTO_PATH']
root_folder_abs_path = os.environ['ROOT_FOLDER']

# Configure the logging module
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Create a logger
logger = logging.getLogger('entry_logger')

# Waiting for neo4j to startup
logger.info("Waiting 2 minutes for neo4j to startup...")
time.sleep(120)


cwe_data_status = collect.check_cwe_status()
if cwe_data_status == 3:
    logger.info("The CWE database has not been created yet, starting initialization now...\n")
    collect.cwe_init()
elif cwe_data_status == 0:
    logger.info("The CWE initialization has not finished yet, continuing now...\n")
    collect.cwe_init()

cve_data_status = collect.check_cve_status()

if cve_data_status == 3:
    logger.info("The CVE database has not been created yet, starting initialization now...\n")
    collect.cve_init()
elif cve_data_status == 0:
    logger.info("The CVE initialization has not finished yet, continuing now...\n")
    collect.cve_init()

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


