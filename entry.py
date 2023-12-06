import sys
import logging
sys.path.append("./collect_data") 
from collect_data import collect
# Configure the logging module
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Create a logger
logger = logging.getLogger('entry_logger')

cve_data_status = collect.check_cve_status()

if cve_data_status == 3:
    logger.info("The CVE database has not been created yet, starting initilization now...\n")
    collect.cve_init()
elif cve_data_status == 0:
    logger.info("The CVE initialization has not finished yet, continuining now...\n")
    collect.cve_init()


