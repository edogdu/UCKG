import sys
import os
import logging
import time
from process import shared_functions as sf

sys.path.append("./data_collection")
from data_collection import cpe_collection as cpe, cve_collection as cve, cwe_collection as cwe, d3fend_collection as d3fend, attack_collection as attack, attack_mitigations_collection as mitigations, attack_campaigns_collection as campaigns, attack_groups_collection as groups, attack_software_collection as software, attack_tactics_collection as tactics , capec_collection as capec

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


d3fend_data_status = sf.check_status("d3fend")

if d3fend_data_status == 3:
    logger.info("The D3FEND database has not been created yet, starting initialization now...\n")
    d3fend.d3fend_init()
elif d3fend_data_status == 0:
    logger.info("The D3FEND initialization has not finished yet, continuing now...\n")
    d3fend.d3fend_init()

attack_data_status = sf.check_status("attack")

if attack_data_status == 3:
    logger.info("The ATT&CK database has not been created yet, starting initialization now...\n")
    attack.attack_init()
elif attack_data_status == 0:
    logger.info("The ATT&CK initialization has not finished yet, continuing now...\n")
    attack.attack_init()

mitigations_data_status = sf.check_status("mitigations")

if mitigations_data_status == 3:
    logger.info("The MITIGATIONS database has not been created yet, starting initialization now...\n")
    mitigations.mitigations_init()
elif mitigations_data_status == 0:
    logger.info("The MITIGATIONS initialization has not finished yet, continuing now...\n")
    mitigations.mitigations_init()

campaigns_data_status = sf.check_status("campaigns")

if campaigns_data_status == 3:
    logger.info("The campaigns database has not been created yet, starting initialization now...\n")
    campaigns.campaigns_init()
elif campaigns_data_status == 0:
    logger.info("The campaigns initialization has not finished yet, continuing now...\n")
    campaigns.campaigns_init()

groups_data_status = sf.check_status("groups")

if groups_data_status == 3:
    logger.info("The groups database has not been created yet, starting initialization now...\n")
    groups.groups_init()
elif groups_data_status == 0:
    logger.info("The groups initialization has not finished yet, continuing now...\n")
    groups.groups_init()

software_data_status = sf.check_status("software")

if software_data_status == 3:
    logger.info("The software database has not been created yet, starting initialization now...\n")
    software.software_init()
elif software_data_status == 0:
    logger.info("The software initialization has not finished yet, continuing now...\n")
    software.software_init()

tactics_data_status = sf.check_status("tactics")

if tactics_data_status == 3:
    logger.info("The tactics database has not been created yet, starting initialization now...\n")
    tactics.tactics_init()
elif tactics_data_status == 0:
    logger.info("The tactics initialization has not finished yet, continuing now...\n")
    tactics.tactics_init()


capec_data_status = sf.check_status("capec")

if capec_data_status == 3:
    logger.info("The CAPEC database has not been created yet, starting initialization now...\n")
    capec.capec_init()
elif capec_data_status == 0:
    logger.info("The CAPEC initialization has not finished yet, continuing now...\n")
    capec.capec_init()

# cpe_data_status = cpe.check_cpe_status()
#
# if (cpe_data_status == 3):
#     logger.info("The CPE database does not yet exist")
#     cpe.cpe_init()
# elif (cpe_data_status == 1):
#     logger.info("The CPE table exists and is up to date")
# elif cpe_data_status == 0:
#     logger.info("The CPE initialization has not finished yet, continuing now...\n")
#     cpe.cpe_init()

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