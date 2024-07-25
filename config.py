import os
import logging


# # Getting environment variables
# os.environ['ROOT_FOLDER'] = "/app"
# os.environ['VOL_PATH'] = "/vol/data"
# os.environ['UCO_ONTO_PATH'] = "/app/uco2.ttl"
#
# root_file_path = os.environ['ROOT_FOLDER']
# vol_file_path = os.environ['VOL_PATH']
# ontology_file_path = os.environ['UCO_ONTO_PATH']

# Configure the logging module
logging.basicConfig(level=logging.INFO , format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

# Create a logger
LOGGER = logging.getLogger('collect_logger')