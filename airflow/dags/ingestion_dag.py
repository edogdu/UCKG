import sys
# Ensure the path to the repo is included for module imports
sys.path.append('/opt/airflow/repo/data_collection')
from cve_collection import cve_init

import logging
import requests
import sqlite3
import os
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago
from datetime import timedelta
from neo4j import GraphDatabase

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('ingestion_dag_logger')

# Configs for Neo4j & NVD
NEO4J_URI = "bolt://neo4j:7687"
NEO4J_USER = "neo4j"
NEO4J_PASSWORD = "abcd90909090"
NVD_API_CVE_COUNT_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"

# Task 1: Get total CVEs in Neo4j
def count_cves_in_neo4j():
    # Tell the user we are beginning the DAG ingestion checks
    logger.info("Checking how many CVEs are in Neo4j database...")
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
    with driver.session() as session:
        result = session.run("MATCH (n:UcoCVE) RETURN COUNT(n) AS total_cves")
        count = result.single()["total_cves"]
        logging.info(f"Total CVEs in Neo4j: {count}")
        return count

# Task 2: Get total CVEs from NVD API
def count_cves_in_nvd():
    response = requests.get(NVD_API_CVE_COUNT_URL)
    if response.status_code != 200:
        logging.warning(f"NVD API returned error code {response.status_code}")
        return None
    
    data = response.json()
    nvd_total = data.get('totalResults', 0)
    logging.info(f"Total CVEs in NVD: {nvd_total}")
    return nvd_total

# Task 3: Decide whether to run collection based on counts
# Working method: Access the database, set the init_finished int to 0 and call
# cve_init() to resume the ingestion process from the last recorded startIndex
# in the database.
def compare_counts_and_run():
    neo4j_count = count_cves_in_neo4j()
    nvd_count = count_cves_in_nvd()

    if nvd_count is None:
        logging.error("Failed to fetch NVD data. Skipping collection.")
        return

    if nvd_count > neo4j_count:
        logging.info("Running CVE collection - NVD has more CVEs.")
        # Gather the environment variables needed for the database connection
        # Define the relative path to the data file
        logger.info("Setting up database connection...")
        vol_path = os.environ['VOL_PATH']
        cve_db_file = os.path.join(vol_path, 'cve_database.db')
        with sqlite3.connect(cve_db_file) as conn:
            # Create database cursor
            cursor = conn.cursor()
            cursor.execute("UPDATE cve_meta SET init_finished=0 WHERE id=12345")
            conn.commit()
            logger.info("Database connection established and init_finished set to 0.")
            logger.info("Running cve_init() to resume CVE ingestion...")
            cve_init(DEBUG=False)
    else:
        logging.info("No need to run CVE collection. CVEs are up-to-date.")

# Airflow DAG definition
default_args = {
    'owner': 'uckg_user',
    'depends_on_past': False,
    'email_on_failure': True,
    'retries': 1,
    'retry_delay': timedelta(minutes=10),
}

with DAG(
    'daily_cve_sync',
    default_args=default_args,
    description='Check and sync CVEs with NVD and Neo4j',
    schedule_interval='@daily',
    start_date=days_ago(1),
    catchup=False,
    tags=['uckg', 'daily'],
) as dag:

    check_and_sync_cves = PythonOperator(
        task_id='check_and_sync_cves',
        python_callable= compare_counts_and_run,
        retries=1,
    )
    nvd_cve_count = PythonOperator(
        task_id='retrieve_nvd_cve_count',
        python_callable= count_cves_in_nvd,
        retries=1,
    )
    sync_cves_task = PythonOperator(
        task_id='count_neo4j_cve_total',
        python_callable=count_cves_in_neo4j,
        retries=1,
    )

    sync_cves_task