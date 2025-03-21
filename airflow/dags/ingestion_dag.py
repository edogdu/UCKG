from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.utils.dates import days_ago
from datetime import timedelta
import logging
import requests
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
'''
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
def compare_counts_and_run():
    neo4j_count = count_cves_in_neo4j()
    nvd_count = count_cves_in_nvd()

    if nvd_count is None:
        logging.error("Failed to fetch NVD data. Skipping collection.")
        return

    if nvd_count > neo4j_count:
        logging.info("Running CVE collection - NVD has more CVEs.")
        # This assumes you have a command in your container:
        os.system("python /app/cve_collection.py")  # Replace with correct call
    else:
        logging.info("No need to run CVE collection. CVEs are up-to-date.")
'''
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

    sync_cves_task = PythonOperator(
        task_id='check_and_sync_cves',
        python_callable=count_cves_in_neo4j,
        retries=1,
    )

    sync_cves_task