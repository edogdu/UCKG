from prometheus_client import start_http_server, Counter
import logging
import time

logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('network_logger')

REQUESTS = Counter('uckg_requests_total', 'Total requests received')

def process_request():
    REQUESTS.inc()
    time.sleep(1)

def signal_network_start():
    logger.info("Scirpt launched successfully in network.py file")
    start_http_server(8000)  # Start metrics endpoint on port 8000
    logger.info("Server successfully started on port 8000")

if __name__ == "__main__":
    signal_network_start()
    while True:
        logger.info("Processing request...")
        process_request()
