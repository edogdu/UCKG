import time
import os
import pandas as pd
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC



# Load APTnotes and filter Box links
df = pd.read_csv("https://raw.githubusercontent.com/aptnotes/data/master/APTnotes.csv")
box_links = df[df["Link"].str.contains("box.com", na=False)]["Link"].tolist()

# Set download folder
download_dir = os.path.abspath("box_downloads")
os.makedirs(download_dir, exist_ok=True)

# Configure Chrome download behavior
chrome_options = Options()

chrome_options.add_experimental_option("prefs", {
    "download.prompt_for_download": False,
    "download.default_directory": download_dir,
    "plugins.always_open_pdf_externally": True
})

# Launch Chrome
driver = webdriver.Chrome(
    service=ChromeService(ChromeDriverManager().install()),
    options=chrome_options
)

# Visit each Box link and download
for i, link in enumerate(box_links):
    try:
        print(f"\n[{i+1}/{len(box_links)}] Visiting: {link}")
        driver.get(link)
        time.sleep(5)  # Let Box preview load

        # Find and click the download button
        wait = WebDriverWait(driver, 15)
        download_button = wait.until(EC.element_to_be_clickable((By.XPATH, '//button[.//span[text()="Download"]]')))
        download_button.click()

        print("Download clicked. Waiting for file...")

        time.sleep(10)  # Wait for download to finish

    except Exception as e:
        print(f"Failed for: {link}\nReason: {e}")

driver.quit()
print("\nAll done. Files downloaded to:", download_dir)