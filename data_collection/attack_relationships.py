import os
import requests
import json
import pandas as pd
from io import BytesIO
from bs4 import BeautifulSoup
from config import LOGGER
from process import shared_functions as sf

def download_relationships_json_file():
    url = 'https://attack.mitre.org/resources/attack-data-and-tools/'
    html = requests.get(url).raise_for_status() or requests.get(url).text
    soup = BeautifulSoup(html, 'html.parser')
    base_url = "https://attack.mitre.org"

    excel_paths = [
        "/docs/enterprise-attack-v16.1/enterprise-attack-v16.1.xlsx",
        "/docs/mobile-attack-v16.1/mobile-attack-v16.1.xlsx",
        "/docs/ics-attack-v16.1/ics-attack-v16.1.xlsx"
    ]

    # find the download URLs
    excel_files = {
      href.split('/')[-2]: base_url + href
      for a in soup.find_all('a', href=True)
      if (href := a['href']) in excel_paths
    }

    all_relationships = []
    for domain, file_url in excel_files.items():
        resp = requests.get(file_url)
        resp.raise_for_status()
        df = pd.read_excel(
            BytesIO(resp.content),
            sheet_name="relationships",
            usecols=["source ID", "target ID", "source type", "target type"]
        )
        # convert to strings and strip
        for col in df.columns:
            df[col] = df[col].astype(str).str.strip()
        # drop rows where source ID == 'nan'
        df = df[df["source ID"].str.lower() != "nan"]
        all_relationships.extend(df.to_dict(orient='records'))

    # ensure the folder exists **and** fix the filename typo
    out_path = "./data/attack/relationships_enriched.json"
    os.makedirs(os.path.dirname(out_path), exist_ok=True)

    LOGGER.info(f"Writing {len(all_relationships)} relationships to {out_path}")
    sf.write_file(out_path, all_relationships)
    LOGGER.info("Done.")
def relationships_init():
    LOGGER.info("############################")
    LOGGER.info("Beginning relationships Data Download")
    LOGGER.info("############################\n")

    # Download latest relationships data by converting the Excel files to JSON.
    download_relationships_json_file()