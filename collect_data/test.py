import os
import requests

def download_json_file():
    url = "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.json"

    # Send a GET request to fetch the JSON file
    response = requests.get(url)

    # Check if the request was successful
    if response.status_code == 200:
        # Save the JSON file in the specified directory
        folder_path = "../rml_mapper/d3fend"  # Path to the directory one level up and down to /rml_mapper/d3fend
        os.makedirs(folder_path, exist_ok=True)  # Ensure the directory exists, or create it if it doesn't

        # Extract the filename from the URL
        filename = os.path.join(folder_path, "d3fend.json")

        # Save the JSON file
        with open(filename, "wb") as f:
            f.write(response.content)

        print(f"File '{filename}' downloaded and saved successfully.")
    else:
        print("Failed to download the JSON file.")

download_json_file()

