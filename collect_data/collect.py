import requests
# function to collect data from cve.mitre.org
# and store it in a csv file
def collect_cve():
    # get the data from the website
    url = "https://cve.mitre.org/data/downloads/allitems.csv"
    response = requests.get(url)
    # save the data in a csv file
    with open("cve.csv", "wb") as file:
        file.write(response.content)
    # read the csv file and return the data
    with open("cve.csv", "rb") as file:
        data = file.read()
    return data

collect_cve()

