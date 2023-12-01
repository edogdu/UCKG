import json

import os

cves = []
for file in os.listdir("../cvelistV5-main/cvelistV5-main/cves/1999/1xxx"):
#    print(file)
    with open("./cves/1999/1xxx/"+file, 'r') as cve:
        data = json.load(cve)
        cves.append(data)

cves_dict = {'cves': cves}

with open("cves.json", "w") as cves_file:
    json.dump(cves_dict, cves_file, indent=4)
    print('loaded data')

