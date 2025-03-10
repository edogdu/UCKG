import pandas as pd
import json

df1 = pd.read_excel("../data/attack/enterprise-attack-v16.1.xlsx")
df2 = pd.read_excel("../data/attack/mobile-attack-v16.1.xlsx")
df3 = pd.read_excel("../data/attack/ics-attack-v16.1.xlsx")


json_data1 = df1.to_json(orient="records", indent=4)
json_data2 = df2.to_json(orient="records", indent=4)
json_data3 = df3.to_json(orient="records", indent=4)

with open("attack.json", "w") as json_file:
    json_file.write(json_data1)
    json_file.write(json_data2)
    json_file.write(json_data3)