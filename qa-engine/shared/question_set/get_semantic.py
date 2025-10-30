import json
import sys
import os

# Add the parent directory to the path to import config
sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..'))
from text2cypher.config import CYBERSECURITY_SEMANTICS


# Load JSON data
with open('nodes.json', 'r', encoding='utf-8') as file:
    json_data = json.load(file)

# Extract labels and relationships
all_labels = set()
all_relationships = set()

# Iterate through each item in the JSON array
for item in json_data:
    # Extract labels from each node
    for key, value in item.items():
        if key.startswith('node') and isinstance(value, dict):
            # Get labels if they exist
            if 'labels' in value:
                for label in value['labels']:
                    all_labels.add(label)
        
        # Extract relationship types
        if key == 'relationships' and isinstance(value, dict):
            for rel_key, rel_list in value.items():
                if isinstance(rel_list, list):
                    for rel in rel_list:
                        if isinstance(rel, dict) and 'type' in rel:
                            all_relationships.add(rel['type'])

# Convert sets to sorted lists for better readability
unique_labels = sorted([label for label in all_labels if label != "Resource"])
unique_relationships = sorted(list(all_relationships))

labels_and_relationships = unique_labels + unique_relationships

# Get semantic descriptions from config
with open('semantic_descriptions.txt', 'w', encoding='utf-8') as outfile:
    for item in labels_and_relationships:
        if item in CYBERSECURITY_SEMANTICS:
            description = CYBERSECURITY_SEMANTICS[item]
            outfile.write(f"{item}: {description}\n")

print(f"Semantic descriptions saved to semantic_descriptions.txt")

