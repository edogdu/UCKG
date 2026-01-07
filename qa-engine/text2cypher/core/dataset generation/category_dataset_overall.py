import re
import pandas as pd
import ast
from typing import Dict, Any

class SchemaValidator:
    def __init__(self, schema_file: str):
        """
        Loads schema from schema_cache.txt and prepares node labels, properties, and relationships.
        """
        self.schema = self._load_schema(schema_file)
        self.labels = set(self.schema['nodes'].keys())
        self.relationships = self.schema['relationships']
        self.properties = set()
        for props in self.schema['nodes'].values():
            self.properties.update(props.keys())

    def _load_schema(self, schema_file: str) -> Dict[str, Any]:
        """
        Parses the schema_cache.txt file to extract nodes, properties, and relationships.
        Expected schema format:
        NodeName {prop1: type1, prop2: type2, ...}
        (NodeA)-[:REL_TYPE]->(NodeB)
        """
        schema = {"nodes": {}, "relationships": set()}
        with open(schema_file, 'r', encoding='utf-8') as f:
            content = f.read()

        # Match nodes like: NodeName {prop1: type1, prop2: type2}
        node_pattern = re.compile(r'(\w+)\s*{\s*(.*?)\s*}', re.DOTALL)
        # Match relationships like: (NodeA)-[:REL_TYPE]->(NodeB)
        rel_pattern = re.compile(r'\(:(\w+)\)\s*-\[:(\w+)\]->\s*\(:(\w+)\)')

        for match in node_pattern.finditer(content):
            node_name, props_str = match.groups()
            props = {p.split(':')[0].strip(): p.split(':')[1].strip() 
                     for p in props_str.split(',') if ':' in p}
            schema["nodes"][node_name] = props

        for match in rel_pattern.finditer(content):
            _, rel_type, _ = match.groups()
            schema["relationships"].add(rel_type)

        return schema

    def check_csv_expectations(self, csv_file: str):
        # Read CSV safely
        df = pd.read_csv(csv_file, quotechar='"', doublequote=True)
        results = []

        for idx, row in df.iterrows():
            category = row.get('Category', 'Unknown')
            
            # Fix the double quotes in list strings before evaluating
            expected_labels = ast.literal_eval(row.get('ExpectedNodeLabels', '[]').replace('""', '"'))
            expected_rels = ast.literal_eval(row.get('ExpectedRelationshipTypes', '[]').replace('""', '"'))
            expected_props = ast.literal_eval(row.get('ExpectedProperties', '[]').replace('""', '"'))

            label_check = all(label in self.labels for label in expected_labels)
            rel_check = all(rel in self.relationships for rel in expected_rels)
            prop_check = all(prop in self.properties for prop in expected_props)

            results.append({
                'Category': category,
                'LabelsValid': label_check,
                'RelationshipsValid': rel_check,
                'PropertiesValid': prop_check,
                'AllValid': label_check and rel_check and prop_check
            })
        
        return pd.DataFrame(results)


    def check_csv_coverage(self, csv_file: str):
        # Read CSV safely
        df = pd.read_csv(csv_file, quotechar='"', doublequote=True)

        results = []

        # Group by Category
        grouped = df.groupby('Category')

        for category, group in grouped:
            # Combine all expected labels, relationships, properties for this category
            all_labels = set()
            all_rels = set()
            all_props = set()

            for idx, row in group.iterrows():
                expected_labels = ast.literal_eval(row.get('ExpectedNodeLabels', '[]').replace('""', '"'))
                expected_rels = ast.literal_eval(row.get('ExpectedRelationshipTypes', '[]').replace('""', '"'))
                expected_props = ast.literal_eval(row.get('ExpectedProperties', '[]').replace('""', '"'))

                all_labels.update(expected_labels)
                all_rels.update(expected_rels)
                all_props.update(expected_props)

            # Compare with schema
            labels_missing = self.labels - all_labels
            rels_missing = self.relationships - all_rels
            props_missing = self.properties - all_props

            results.append({
                'Category': category,
                'LabelsCovered': list(all_labels & self.labels),
                'LabelsMissing': list(labels_missing),
                'RelationshipsCovered': list(all_rels & self.relationships),
                'RelationshipsMissing': list(rels_missing),
                'PropertiesCovered': list(all_props & self.properties),
                'PropertiesMissing': list(props_missing),
                'AllLabelsCovered': len(labels_missing) == 0,
                'AllRelsCovered': len(rels_missing) == 0,
                'AllPropsCovered': len(props_missing) == 0,
                'AllCovered': len(labels_missing) == 0 and len(rels_missing) == 0 and len(props_missing) == 0
            })

        return pd.DataFrame(results)


    def check_csv_coverage_detailed(self, csv_file: str, txt_output_path: str):
        # Read CSV safely
        df = pd.read_csv(csv_file, quotechar='"', doublequote=True)
        results = []

        grouped = df.groupby('Category')

        with open(txt_output_path, 'w', encoding='utf-8') as txt_file:
            for category, group in grouped:
                all_labels = set()
                all_rels = set()
                all_props_by_label = {}  # {label: set(props)}

                for idx, row in group.iterrows():
                    expected_labels = ast.literal_eval(row.get('ExpectedNodeLabels', '[]').replace('""', '"'))
                    expected_rels = ast.literal_eval(row.get('ExpectedRelationshipTypes', '[]').replace('""', '"'))
                    expected_props = ast.literal_eval(row.get('ExpectedProperties', '[]').replace('""', '"'))

                    all_labels.update(expected_labels)
                    all_rels.update(expected_rels)

                    # Assign expected properties to the correct node (simple approach: assign to all labels in this query)
                    for label in expected_labels:
                        if label not in all_props_by_label:
                            all_props_by_label[label] = set()
                        all_props_by_label[label].update(expected_props)

                # Compare with schema
                labels_missing = self.labels - all_labels
                rels_missing = self.relationships - all_rels

                props_missing_by_label = {}
                for label, schema_props in self.schema['nodes'].items():
                    expected_props = all_props_by_label.get(label, set())
                    missing = set(schema_props.keys()) - expected_props
                    if missing:
                        props_missing_by_label[label] = missing

                # Write human-readable TXT
                txt_file.write(f"Category: {category}\n")
                txt_file.write(f"  Missing Labels: {sorted(labels_missing)}\n")
                txt_file.write(f"  Missing Relationships: {sorted(rels_missing)}\n")
                txt_file.write(f"  Missing Properties per Label:\n")
                if props_missing_by_label:
                    for label, missing_props in props_missing_by_label.items():
                        txt_file.write(f"    {label}: {sorted(missing_props)}\n")
                else:
                    txt_file.write("    None\n")
                txt_file.write("\n")

                results.append({
                    'Category': category,
                    'LabelsMissing': list(labels_missing),
                    'RelationshipsMissing': list(rels_missing),
                    'PropertiesMissingPerLabel': props_missing_by_label,
                    'AllCovered': len(labels_missing) == 0 and len(rels_missing) == 0 and len(props_missing_by_label) == 0
                })

        return pd.DataFrame(results)



if __name__ == "__main__":
    schema_file = r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\Data Generation\Generate Code\schema_cache.txt'
    csv_file = r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\Data Generation\Generate Code\Cypher Output Check\failed_queries.csv'
    txt_output_path = r'C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\Data Generation\Dataset Generation Process\technical dataset\category check\category_coverage_ADJUST_report.txt'

    validator = SchemaValidator(schema_file)

    # Get coverage summary (per category)
    coverage_results = validator.check_csv_coverage(csv_file)

    # Get detailed coverage and write human-readable TXT report
    coverage_results_detailed = validator.check_csv_coverage_detailed(csv_file, txt_output_path)

    # Save CSV outputs
    coverage_results.to_csv(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\Data Generation\Dataset Generation Process\technical dataset\category check\category_coverage_ADJUST_results.csv", index=False)
    coverage_results_detailed.to_csv(r"C:\Users\User\Downloads\UCKG\qa-engine\text2cypher\Data Generation\Dataset Generation Process\technical dataset\category check\category_coverage_results_ADJUST_detailed.csv", index=False)

    print("Coverage analysis completed. CSV and TXT reports are saved.")
