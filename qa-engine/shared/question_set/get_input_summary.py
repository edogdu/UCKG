import json
from subgraph_description import NODE_TYPES, NODE_PROPERTY_TYPES, RELATIONSHIPS_TYPES


def get_node_type(node_data):
    """Extract the primary node type from labels (excluding 'Resource')."""
    labels = node_data.get('labels', [])
    for label in labels:
        if label != 'Resource':
            return label
    return None


def format_node_schema(node_types_used):
    """Generate the schema section for node types."""
    schema_lines = []
    for node_type in sorted(node_types_used):
        if node_type in NODE_TYPES:
            properties = NODE_TYPES[node_type]
            prop_str = ', '.join([f'"{key}": "{value}"' for key, value in properties.items()])
            schema_lines.append(f'"{node_type}": {{ {prop_str} }}')
    return schema_lines


def format_node_properties(node_types_used):
    """Generate the property description section for node types."""
    property_lines = []
    for node_type in sorted(node_types_used):
        if node_type in NODE_PROPERTY_TYPES:
            property_lines.append(f'"{node_type}": {{')
            properties = NODE_PROPERTY_TYPES[node_type]
            for key, template in properties.items():
                property_lines.append(f'    "{key}": "{template}"')
            property_lines.append('}')
    return property_lines


def format_relationships(relationships_used):
    """Generate the relationship section."""
    relationship_lines = []
    for rel_type in sorted(relationships_used):
        if rel_type in RELATIONSHIPS_TYPES:
            rel_info = RELATIONSHIPS_TYPES[rel_type]
            # rel_info is a set with pattern and description
            rel_data = list(rel_info)
            # Find which one is the pattern and which is the description
            rel_pattern = None
            rel_description = None
            for item in rel_data:
                # Pattern contains relationship syntax like -[:REL_NAME]->
                if '-[' in item and ']->' in item and '(:' in item:
                    rel_pattern = item
                else:
                    rel_description = item
            
            if rel_pattern and rel_description:
                relationship_lines.append(f'{rel_pattern}')
                relationship_lines.append(f'{rel_type}: {rel_description}')
    return relationship_lines


def get_node_identifier(node_data):
    """Get a human-readable identifier for a node."""
    node_type = get_node_type(node_data)
    
    # Try to find a name/label property
    if 'label' in node_data:
        return node_data['label']
    if 'ucoexCAPEC_name' in node_data:
        return node_data['ucoexCAPEC_name']
    if 'ucocweName' in node_data:
        return node_data['ucocweName']
    if 'ucoexNAME' in node_data:
        return node_data['ucoexNAME']
    if 'ucoexMITRED3FEND_LABEL' in node_data:
        return node_data['ucoexMITRED3FEND_LABEL']
    if 'cpeName' in node_data:
        return node_data['cpeName']
    
    return None


def generate_node_description(node_id, node_data):
    """Generate natural language description for a node."""
    node_type = get_node_type(node_data)
    if not node_type or node_type not in NODE_PROPERTY_TYPES:
        return ""
    
    property_templates = NODE_PROPERTY_TYPES[node_type]
    description_parts = []
    
    # Start with node ID
    description_parts.append(node_id)
    
    # Check if node has a name or label property to put first
    name_label_properties = ['label', 'ucoexCAPEC_name', 'ucocweName', 'ucoexNAME', 
                             'ucoexMITRED3FEND_LABEL', 'cpeName']
    node_label_value = None
    node_label_key = None
    
    for prop in name_label_properties:
        if prop in node_data and node_data[prop]:
            node_label_value = node_data[prop]
            node_label_key = prop
            break
    
    # If node has a label/name, add it right after node_id
    if node_label_value:
        description_parts.append(f", labeled as {node_label_value},")
    
    # Now add the type description and other properties
    for prop_key, template in property_templates.items():
        if prop_key == node_type:
            # This is the node type description
            description_parts.append(template)
        elif prop_key == node_label_key:
            # Skip the label/name property since we already added it at the beginning
            continue
        elif prop_key in node_data:
            value = node_data[prop_key]
            if value is not None and value != "" and value != "unknown":
                # Replace <value> with actual value
                formatted = template.replace('<value>', str(value))
                description_parts.append(formatted)
    
    # Join all parts
    description = ''.join(description_parts)
    # Clean up any double spaces or commas
    description = description.replace('  ', ' ').strip()
    # Ensure it ends with a period
    if description and not description.endswith('.'):
        description += '.'
    
    return description


def generate_relationship_description(source_id, source_node, rel_type, target_id, target_node):
    """Generate natural language description for a relationship."""
    source_identifier = get_node_identifier(source_node)
    source_type = get_node_type(source_node)
    target_identifier = get_node_identifier(target_node)
    target_type = get_node_type(target_node)
    
    # Get relationship description template
    if rel_type not in RELATIONSHIPS_TYPES:
        return ""
    
    rel_info = RELATIONSHIPS_TYPES[rel_type]
    rel_data = list(rel_info)
    
    # Find the description (not the pattern)
    rel_description = None
    for item in rel_data:
        # Description does not contain relationship syntax
        if not ('-[' in item and ']->' in item and '(:' in item):
            rel_description = item
            break
    
    if not rel_description:
        return ""
    
    # Replace <s> and <o> with actual node identifiers
    description = f"{source_id}"
    if source_identifier:
        description += f" ({source_type} ({source_identifier}))"
    else:
        description += f" ({source_type})"
    
    # Replace placeholders in relationship description
    rel_text = rel_description.replace('<s>', '').replace('<o>', '').strip()
    # Remove the trailing period from rel_text if present
    if rel_text.endswith('.'):
        rel_text = rel_text[:-1]
    # Strip again to remove any trailing spaces
    rel_text = rel_text.strip()
    description += f" {rel_text} {target_id}"
    if target_identifier:
        description += f" ({target_type} ({target_identifier}))"
    else:
        description += f" ({target_type})"
    
    description += "."
    
    return description


def process_nodes_json(input_file, output_file):
    """Main processing function."""
    # Read nodes.json
    with open(input_file, 'r', encoding='utf-8') as f:
        data = json.load(f)
    
    output_lines = []
    
    # Process each subgraph in the JSON
    for subgraph in data:
        node_types_used = set()
        relationships_used = set()
        nodes_dict = {}
        
        # Collect all nodes and their types
        for key, value in subgraph.items():
            if key.startswith('node'):
                node_type = get_node_type(value)
                if node_type:
                    node_types_used.add(node_type)
                    nodes_dict[key] = value
            elif key == 'relationships':
                # Collect relationship types
                # Handle both dict format {"node1_node2": [...]} and list format [{"type": "..."}]
                if isinstance(value, dict):
                    # Dictionary format: {"node1_node2": [...], "node2_node3": [...]}
                    for rel_key, rel_list in value.items():
                        for rel in rel_list:
                            rel_type = rel.get('type')
                            if rel_type:
                                relationships_used.add(rel_type)
                elif isinstance(value, list):
                    # List format: [{"type": "..."}, ...]
                    for rel in value:
                        rel_type = rel.get('type')
                        if rel_type:
                            relationships_used.add(rel_type)
        
        # Generate schema section
        output_lines.extend(format_node_schema(node_types_used))
        output_lines.append("")
        
        # Generate property descriptions section
        output_lines.extend(format_node_properties(node_types_used))
        output_lines.append("")
        
        # Generate relationship patterns section
        output_lines.extend(format_relationships(relationships_used))
        output_lines.append("")
        output_lines.append("")
        
        # Generate interleaved natural language descriptions
        # We want to alternate between node descriptions and relationships
        # Format: node1 description, relationship1 (node1->node2), node2 description, relationship2 (node2->node3), node3 description
        
        # First, collect all node IDs and their descriptions
        node_descriptions = {}
        for node_id in nodes_dict.keys():
            node_data = nodes_dict[node_id]
            description = generate_node_description(node_id, node_data)
            if description:
                node_descriptions[node_id] = description
        
        # Collect relationships with their source and target
        relationships_list = []
        if 'relationships' in subgraph:
            relationships_data = subgraph['relationships']
            
            if isinstance(relationships_data, dict):
                # Dictionary format: {"node1_node2": [...], "node2_node3": [...]}
                for rel_key, rel_list in relationships_data.items():
                    parts = rel_key.split('_')
                    if len(parts) == 2:
                        source_id = parts[0]
                        target_id = parts[1]
                        source_node = nodes_dict.get(source_id)
                        target_node = nodes_dict.get(target_id)
                        
                        for rel in rel_list:
                            rel_type = rel.get('type')
                            if source_node and target_node and rel_type:
                                description = generate_relationship_description(
                                    source_id, source_node, rel_type, target_id, target_node
                                )
                                if description:
                                    relationships_list.append({
                                        'source': source_id,
                                        'target': target_id,
                                        'description': description
                                    })
            elif isinstance(relationships_data, list):
                # List format: [{"type": "..."}, ...]
                # Infer node connections based on node order (node1 -> node2, node2 -> node3, etc.)
                node_ids = sorted([k for k in nodes_dict.keys() if k.startswith('node')])
                
                for i, rel in enumerate(relationships_data):
                    if i < len(node_ids) - 1:
                        source_id = node_ids[i]
                        target_id = node_ids[i + 1]
                        source_node = nodes_dict.get(source_id)
                        target_node = nodes_dict.get(target_id)
                        rel_type = rel.get('type')
                        
                        if source_node and target_node and rel_type:
                            description = generate_relationship_description(
                                source_id, source_node, rel_type, target_id, target_node
                            )
                            if description:
                                relationships_list.append({
                                    'source': source_id,
                                    'target': target_id,
                                    'description': description
                                })
        
        # Now interleave: output nodes and relationships in order
        # Follow the pattern in example: node1, rel(node1->node2), node2, rel(node2->node3), node3
        output_nodes = set()
        
        for rel in relationships_list:
            # Output source node if not yet output
            if rel['source'] not in output_nodes and rel['source'] in node_descriptions:
                output_lines.append(node_descriptions[rel['source']])
                output_nodes.add(rel['source'])
            
            # Output relationship
            output_lines.append(rel['description'])
            
            # Output target node if not yet output
            if rel['target'] not in output_nodes and rel['target'] in node_descriptions:
                output_lines.append(node_descriptions[rel['target']])
                output_nodes.add(rel['target'])
        
        # Output any remaining nodes that weren't in relationships
        for node_id in sorted(nodes_dict.keys()):
            if node_id not in output_nodes and node_id in node_descriptions:
                output_lines.append(node_descriptions[node_id])
                output_nodes.add(node_id)
    
    # Write to output file
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(output_lines))
    
    print(f"Summary generated successfully in {output_file}")


if __name__ == "__main__":
    input_file = "nodes.json"
    output_file = "subgraph_summary.txt"
    process_nodes_json(input_file, output_file)

