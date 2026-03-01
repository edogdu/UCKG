import kuzu
import networkx as nx
import matplotlib.pyplot as plt
import os
import json

DB_PATH = "cache/graph_kuzu"

def visualize_graph():
    if not os.path.exists(DB_PATH):
        print(f"Error: Database path '{DB_PATH}' does not exist. Run from fine-tuning folder.")
        return

    print(f"Connecting to KuzuDB at {DB_PATH}...")
    try:
        db = kuzu.Database(DB_PATH)
        conn = kuzu.Connection(db)
        
        query = "MATCH (a:Entity)-[r:Relation]->(b:Entity) RETURN a.id, b.id, a.data, b.data LIMIT 150"
        result = conn.execute(query)
        
        G = nx.DiGraph()
        
        while result.has_next():
            row = result.get_next()
            src_id = row[0]
            tgt_id = row[1]
            
            try:
                src_type = json.loads(row[2]).get("entity_type", "Unknown")
                tgt_type = json.loads(row[3]).get("entity_type", "Unknown")
            except:
                src_type = "Unknown"
                tgt_type = "Unknown"
                
            G.add_node(src_id, type=src_type)
            G.add_node(tgt_id, type=tgt_type)
            G.add_edge(src_id, tgt_id)

        print(f"Extracted {G.number_of_nodes()} nodes and {G.number_of_edges()} edges for visualization.")

        color_map = []
        for node, data in G.nodes(data=True):
            ntype = data.get("type", "")
            if "CAPEC" in ntype:
                color_map.append("red")
            elif "ATTACK" in ntype:
                color_map.append("orange")
            elif "MITIGATION" in ntype:
                color_map.append("green")
            else:
                color_map.append("gray")

        plt.figure(figsize=(14, 10))
        plt.title("KuzuDB Subgraph Sample (CAPEC -> ATT&CK <- MITIGATION)", fontsize=16)
        
        pos = nx.spring_layout(G, k=0.5, iterations=50)
        
        nx.draw(G, pos, node_color=color_map, with_labels=True, 
                node_size=800, font_size=8, font_weight="bold", 
                edge_color="gray", arrows=True)
        
        from matplotlib.lines import Line2D
        legend_elements = [
            Line2D([0], [0], marker="o", color="w", markerfacecolor="red", markersize=10, label="CAPEC (Attack)"),
            Line2D([0], [0], marker="o", color="w", markerfacecolor="orange", markersize=10, label="ATT&CK (Category)"),
            Line2D([0], [0], marker="o", color="w", markerfacecolor="green", markersize=10, label="MITIGATION (Defense)")
        ]
        plt.legend(handles=legend_elements, loc="upper right")

        output_file = "kuzu_graph_visualization.png"
        plt.savefig(output_file, dpi=300, bbox_inches="tight")
        print(f"Success! Visualization saved to: {output_file}")
        
    except Exception as e:
        print(f"Error generating visualization: {e}")

if __name__ == "__main__":
    visualize_graph()
