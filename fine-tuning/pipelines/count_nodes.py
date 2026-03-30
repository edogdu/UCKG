from sft_engine.models.storage.graph.kuzu_storage import KuzuStorage
import json

k = KuzuStorage('cache', 'graph')
nodes = k.get_all_nodes()
print(f"Total Nodes: {len(nodes)}")
print("-" * 60)

# Inspect the first node fully
if nodes:
    n_id, data = nodes[0]
    print(f"ID: {n_id}")
    print("Full Data Content:")
    print(json.dumps(data, indent=2, ensure_ascii=False))
else:
    print("No nodes found.")
print("-" * 60)
