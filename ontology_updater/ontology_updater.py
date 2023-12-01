from owlready2 import *
from rdflib import *
import os
import sys
# Create a graph to convert uco to owl xml format
def update_ontology(ontology_folder):
    g = Graph()
    g.parse("uco2.ttl", format="turtle")
    write_path = os.path.join("./"+ontology_folder +  "/uco.owl")
    g.serialize(write_path, format="xml")
    print("\nCreated file uco.owl\n")

    # Load the ontolgy
    onto = get_ontology(write_path).load()

    # Switch back to to rdflib so I can add the instances
    graph_2 = onto.world.as_rdflib_graph()

    with onto:
        graph_2.parse("../rml_mapper/" + ontology_folder +"/out.ttl")
        write_path = os.path.join("./" + ontology_folder + "/uco_with_instances.owl")
        graph_2.serialize(write_path, format="xml")
        print("\nCreated file uco_with_instances.owl\n")

    # Switch back to owlready2 so I can use the sync_reasoner
    onto_final = get_ontology(write_path).load()
    sync_reasoner()

    # Finally switch back to rdflib so I can the ontology and instances as turtle format
    graph_3 = onto_final.world.as_rdflib_graph()

    with onto_final:
        write_path = os.path.join("./" + ontology_folder + "/uco_with_instances.ttl")
        graph_3.serialize(write_path, format="turtle")
        print("\nCreated file uco_with_instances.ttl\n")

    files_to_delete = ["uco.owl", "uco_with_instances.owl"]

    for file in files_to_delete:
        to_delete = os.path.join("./" + ontology_folder + "/", file)
        if os.path.exists(to_delete):
            os.remove(to_delete)
            print(f"\nFile '{to_delete}' has been deleted\n")
        else:
            print(f"\nFile '{to_delete}' does not exist\n")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        ontology_folder = sys.argv[1]
        update_ontology(ontology_folder)
    else:
        print("Please provide a ontology folder(example:python ontology_updater cve).")