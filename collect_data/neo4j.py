# File: neo4j.py
# Purpose: A Python script for parsing a Turtle (TTL) file using RDFLib,
# generating Cypher queries for Neo4j graph database based on the parsed RDF
# triples, and executing these queries to populate the graph database.
#
# Functions:
#     parse_ttl(file_path): Parses the TTL file using RDFLib and returns the RDF
#                           graph.
#     sanitize_label(label): Sanitizes the given label by replacing invalid
#                            characters with underscores.
#     generate_cypher_queries(graph): Generates Cypher queries based on the RDF
#                                     triples extracted from the parsed RDF
#                                     graph.
#     __main__: Executes the main logic of the script, including parsing the TTL
#               file, generating Cypher queries, and executing them in the Neo4j
#               graph database.
#
# Last Updated (by):

from rdflib import Graph
from neo4j import GraphDatabase
import re

def parse_ttl(file_path):
    g = Graph()
    g.parse(file_path, format='turtle')
    return g

def sanitize_label(label):
    # Replace invalid characters with underscores
    return re.sub(r'[^a-zA-Z0-9_]', '_', label)

def generate_cypher_queries(graph):
    cypher_queries = []

    # Example: Creating nodes for D3FEND concepts
    for concept in graph.subjects(predicate=None, object=None):
        # Sanitize the label to remove invalid characters
        label = sanitize_label(concept)
        cypher_queries.append(f"CREATE (:{label} {{label: '{concept}'}})")

    # Example: Creating relationships between D3FEND concepts
    for triple in graph.triples((None, 'relatedTo', None)):
        source, _, target = triple
        # Sanitize the labels to remove invalid characters
        source_label = sanitize_label(source)
        target_label = sanitize_label(target)
        cypher_queries.append(f"MATCH (s:{source_label}), (t:{target_label}) CREATE (s)-[:RELATED_TO]->(t)")

    return cypher_queries

if __name__ == "__main__":
    ttl_file_path = "C:/Users/newmo/Downloads/d3fend.ttl"

    # Step 1: Parse TTL file
    rdf_graph = parse_ttl(ttl_file_path)


    # Step 2-5: Generate Cypher queries
    cypher_queries = generate_cypher_queries(rdf_graph)

    # Step 6: Execute Cypher queries in Neo4j without authentication
    neo4j_uri = "bolt://localhost:7687"

    with GraphDatabase.driver(neo4j_uri) as driver:
        with driver.session() as session:
            for query in cypher_queries:
                session.run(query)
