# Create a Python environment
FROM python:latest AS python-builder

# Set the working directory
WORKDIR /app

# Install any Python dependencies you need
RUN apt-get update && apt-get install -y python3.11 \
    openjdk-17-jdk \
    sqlite3
# Install Vim
RUN export PATH=$PATH:/usr/bin/python3.11
# Install curl (and vim if you need it)
# RUN apt-get update && apt-get install -y curl vim
RUN pip install requests
RUN pip install neo4j
RUN pip install owlready2
RUN pip install rdflib
RUN pip install beautifulsoup4 html5lib


# Copy your Python script and any other necessary files
COPY . /app

# Set permissions for the JAR and data directory
RUN chmod 755 /app/mapping/mapper.jar

# Set environment variables
ENV UCO_ONTO_PATH=/app/data/UCKG_Snapshots/uco2.ttl
ENV UCO_ONTO_EXTEND_PATH=/app/data/UCKG_Snapshots/uco_extended.ttl
ENV ROOT_FOLDER=/app

# Set the Python script as the entry point
CMD ["python", "entry.py"]
# Stage 1: Build the custom Neo4j image
# FROM neo4j:4.4 AS neo4j-builder

# # Set environment variables for Neo4j
# ENV NEO4J_AUTH=neo4j/password
# ENV NEO4JLABS_PLUGINS='["apoc", "graph-algorithms", "n10s"]'

# # Install the Neosemantics RDF plugin (not needed)
# # RUN wget https://github.com/neo4j-labs/neosemantics/releases/download/4.4.0.0/neosemantics-4.4.0.0.jar -P /var/lib/neo4j/plugins/

# # Expose Neo4j ports
# EXPOSE 7474 7473 7687

# # Start Neo4j
# CMD ["neo4j"]