# Use a base image with Python 
FROM python:latest

# Set the working directory
WORKDIR /app

RUN apt-get update && \
    apt-get install -y python3.11

RUN ls -a /usr/bin/python3.11 && \
    export PATH=$PATH:/usr/bin/python3.11

COPY . /app

# Install any Python dependencies
RUN pip install requests

# Set the Python script as the entry point
CMD ["python", "entry.py"]
