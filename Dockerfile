# Use a base image with Python 
FROM python:3.11

# Set the working directory
WORKDIR .

# Install any Python dependencies
# RUN pip install ...

# Set the Python script as the entry point
CMD ["python", "entry.py"]
