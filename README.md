# UCKG
Unified Cybersecurity Knowledge Graph

## Software Requirements 
* Docker Desktop - https://www.docker.com/products/docker-desktop/

## Usage
* First, pull the repository into your file system 
```bash
$  git clone https://github.com/edogdu/UCKG.git ./UCKG
```

* Next, switch to root directory of project
```bash
$  cd UCKG
```

* Lastly, run docker-compose to start project
```bash
$  docker-compose up --build
```

* To shutdown the UCKG, follow these steps
    - type Ctrl+C to stop server
    - use docker-compose to clean up images
```bash
$  docker-compose down
```

## Configuration Options

### GPU Acceleration (Optional)
The embedding generation process can utilize NVIDIA GPUs for faster processing:

* **To run with GPU** (default): The GPU configuration is enabled by default. Requires NVIDIA drivers and Docker GPU support.

* **To disable GPU support**: Comment out the GPU-related lines in `docker-compose.yml` if you don't have an NVIDIA GPU:
  ```yaml
  # In the ollama service section, comment out these lines:
  environment:
    # - NVIDIA_VISIBLE_DEVICES=all
    # - NVIDIA_DRIVER_CAPABILITIES=compute,utility
  # deploy:
  #   resources:
  #     reservations:
  #       devices:
  #         - driver: nvidia
  #           count: all
  #           capabilities: [gpu]
  ```

### Embedding Process Control
The system includes semantic embedding generation for enhanced search capabilities:

* **To enable embeddings** (default): The embedding generation is enabled by default with `EMBED_ENV: "true"`.

* **To disable embeddings**: Change `EMBED_ENV` to `"false"` in `docker-compose.yml` to skip embedding generation and save processing time:
  ```yaml
  # In uckg-scripts service environment section:
  uckg-scripts:
    environment:
      EMBED_ENV: "false"  # Change from "true" to "false" to disable
  ```

Note: Disabling embeddings will skip the semantic search capabilities but the core knowledge graph functionality will still work.

## Resources
* A copy of our paper outlining the project is available in the root directory as uckg_paper.pdf
* A web-based visualization of the Unified Cybersecurity Ontology can be accessed at this url: https://service.tib.eu/webvowl/#iri=http://purl.org/cyber/uco
* Docker has a tendency to have hanging resources that can take up alot of diskspace, I found the following commands useful
    - In Docker Desktop Application, ensure no containers are running
    - In Command Line or Bash run Docker prune commands
    ```bash
    $  docker image prune -f
    ```
    ```bash
    $  docker builder prune
    ```
    - In Docker Desktop Application, navigate to Troubleshoot section (bug button) and select Clean/Purge data
    - If diskspace utilization is not changing after running these steps, try restarting your computer


## License

This project is licensed under the [MIT License](LICENSE.md).
