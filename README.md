# UCKG
Unified Cybersecurity Knowledge Graph

## Software Requirements 
* Docker Desktop - https://www.docker.com/products/docker-desktop/

## Usage
* First, pull the repository into your file system 
```bash
$  git clone https://github.com/edogdu/UCKG.git .
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
