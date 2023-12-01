# UCKG
Unified Cybersecurity Knowledge Graph

## Programming Languages Needed to Run Scripts
* Python3 - https://www.python.org/downloads/
* Java JDK 17 - https://www.oracle.com/java/technologies/downloads/#java17

## Ussage
* First run rml_mapper tool to generate your turtle file to be combined later with the ontology
```bash
$  java -jar mapper.jar -m UCKG/rml_mapper/<data_source>/<data_source>_rml.ttl -s turtle >> ./<data_source>/out.ttl
```
Example for CVE rml_mapper:
```bash
$  java -jar mapper.jar -m UCKG/rml_mapper/cve/cve_rml.ttl -s turtle >> ./cve/out.ttl
```

* Next run the ontology_updater to create a merged uco_with_instances.ttl file
```bash
$  python ontology_updater.py <data_source>
```
Example for CVE ontology_updater:
```bash
$  python ontology_updater.py cve
```

## License

This project is licensed under the [MIT License](LICENSE.md).
