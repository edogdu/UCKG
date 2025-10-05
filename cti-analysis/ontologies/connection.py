# ontologies/connection.py
from typing import Set, Dict
from .base import OntologyConfig

SUBJECT_TYPES: Set[str] = {
    "action:Action", "core:Relationship",
    "identity:Identity", "identity:Person", "identity:Organization",
    "tool:Tool",
    "observable:ObservableObject", "observable:Vulnerability",
    "observable:File", "observable:URL", "observable:DomainName",
    "observable:IPAddress", "observable:EmailAddress",
    "location:Location",
}

PREDICATES: Set[str] = {
    "action:performer", "action:instrument", "action:object", "action:location",
    "action:startTime", "action:endTime", "action:participant", "action:objective",
    "action:result", "action:phase", "action:actionStatus", "action:environment", "action:error",
    "core:name", "core:description", "core:confidence", "core:createdBy", "core:modifiedTime",
    "core:externalReference", "core:objectMarking", "core:hasFacet", "core:source", "core:target",
    "identity:givenName", "identity:familyName", "identity:birthdate", "identity:address",
    "observable:addressValue", "observable:destination", "observable:destinationPort",
    "observable:fileName", "observable:filePath", "observable:fullValue",
}

LITERAL_TYPES: Set[str] = {"core:Literal", "core:Number", "core:DateTime"}

OBJECT_TYPES: Set[str] = SUBJECT_TYPES | LITERAL_TYPES

PARENT_OF: Dict[str, str] = {
    "identity:Person": "identity:Identity",
    "identity:Organization": "identity:Identity",
    "observable:URL": "observable:ObservableObject",
    "observable:DomainName": "observable:ObservableObject",
    "observable:IPAddress": "observable:ObservableObject",
    "observable:EmailAddress": "observable:ObservableObject",
    "observable:File": "observable:ObservableObject",
    "observable:Vulnerability": "observable:ObservableObject",
}

ATTRIBUTE_PREDICATES: Set[str] = {
    "core:name", "core:description", "core:confidence", "core:modifiedTime",
    "core:externalReference", "core:objectMarking",
    "identity:givenName", "identity:familyName", "identity:birthdate", "identity:address",
    "observable:addressValue", "observable:fileName", "observable:filePath", "observable:fullValue",
    "action:startTime", "action:endTime", "action:phase", "action:actionStatus",
    "action:environment", "action:error", "action:result", "action:objective",
}
RELATION_PREDICATES: Set[str] = PREDICATES - ATTRIBUTE_PREDICATES

ALLOWED_RELATION_COMBOS = {
    ("action:Action", "action:performer", "identity:*"),
    ("action:Action", "action:participant", "identity:*"),
    ("action:Action", "action:instrument", "tool:Tool"),
    ("action:Action", "action:object", "observable:*"),
    ("action:Action", "action:location", "location:Location"),
    ("*", "core:createdBy", "identity:*"),
    ("*", "core:source", "observable:URL"),
    ("*", "core:source", "observable:DomainName"),
    ("*", "core:source", "observable:EmailAddress"),
    ("*", "core:source", "identity:*"),
    ("*", "core:target", "identity:*"),
    ("*", "core:target", "observable:*"),
    ("*", "core:hasFacet", "observable:*"),
}

ALLOWED_ATTRIBUTE_COMBOS = {
    ("identity:*", "identity:givenName", "core:Literal"),
    ("identity:*", "identity:familyName", "core:Literal"),
    ("identity:*", "identity:birthdate", "core:DateTime"),
    ("identity:*", "identity:address", "core:Literal"),
    ("observable:*", "observable:fileName", "core:Literal"),
    ("observable:*", "observable:filePath", "core:Literal"),
    ("observable:*", "observable:fullValue", "core:Literal"),
    ("observable:*", "observable:addressValue", "core:Literal"),
    ("observable:*", "observable:destination", "observable:IPAddress"),
    ("observable:*", "observable:destinationPort", "core:Number"),
    ("action:Action", "action:startTime", "core:DateTime"),
    ("action:Action", "action:endTime", "core:DateTime"),
    ("action:Action", "action:phase", "core:Literal"),
    ("action:Action", "action:actionStatus", "core:Literal"),
    ("action:Action", "action:environment", "core:Literal"),
    ("action:Action", "action:error", "core:Literal"),
    ("action:Action", "action:result", "core:Literal"),
    ("action:Action", "action:objective", "core:Literal"),
    ("*", "core:name", "core:Literal"),
    ("*", "core:description", "core:Literal"),
    ("*", "core:confidence", "core:Number"),
    ("*", "core:externalReference", "core:Literal"),
    ("*", "core:objectMarking", "core:Literal"),
    ("*", "core:modifiedTime", "core:DateTime"),
}

def get_config() -> OntologyConfig:
    return OntologyConfig(
        SUBJECT_TYPES=SUBJECT_TYPES,
        PREDICATES=PREDICATES,
        OBJECT_TYPES=OBJECT_TYPES,
        LITERAL_TYPES=LITERAL_TYPES,
        PARENT_OF=PARENT_OF,
        ATTRIBUTE_PREDICATES=ATTRIBUTE_PREDICATES,
        RELATION_PREDICATES=RELATION_PREDICATES,
        ALLOWED_RELATION_COMBOS=ALLOWED_RELATION_COMBOS,
        ALLOWED_ATTRIBUTE_COMBOS=ALLOWED_ATTRIBUTE_COMBOS,
    )
