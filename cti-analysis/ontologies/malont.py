# ontologies/malont.py
from typing import Set, Dict, Tuple
from .base import OntologyConfig

# --- Core vocab pulled from your current MALOnt lists ---
SUBJECT_TYPES: Set[str] = {
    'Staging','Adware','CommandAndControl','Spyware','DDoS','DomainName','Dropper','Port','MD5',
    'Protocol','VirusScanner','Downloader','Ransomware','OperatingSystem','Rootkit',
    'AttackPattern_SmallDescription','IPAddress','Bootkit','Hardware','SSDeep',
    'Application','AttackPattern','Phishing','Campaign','SHA-256','System',
    'Vulnerability_Desc','Anonymization','Backdoor','Location','Organization',
    'Reconnaissance','Exploit-kit','Time','MalwareAnalysis','ResourceExploitation',
    'SHA','HostingMalware','SHA-1','Unknown','HostingTargetLists','Hash',
    'AttackPattern_LargeDescription','Software','Network','Indicator','Trojan','Botnet',
    'Worm','EmailAddress','Malware','RogueSecuritySoftware','vHash','Filepath','Region',
    'Report','Virus','ThreatActor','Keylogger','Browser','ScreenCapture',
    'Vulnerability_CVEID','URL','Wiper','Filename','Infrastructure','MalwareFamily',
    'Person','Webshell','Vulnerability','Bot','RemoteAccessTrojan-RAT','Country',
    'Exfiltration','Amplification'
}

PREDICATES: Set[str] = {
    "targets", "communicatesWith", "uses", "has", "hasAlias",
    "hasVulnerability", "indicates", "exploits", "hasAuthor", "belongsTo"
}

# Literals used by attribute predicates
LITERAL_TYPES: Set[str] = {"Literal", "Number", "DateTime"}

# In MALOnt most objects are also valid “object types”
OBJECT_TYPES: Set[str] = SUBJECT_TYPES | LITERAL_TYPES

# Optional simple hierarchy (child -> parent). Extend freely over time.
PARENT_OF: Dict[str, str] = {
    "Person": "Identity",
    "Organization": "Identity",
    "Country": "Location",
    "Region": "Location",
    "IPAddress": "Observable",
    "DomainName": "Observable",
    "URL": "Observable",
    "Filename": "Observable",
    "Filepath": "Observable",
    "Hash": "Observable",
    "MD5": "Hash",
    "SHA": "Hash",
    "SHA-1": "Hash",
    "SHA-256": "Hash",
    "SSDeep": "Hash",
    "vHash": "Hash",
}

# Which predicates are attributes (must end in a literal on the object side)
ATTRIBUTE_PREDICATES: Set[str] = {
    "has",       # e.g., Malware has "persistence via RunKeys"
    "hasAlias",  # ThreatActor hasAlias "APT29"
    "hasAuthor"  # Report hasAuthor "VendorX" (you may prefer Organization as object; keep literal allowed)
}
RELATION_PREDICATES: Set[str] = PREDICATES - ATTRIBUTE_PREDICATES

# Allowed relation triples (subject.type, predicate, object.type).
# This is a seed set. Add/trim to fit your corpus as you iterate.
ALLOWED_RELATION_COMBOS: Set[Tuple[str, str, str]] = {
    ("ThreatActor", "uses", "Malware"),
    ("ThreatActor", "uses", "Tool"),
    ("ThreatActor", "uses", "Software"),
    ("ThreatActor", "uses", "Infrastructure"),
    ("ThreatActor", "targets", "Organization"),
    ("ThreatActor", "targets", "Person"),
    ("ThreatActor", "targets", "Country"),
    ("ThreatActor", "targets", "Region"),

    ("Campaign", "targets", "Organization"),
    ("Campaign", "targets", "Country"),
    ("Campaign", "targets", "Region"),
    ("Campaign", "uses", "Malware"),
    ("Campaign", "uses", "Tool"),
    ("Campaign", "uses", "Infrastructure"),

    ("Malware", "exploits", "Vulnerability"),
    ("Malware", "communicatesWith", "IPAddress"),
    ("Malware", "communicatesWith", "DomainName"),
    ("Malware", "communicatesWith", "URL"),
    ("Malware", "uses", "Infrastructure"),
    ("Malware", "belongsTo", "MalwareFamily"),

    ("Tool", "communicatesWith", "IPAddress"),
    ("Tool", "communicatesWith", "DomainName"),
    ("Tool", "communicatesWith", "URL"),

    ("Infrastructure", "communicatesWith", "IPAddress"),
    ("Infrastructure", "communicatesWith", "DomainName"),
    ("Infrastructure", "communicatesWith", "URL"),

    ("Indicator", "indicates", "Malware"),
    ("Indicator", "indicates", "ThreatActor"),
    ("Indicator", "indicates", "Campaign"),
    ("Indicator", "indicates", "Tool"),
    ("Indicator", "indicates", "Infrastructure"),

    ("Report", "belongsTo", "Campaign"),
    ("Report", "belongsTo", "ThreatActor"),
    ("Report", "belongsTo", "Malware"),

    # Hash & file-ish things often belong to Malware/Tool
    ("Hash", "belongsTo", "Malware"),
    ("Filename", "belongsTo", "Malware"),
    ("Filepath", "belongsTo", "Malware"),
    ("URL", "belongsTo", "Infrastructure"),
    ("DomainName", "belongsTo", "Infrastructure"),
    ("IPAddress", "belongsTo", "Infrastructure"),
}

# Allowed attribute triples (subject.type, predicate, object.literalType)
ALLOWED_ATTRIBUTE_COMBOS: Set[Tuple[str, str, str]] = {
    ("ThreatActor", "hasAlias", "Literal"),
    ("Malware", "hasAlias", "Literal"),
    ("Campaign", "hasAlias", "Literal"),
    ("Report", "hasAuthor", "Literal"),
    ("Malware", "has", "Literal"),
    ("Tool", "has", "Literal"),
    ("Infrastructure", "has", "Literal"),
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
