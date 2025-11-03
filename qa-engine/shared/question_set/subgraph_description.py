NODE_TYPES = {
    "UcoCVE": { "label": "string", "ucobaseSeverity": "string", "ucoevaluatorSolution": "string", "ucoexploitabilityScore": "string", "ucoimpactScore": "string", "ucoobtainAllPrivilege": "string", "ucouserInteractionRequired": "string", "ucovectorString": "string", "ucovulnStatus": "string", "uri": "string" },
    "UcoCWE": { "ucoabstraction": "string", "ucoapplicablePlatform": "string", "ucocommonConsequences": "string", "ucocweExtendedSummary": "string", "ucocweID": "string", "ucocweName": "string", "ucocweSummary": "string", "ucodemonstrativeExamples": "string", "ucodescription": "string", "ucodetectionMethods": "string", "ucolikelihoodOfExploit": "string", "ucomappingNotes": "string", "ucomodesOfIntroduction": "string", "ucopotentialMitigations": "string", "ucoreferences": "string", "ucorelatedAttackPatterns": "string", "ucostatus": "string", "ucostructure": "string", "ucotimeOfIntroduction": "unknown", "uri": "string" },
    "UcoExploitTarget": { "uri": "string" },
    "UcoVulnerability": { "ucolastModifiedDateTime": "unknown", "ucopublishedDateTime": "unknown", "ucosummary": "string", "uri": "string" },
    "UcoexCAMPAIGNS": { "ucoexDESCRIPTION": "string", "ucoexDOMAIN": "string", "ucoexNAME": "string", "ucoexURL": "string", "uri": "string" },
    "UcoexCAPEC": { "label": "string", "ucoexAbstraction": "string", "ucoexCAPEC_id": "string", "ucoexCAPEC_name": "string", "ucoexConsequences": "list<string>", "ucoexDescription": "string", "ucoexExample": "list<string>", "ucoexExecutionFlowTechnique": "list<string>", "ucoexExtendedDescription": "list<string>", "ucoexLikelihood": "string", "ucoexMitigations": "list<string>", "ucoexPrerequisites": "list<string>", "ucoexRelatedAttPattern": "list<string>", "ucoexRelatedWeaknesses": "list<string>", "ucoexResources_Required": "list<string>", "ucoexSeverity": "string", "ucoexSkills_Required": "list<string>", "ucoexTaxonomyMappingATTACK": "list<string>", "uri": "string" },
    "UcoexCPE": { "cpeName": "string", "cpeNameId": "string", "dictionary_found": "boolean", "lastModified": "unknown", "titles": "string", "uri": "string" },
    "UcoexGROUPS": { "ucoexDESCRIPTION": "string", "ucoexDOMAIN": "string", "ucoexNAME": "string", "ucoexURL": "string", "uri": "string" },
    "UcoexMITIGATIONS": { "ucoexDESCRIPTION": "string", "ucoexDOMAIN": "string", "ucoexNAME": "string", "ucoexURL": "string", "uri": "string" },
    "UcoexMITREATTACK": { "ucoexDESCRIPTION": "string", "ucoexDOMAIN": "string", "ucoexNAME": "string", "ucoexURL": "string", "uri": "string" },
    "UcoexMITRED3FEND": { "ucoexMITRED3FEND_DEFINITION": "string", "ucoexMITRED3FEND_LABEL": "string", "uri": "string" },
    "UcoexObservedExample": { "ucoexDESCRIPTION": "string", "uri": "string" },
    "UcoexSOFTWARE": { "ucoexDESCRIPTION": "string", "ucoexDOMAIN": "string", "ucoexNAME": "string", "ucoexURL": "string", "uri": "string" },
    "UcoexTACTICS": { "ucoexDESCRIPTION": "string", "ucoexDOMAIN": "string", "ucoexNAME": "string", "ucoexURL": "string", "uri": "string" }
}
NODE_PROPERTY_TYPES = {
    "UcoCVE": {
        "UcoCVE": " is a documented cybersecurity vulnerability",
        "label": ", named <value>,",
        "ucobaseSeverity": " It has a base severity of <value>",
        "ucoevaluatorSolution": " It has the evaluator recommending the solution <value>",
        "ucoexploitabilityScore": " It has an exploitability score of <value>",
        "ucoimpactScore": " It has an overall impact score of <value>",
        "ucoobtainAllPrivilege": " It indicates that obtaining all privileges is <value>",
        "ucouserInteractionRequired": " It indicates that user interaction is <value>",
        "ucovectorString": " It is represented by the vector string <value>",
        "ucovulnStatus": " It is currently marked with the vulnerability status <value>",
    },
    "UcoCWE": {
        "UcoCWE": " is a software weakness type defined in the Common Weakness Enumeration (CWE) catalog",
        "ucocweName": ", named <value>,",
        "ucocweID": " It is identified by the ID <value>",
        "ucocweSummary": " It is summarized as <value>",
        "ucocweExtendedSummary": " with an extended explanation stating that <value>",
        "ucodescription": " It is described as <value>",
        "ucabstraction": " It is categorized under the abstraction level <value>",
        "ucostructure": " It follows the structural classification of <value>",
        "ucapplicablePlatform": " It is applicable to platforms such as <value>",
        "ucocommonConsequences": " It leads to common consequences like <value>",
        "ucopotentialMitigations": " It can be mitigated through measures such as <value>",
        "ucodetectionMethods": " It is detectable by methods such as <value>",
        "ucolikelihoodOfExploit": " It has a likelihood of exploitation rated as <value>",
        "ucodemonstrativeExamples": " It is illustrated by examples such as <value>",
        "ucomodesOfIntroduction": " It is typically introduced during phases like <value>",
        "ucotimeOfIntroduction": " It generally occurs at <value>",
        "ucomappingNotes": " It has mapping notes stating <value>",
        "ucorelatedAttackPatterns": " It is related to attack patterns such as <value>",
        "ucoreferences": " It is referenced in materials like <value>",
        "ucostatus": " It currently has the status <value>",
    },
    "UcoExploitTarget": {
        "UcoExploitTarget": " is an exploit target resource/object",
        "uri": ", identified by the URI <value>",
    },
    "UcoVulnerability": {
        "UcoVulnerability": " is a documented security flaw/weakness",
        "ucosummary": ", described as <value>",
        "ucopublishedDateTime": " It was first published on <value>",
        "ucolastModifiedDateTime": " And it was last modified on <value>",
    },
    "UcoexCAMPAIGNS": {
        "UcoexCAMPAIGNS": " is a cybersecurity campaign/operation",
        "ucoexNAME": ", named <value>,",
        "ucoexDESCRIPTION": ", described as <value>",
        "ucoexDOMAIN": " It is associated with the domain <value>",
        "ucoexURL": " It is referenced at the URL <value>",
    },
    "UcoexCAPEC": {
        "UcoexCAPEC": " is a common attack pattern from the MITRE CAPEC framework",
        "ucoexCAPEC_name": ", named <value>,",
        "ucoexCAPEC_id": " It is identified by the ID <value>",
        "ucoexAbstraction": " It is categorized under the abstraction level <value>",
        "ucoexDescription": ", described as <value>",
        "ucoexExtendedDescription": " It has further explanation stating that <value>",
        "ucoexSeverity": " It has a severity level of <value>",
        "ucoexLikelihood": " It has a likelihood rated as <value>",
        "ucoexMitigations": " It can be mitigated by measures such as <value>",
        "ucoexRelatedAttPattern": " It is related to other attack patterns such as <value>",
        "ucoexRelatedWeaknesses": " It is associated with weaknesses like <value>",
        "ucoexSkills_Required": " It requires skills such as <value>",
        "ucoexResources_Required": " It needs resources like <value>",
        "ucoexPrerequisites": " It assumes conditions such as <value>",
        "ucoexConsequences": " It can lead to consequences like <value>",
        "ucoexExecutionFlowTechnique": " It is typically carried out using techniques such as <value>",
        "ucoexExample": " It is illustrated by examples like <value>",
        "ucoexTaxonomyMappingATTACK": " It is mapped to MITRE ATT&CK techniques such as <value>",
        "label": ", labeled as <value>,",
    },
    "UcoexCPE": {
        "UcoexCPE": " is a software/hardware product configuration entry from the CPE dictionary",
        "cpeName": ", identified as <value>,",
        "cpeNameId": " with the CPE name ID <value>",
        "titles": " It is also titled <value>",
        "dictionary_found": " It has a dictionary entry found: <value>",
        "lastModified": " It was last modified on <value>",
    },
    "UcoexGROUPS": {
        "UcoexGROUPS": " is a threat group/adversary organization",
        "ucoexNAME": ", known as <value>,",
        "ucoexDESCRIPTION": ", described as <value>",
        "ucoexDOMAIN": " It is operating within the domain <value>",
        "ucoexURL": " It is referenced at the URL <value>",
    },
    "UcoexMITIGATIONS": {
        "UcoexMITIGATIONS": " is a defensive measure/security mitigation technique",
        "ucoexNAME": ", named <value>,",
        "ucoexDESCRIPTION": ", described as <value>",
        "ucoexDOMAIN": " It is applicable within the domain <value>",
        "ucoexURL": " It is referenced at the URL <value>",
    },
    "UcoexMITREATTACK": {
        "UcoexMITREATTACK": " is a MITRE ATT&CK technique or technique group",
        "ucoexNAME": ", named <value>,",
        "ucoexDESCRIPTION": ", described as <value>",
        "ucoexDOMAIN": " It is applicable within the domain <value>",
        "ucoexURL": " It is referenced at the URL <value>",
    },
    "UcoexMITRED3FEND": {
        "UcoexMITRED3FEND": " is a defensive cybersecurity technique from the MITRE D3FEND framework",
        "ucoexMITRED3FEND_LABEL": ", labeled as <value>,",
        "ucoexMITRED3FEND_DEFINITION": ", defined as <value>",
    },
    "UcoexObservedExample": {
        "UcoexObservedExample": " is an observed real-world example/instance of a cybersecurity event",
        "ucoexDESCRIPTION": ", described as <value>",
    },
    "UcoexSOFTWARE": {
        "UcoexSOFTWARE": " is a software tool or application relevant to cybersecurity analysis",
        "ucoexNAME": ", named <value>,",
        "ucoexDESCRIPTION": ", described as <value>",
        "ucoexDOMAIN": " It is associated with the domain <value>",
        "ucoexURL": " It is referenced at the URL <value>",
    },
    "UcoexTACTICS": {
        "UcoexTACTICS": " is an adversarial tactic from the MITRE ATT&CK framework",
        "ucoexNAME": ", named <value>,",
        "ucoexDESCRIPTION": ", described as <value>",
        "ucoexDOMAIN": " It is used within the domain <value>",
        "ucoexURL": " It is referenced at the URL <value>",
    }
}
RELATIONSHIPS_TYPES = {
    "UCOEXHASCPE": {
        "(:UcoCVE) -[:UCOEXHASCPE]-> (:UcoexCPE)",
        "<s> is a vulnerability in the platform <o>."
    },
    "UCOHASOBSERVEDEXAMPLE": {
        "(:UcoCWE) -[:UCOHASOBSERVEDEXAMPLE]-> (:UcoexObservedExample)",
        "<s> has real-world observed examples <o>."
    },
    "UCOHASVULNERABILITY": {
        "(:UcoExploitTarget) -[:UCOHASVULNERABILITY]-> (:UcoVulnerability)",
        "<s> has a vulnerability <o>."
    },
    "UCOHASWEAKNESS": {
        "(:UcoExploitTarget) -[:UCOHASWEAKNESS]-> (:UcoCWE)",
        "<s> has a weakness <o>."
    },
    "UCOHASCVE_ID": {
        "(:UcoVulnerability) -[:UCOHASCVE_ID]-> (:UcoCVE)",
        "<s> has a CVE identifier <o>."
    },
    "UCOEXATTRIBUTEDTO": {
        "(:UcoexCAMPAIGNS) -[:UCOEXATTRIBUTEDTO]-> (:UcoexGROUPS)",
        "<s> is attributed to <o>."
    },
    "UCOEXCAMPAIGNUSESSOFTWARE": {
        "(:UcoexCAMPAIGNS) -[:UCOEXCAMPAIGNUSESSOFTWARE]-> (:UcoexSOFTWARE)",
        "<s> uses software <o>."
    },
    "UCOEXCAMPAIGNUSESTECHNIQUE": {
        "(:UcoexCAMPAIGNS) -[:UCOEXCAMPAIGNUSESTECHNIQUE]-> (:UcoexMITREATTACK)",
        "<s> uses technique <o>."
    },
    "UCOEXHASRELATEDWEAKNESS": {
        "(:UcoexCAPEC) -[:UCOEXHASRELATEDWEAKNESS]-> (:UcoCWE)",
        "<s> has related weakness <o>."
    },
    "UCOEXHASTAXONOMYMAPPING": {
        "(:UcoexCAPEC) -[:UCOEXHASTAXONOMYMAPPING]-> (:UcoexMITREATTACK)",
        "<s> has taxonomy mapping <o>."
    },
    "UCOEXGROUPUSESSOFTWARE": {
        "(:UcoexGROUPS) -[:UCOEXGROUPUSESSOFTWARE]-> (:UcoexSOFTWARE)",
        "<s> uses software <o>."
    },
    "UCOEXGROUPUSESTECHNIQUE": {
        "(:UcoexGROUPS) -[:UCOEXGROUPUSESTECHNIQUE]-> (:UcoexMITREATTACK)",
        "<s> uses technique <o>."
    },
    "UCOEXMITIGATES": {
        "(:UcoexMITIGATIONS) -[:UCOEXMITIGATES]-> (:UcoexMITREATTACK)",
        "<s> mitigates <o>."
    },
    "UCOEXHASMITREATTACK": {
        "(:UcoexMITRED3FEND) -[:UCOEXHASMITREATTACK]-> (:UcoexMITREATTACK)",
        "<s> has MITRE technique <o>."
    },
    "UCOEXEXAMPLEOBSERVEDIN": {
        "(:UcoexObservedExample) -[:UCOEXEXAMPLEOBSERVEDIN]-> (:UcoCVE)",
        "<s> is observed in <o>."
    },
    "UCOEXSOFTWAREUSESTECHNIQUE": {
        "(:UcoexSOFTWARE) -[:UCOEXSOFTWAREUSESTECHNIQUE]-> (:UcoexMITREATTACK)",
        "<s> uses technique <o>."
    }
}