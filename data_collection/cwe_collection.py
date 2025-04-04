import os
import json
import logging
import xml.etree.ElementTree as ET
from process import shared_functions as sf  # 이거 코멘트 아니었음
from bs4 import BeautifulSoup
import requests
import zipfile

# Configure the logging module
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('collect_logger')

def check_cwe_status():
    # Need to add the meta-data
    return 3

def download_cwe_xml_file():
    url = "https://cwe.mitre.org/data/downloads.html"
    xml_filename = ""
    path = ""
    response = requests.get(url)
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        table = soup.find("table", {"id": "StripedTable"})
        if table:
            rows = table.find_all("tr")
            if len(rows) > 1:
                download_row = rows[1]
                first_cell = download_row.find("td")
                if first_cell:
                    link = first_cell.find("a")
                    if link and link.get("href"):
                        xml_zip_url = link.get("href")
                        full_url = "https://cwe.mitre.org" + xml_zip_url
                        filename = "cwe.xml.zip"
                        try:
                            with open(filename, "wb") as f:
                                f.write(requests.get(full_url).content)
                            logger.info(f"File '{filename}' downloaded successfully.")

                            with zipfile.ZipFile(filename, 'r') as zip_ref:
                                xml_files = [f for f in zip_ref.namelist() if f.endswith('.xml')]
                                if xml_files:
                                    xml_filename = xml_files[0]
                                    destination = os.getcwd()
                                    zip_ref.extract(xml_filename, destination)
                                    os.rename(xml_filename, "cwe_dict.xml")
                                    path = os.path.join(os.getcwd(), "cwe_dict.xml")
                                    logger.info(f"XML file '{xml_filename}' extracted successfully.")
                                else:
                                    logger.info("No XML file found in the ZIP.")
                            
                            os.remove(filename)
                            logger.info(f"ZIP file '{filename}' removed.")
                        except Exception as e:
                            logger.info(f"Failed to process ZIP file '{filename}': {e}")
                    else:
                        logger.info("Download link not found in the first cell.")
                else:
                    logger.info("First cell not found in the download row.")
            else:
                logger.info("No download row found in the table.")
        else:
            logger.info("Table with id 'StripedTable' not found.")
    else:
        logger.info(f"Failed to access URL: {url}")
    return path

## MODIFICATION: Helper to get clean text
def get_clean_text(element):
    if element is None:
        return None
    return ''.join(element.itertext()).strip()

## MODIFICATION: Helper to convert a set of XML elements (children) into a list of dicts
def parse_children_as_list(parent, child_tag, mapping):
    """
    mapping: dict mapping child XML tag to the key name in output.
    For attributes that need to be copied, use mapping from attribute name to output key.
    """
    result = []
    for child in parent.findall(child_tag):
        item = {}
        # For each mapping key, try to get from attribute or element text.
        for xml_key, out_key in mapping.items():
            # First try attribute:
            val = child.get(xml_key)
            if val is None:
                # Then try child element text:
                sub = child.find(xml_key)
                if sub is not None:
                    val = get_clean_text(sub)
            if val is not None:
                item[out_key] = val
        result.append(item)
    return result if result else None

def cwe_init():
    xml_file_path = download_cwe_xml_file()
    target_path = {
        'Weaknesses': './{http://cwe.mitre.org/cwe-7}Weaknesses',
        'Weakness': './{http://cwe.mitre.org/cwe-7}Weakness',
        'Description': './{http://cwe.mitre.org/cwe-7}Description',
        'Extended_Description': './{http://cwe.mitre.org/cwe-7}Extended_Description',
        'Related_Weaknesses': './{http://cwe.mitre.org/cwe-7}Related_Weaknesses',
        'Applicable_Platforms': './{http://cwe.mitre.org/cwe-7}Applicable_Platforms',
        'Alternate_Terms': './{http://cwe.mitre.org/cwe-7}Alternate_Terms',
        'Modes_Of_Introduction': './{http://cwe.mitre.org/cwe-7}Modes_Of_Introduction',
        'Common_Consequences': './{http://cwe.mitre.org/cwe-7}Common_Consequences',
        'Detection_Methods': './{http://cwe.mitre.org/cwe-7}Detection_Methods',
        'Potential_Mitigations': './{http://cwe.mitre.org/cwe-7}Potential_Mitigations',
        'Demonstrative_Examples': './{http://cwe.mitre.org/cwe-7}Demonstrative_Examples',
        'Observed_Examples': './{http://cwe.mitre.org/cwe-7}Observed_Examples',
        'References': './{http://cwe.mitre.org/cwe-7}References',
        'Mapping_Notes': './{http://cwe.mitre.org/cwe-7}Mapping_Notes',
        'Content_History': './{http://cwe.mitre.org/cwe-7}Content_History'
    }

    tree = ET.parse(xml_file_path)
    root = tree.getroot()
    cwes = {"cwes": []}

    for weaknesses in root.findall(target_path['Weaknesses']):
        for weakness in weaknesses.findall(target_path['Weakness']):
            # Basic attributes
            cwe_id = "CWE-" + str(weakness.get("ID")).strip()
            name = weakness.get("Name")
            abstraction = weakness.get("Abstraction")
            structure = weakness.get("Structure")
            status = weakness.get("Status")

            description = get_clean_text(weakness.find(target_path['Description']))
            extended_summary = get_clean_text(weakness.find(target_path['Extended_Description']))

            ## related_weaknesses: Build an object with key "related_weakness" as a list of dicts.
            rel_weak_elem = weakness.find(target_path['Related_Weaknesses'])
            related_weaknesses = None
            if rel_weak_elem is not None:
                related_weaknesses = {"related_weakness": []}
                for child in rel_weak_elem.findall('{http://cwe.mitre.org/cwe-7}Related_Weakness'):
                    rel_dict = {}
                    cwe_rel = child.get("CWE_ID")
                    if cwe_rel:
                        rel_dict["ID"] = "CWE-" + cwe_rel.strip()
                    if child.get("Nature"):
                        rel_dict["Nature"] = child.get("Nature")
                    if child.get("View_ID"):
                        rel_dict["View_ID"] = child.get("View_ID")
                    if child.get("Ordinal"):
                        rel_dict["Ordinal"] = child.get("Ordinal")
                    related_weaknesses["related_weakness"].append(rel_dict)
                if not related_weaknesses["related_weakness"]:
                    related_weaknesses = None

            ## applicable_platforms: Process children (<Language>, <Technology>, etc.)
            app_platforms_elem = weakness.find(target_path['Applicable_Platforms'])
            applicable_platforms = None
            if app_platforms_elem is not None:
                applicable_platforms = {}
                for child in app_platforms_elem:
                    # tag = ET.QName(child.tag).localname  # e.g., "Language" or "Technology"
                    tag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                    # Get all attributes
                    entry = child.attrib
                    if tag in applicable_platforms:
                        applicable_platforms[tag].append(entry)
                    else:
                        applicable_platforms[tag] = [entry]
            
            ## alternative_terms: Process <Alternate_Terms>
            alt_terms_elem = weakness.find(target_path['Alternate_Terms'])
            alternative_terms = None
            if alt_terms_elem is not None:
                alternative_terms = {"alternative_term": []}
                for child in alt_terms_elem.findall('{http://cwe.mitre.org/cwe-7}Alternate_Term'):
                    term_text = get_clean_text(child.find('./{http://cwe.mitre.org/cwe-7}Term'))
                    desc_text = get_clean_text(child.find('./{http://cwe.mitre.org/cwe-7}Description'))
                    alternative_terms["alternative_term"].append({
                        "Term": term_text,
                        "Description": desc_text
                    })
                if not alternative_terms["alternative_term"]:
                    alternative_terms = None

            ## modes_of_introduction: Process <Modes_Of_Introduction>
            moi_elem = weakness.find(target_path['Modes_Of_Introduction'])
            modes_of_introduction = None
            if moi_elem is not None:
                modes_of_introduction = {"introduction": []}
                for child in moi_elem.findall('{http://cwe.mitre.org/cwe-7}Introduction'):
                    intro_dict = {}
                    phase_elem = child.find('./{http://cwe.mitre.org/cwe-7}Phase')
                    if phase_elem is not None:
                        intro_dict["Phase"] = get_clean_text(phase_elem)
                    note_elem = child.find('./{http://cwe.mitre.org/cwe-7}Note')
                    if note_elem is not None:
                        intro_dict["Note"] = get_clean_text(note_elem)
                    modes_of_introduction["introduction"].append(intro_dict)
                if not modes_of_introduction["introduction"]:
                    modes_of_introduction = None

            ## common_consequences: Process <Common_Consequences>
            cc_elem = weakness.find(target_path['Common_Consequences'])
            common_consequences = None
            if cc_elem is not None:
                common_consequences = {"consequence": []}
                for child in cc_elem.findall('{http://cwe.mitre.org/cwe-7}Consequence'):
                    cons_dict = {}
                    scopes = [get_clean_text(s) for s in child.findall('./{http://cwe.mitre.org/cwe-7}Scope') if get_clean_text(s)]
                    # If only one, output as string; otherwise list
                    cons_dict["Scope"] = scopes[0] if len(scopes)==1 else scopes
                    impacts = [get_clean_text(i) for i in child.findall('./{http://cwe.mitre.org/cwe-7}Impact') if get_clean_text(i)]
                    cons_dict["Impact"] = impacts[0] if len(impacts)==1 else impacts
                    note_elem = child.find('./{http://cwe.mitre.org/cwe-7}Note')
                    if note_elem is not None:
                        cons_dict["Note"] = get_clean_text(note_elem)
                    common_consequences["consequence"].append(cons_dict)
                if not common_consequences["consequence"]:
                    common_consequences = None

            ## detection_methods: Process <Detection_Methods>
            dm_elem = weakness.find(target_path['Detection_Methods'])
            detection_methods = None
            if dm_elem is not None:
                detection_methods = {"detection_method": []}
                for child in dm_elem.findall('{http://cwe.mitre.org/cwe-7}Detection_Method'):
                    dm_dict = {}
                    if child.get("Detection_Method_ID"):
                        dm_dict["Detection_Method_ID"] = child.get("Detection_Method_ID")
                    method_elem = child.find('./{http://cwe.mitre.org/cwe-7}Method')
                    if method_elem is not None:
                        dm_dict["Method"] = get_clean_text(method_elem)
                    desc_elem = child.find('./{http://cwe.mitre.org/cwe-7}Description')
                    if desc_elem is not None:
                        dm_dict["Description"] = get_clean_text(desc_elem)
                    eff_elem = child.find('./{http://cwe.mitre.org/cwe-7}Effectiveness')
                    if eff_elem is not None:
                        dm_dict["Effectiveness"] = get_clean_text(eff_elem)
                    detection_methods["detection_method"].append(dm_dict)
                if not detection_methods["detection_method"]:
                    detection_methods = None

            ## potential_mitigations: Process <Potential_Mitigations>
            pm_elem = weakness.find(target_path['Potential_Mitigations'])
            potential_mitigations = None
            if pm_elem is not None:
                potential_mitigations = {"mitigation": []}
                for child in pm_elem.findall('{http://cwe.mitre.org/cwe-7}Mitigation'):
                    mit_dict = {}
                    phase_elem = child.find('./{http://cwe.mitre.org/cwe-7}Phase')
                    if phase_elem is not None:
                        mit_dict["Phase"] = get_clean_text(phase_elem)
                    desc_elem = child.find('./{http://cwe.mitre.org/cwe-7}Description')
                    if desc_elem is not None:
                        mit_dict["Description"] = get_clean_text(desc_elem)
                    potential_mitigations["mitigation"].append(mit_dict)
                if not potential_mitigations["mitigation"]:
                    potential_mitigations = None

            ## demonstrative_examples: Process <Demonstrative_Examples>
            de_elem = weakness.find(target_path['Demonstrative_Examples'])
            demonstrative_examples = None
            if de_elem is not None:
                # Similar processing can be applied; here we simply get the clean text.
                demonstrative_examples = get_clean_text(de_elem)

            ## observed_examples: Process <Observed_Examples>
            oe_elem = weakness.find(target_path['Observed_Examples'])
            observed_examples = None
            if oe_elem is not None:
                observed_examples = {"observed_example": []}
                for child in oe_elem.findall('{http://cwe.mitre.org/cwe-7}Observed_Example'):
                    ex_dict = {}
                    ref_elem = child.find('./{http://cwe.mitre.org/cwe-7}Reference')
                    if ref_elem is not None:
                        ex_dict["Reference"] = get_clean_text(ref_elem)
                    desc_elem = child.find('./{http://cwe.mitre.org/cwe-7}Description')
                    if desc_elem is not None:
                        ex_dict["Description"] = get_clean_text(desc_elem)
                    link_elem = child.find('./{http://cwe.mitre.org/cwe-7}Link')
                    if link_elem is not None:
                        ex_dict["Link"] = get_clean_text(link_elem)
                    observed_examples["observed_example"].append(ex_dict)
                if not observed_examples["observed_example"]:
                    observed_examples = None

            ## references: Process <References>
            ref_elem = weakness.find(target_path['References'])
            references = None
            if ref_elem is not None:
                references = {"reference": []}
                for child in ref_elem.findall('{http://cwe.mitre.org/cwe-7}Reference'):
                    ref_dict = {}
                    if child.get("External_Reference_ID"):
                        ref_dict["External_Reference_ID"] = child.get("External_Reference_ID")
                    references["reference"].append(ref_dict)
                if not references["reference"]:
                    references = None

            ## mapping_notes: Process <Mapping_Notes>
            mn_elem = weakness.find(target_path['Mapping_Notes'])
            mapping_notes = None
            if mn_elem is not None:
                mapping_notes = {}
                usage_elem = mn_elem.find('./{http://cwe.mitre.org/cwe-7}Usage')
                if usage_elem is not None:
                    mapping_notes["usage"] = get_clean_text(usage_elem)
                rationale_elem = mn_elem.find('./{http://cwe.mitre.org/cwe-7}Rationale')
                if rationale_elem is not None:
                    mapping_notes["rationale"] = get_clean_text(rationale_elem)
                comments_elem = mn_elem.find('./{http://cwe.mitre.org/cwe-7}Comments')
                if comments_elem is not None:
                    mapping_notes["comments"] = get_clean_text(comments_elem)
                reasons_elem = mn_elem.find('./{http://cwe.mitre.org/cwe-7}Reasons')
                if reasons_elem is not None:
                    reasons_list = []
                    for reason in reasons_elem.findall('./{http://cwe.mitre.org/cwe-7}Reason'):
                        if reason.get("Type"):
                            reasons_list.append({"Type": reason.get("Type")})
                    if reasons_list:
                        mapping_notes["reason"] = reasons_list
                if not mapping_notes:
                    mapping_notes = None

            ## time_of_introduction: From Content_History / Submission
            time_of_introduction = None
            ch_elem = weakness.find(target_path['Content_History'])
            if ch_elem is not None:
                sub_elem = ch_elem.find('./{http://cwe.mitre.org/cwe-7}Submission')
                if sub_elem is not None:
                    time_elem = sub_elem.find('./{http://cwe.mitre.org/cwe-7}Submission_Date')
                    if time_elem is not None:
                        time_of_introduction = get_clean_text(time_elem)
            if time_of_introduction:
                time_of_introduction += "T00:00:00"

            ## likelihood_of_exploit:
            loe_elem = weakness.find('./{http://cwe.mitre.org/cwe-7}Likelihood_Of_Exploit')
            likelihood_of_exploit = get_clean_text(loe_elem) if loe_elem is not None else None

            ## related_attack_patterns: Process <Related_Attack_Patterns>
            rap_elem = weakness.find('./{http://cwe.mitre.org/cwe-7}Related_Attack_Patterns')
            related_attack_patterns = None
            if rap_elem is not None:
                related_attack_patterns = {"related_attack_pattern": []}
                for child in rap_elem.findall('{http://cwe.mitre.org/cwe-7}Related_Attack_Pattern'):
                    if child.get("CAPEC_ID"):
                        related_attack_patterns["related_attack_pattern"].append("CAPEC-" + child.get("CAPEC_ID").strip())
                if not related_attack_patterns["related_attack_pattern"]:
                    related_attack_patterns = None

            ## summary: Use description as summary if not separately provided.
            summary = description

            ## background_details: Process <Background_Details>
            # bd_elem = weakness.find('./{http://cwe.mitre.org/cwe-7}Background_Details')
            # background_details = None
            # if bd_elem is not None:
            #     background_details = {"background_detail": []}
            #     for child in bd_elem.findall('{http://cwe.mitre.org/cwe-7}Background_Detail'):
            #         background_details["background_detail"].append(child)
            #     if not background_details["background_detail"]:
            #         background_details = None

            cwe_dict = {
                "id_value": cwe_id,
                "name": name,
                "abstraction": abstraction,
                "structure": structure,
                "status": status,
                "description": description,
                "extended_summary": extended_summary,
                "related_weaknesses": related_weaknesses,
                "applicable_platforms": applicable_platforms,
                "alternative_terms": alternative_terms,
                "modes_of_introduction": modes_of_introduction,
                "common_consequences": common_consequences,
                "detection_methods": detection_methods,
                "potential_mitigations": potential_mitigations,
                "demonstrative_examples": demonstrative_examples,
                "observed_examples": observed_examples,
                "references": references,
                "mapping_notes": mapping_notes,
                "time_of_introduction": time_of_introduction,
                "summary": summary,
                "likelihood_of_exploit": likelihood_of_exploit,
                "related_attack_patterns": related_attack_patterns
                # "background_details": background_details
            }

            cwes['cwes'].append({"cwe": cwe_dict})

    # Debug print
    print(json.dumps(cwes, indent=4, ensure_ascii=False))
    with open("./data/cwe/cwes.json", "w+", encoding="utf-8") as json_file:
        json.dump(cwes, json_file, indent=4, ensure_ascii=False)
        logger.info(">>>>>>>>>>>>>>>>>>>>created cwes.json")

    successfully_mapped = sf.call_mapper_update("cwe")
    if successfully_mapped:
        logger.info("Successfully mapped CWEs to RML mapper")
        sf.call_ontology_updater(reason=True)

    logger.info("############################")
    logger.info("CWE Data extraction completed")
    logger.info("############################\n")