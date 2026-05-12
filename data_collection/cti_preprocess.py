import json
import os
import logging
import requests

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('cti_preprocess')

# GitHub raw URLs for STIX bundle files
STIX_DOWNLOADS = {
    'enterprise-attack.json': 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json',
    'mobile-attack.json':     'https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json',
    'ics-attack.json':        'https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json',
    'pre-attack.json':        'https://raw.githubusercontent.com/mitre/cti/master/pre-attack/pre-attack.json',
    'stix-capec.json':        'https://raw.githubusercontent.com/mitre/cti/master/capec/2.1/stix-capec.json',
}

CTI_DIR = './data/cti'

# ATT&CK bundles used for relationship preprocessing (not CAPEC)
ATTACK_BUNDLE_NAMES = [
    'enterprise-attack.json',
    'mobile-attack.json',
    'ics-attack.json',
]

# Map STIX object types to the type labels used in relationships.json
STIX_TYPE_TO_LABEL = {
    'attack-pattern': 'technique',
    'course-of-action': 'mitigation',
    'intrusion-set': 'group',
    'campaign': 'campaign',
    'malware': 'software',
    'tool': 'software',
    'x-mitre-tactic': 'tactic',
}

OUTPUT_DIR = './data/attack'
OUTPUT_FILE = os.path.join(OUTPUT_DIR, 'relationships.json')


def download_stix_bundles():
    """Download all STIX bundle files from the MITRE CTI GitHub repository."""
    os.makedirs(CTI_DIR, exist_ok=True)

    for filename, url in STIX_DOWNLOADS.items():
        dest = os.path.join(CTI_DIR, filename)
        logger.info(f"Downloading {filename} ...")
        try:
            resp = requests.get(url, timeout=120)
            resp.raise_for_status()
            with open(dest, 'w', encoding='utf-8') as f:
                f.write(resp.text)
            logger.info(f"  Saved to {dest} ({len(resp.content)} bytes)")
        except requests.RequestException as e:
            logger.error(f"  Failed to download {filename}: {e}")
            raise


def get_mitre_id(obj):
    """Extract the MITRE external ID (e.g. T1055.011, M1234, G0001) from a STIX object."""
    for ref in obj.get('external_references', []):
        if ref.get('source_name') == 'mitre-attack':
            return ref.get('external_id')
    return None


def build_lookup(bundle_data):
    """Build UUID → (mitre_id, stix_type) lookup from a STIX bundle."""
    lookup = {}
    for obj in bundle_data.get('objects', []):
        stix_type = obj.get('type')
        if stix_type not in STIX_TYPE_TO_LABEL:
            continue
        mitre_id = get_mitre_id(obj)
        if mitre_id:
            lookup[obj['id']] = (mitre_id, STIX_TYPE_TO_LABEL[stix_type])
    return lookup


def preprocess_relationships():
    """Read downloaded STIX bundles, resolve relationship UUIDs, output relationships.json.

    Two relationship sources are merged:
      1. STIX `relationship` objects (uses / mitigates / attributed-to / subtechnique-of).
      2. Technique → Tactic links derived from each attack-pattern's `kill_chain_phases`,
         joined to x-mitre-tactic objects via phase_name == x_mitre_shortname.
    """

    uuid_lookup = {}
    all_relationships = []
    # Per-bundle: shortname -> (TA_id, tactic_uuid) to resolve technique kill_chain_phases
    tactic_lookups = []
    # Collect all technique objects per-bundle so we can emit kill_chain edges
    technique_lists = []

    for bundle_name in ATTACK_BUNDLE_NAMES:
        bundle_path = os.path.join(CTI_DIR, bundle_name)
        if not os.path.exists(bundle_path):
            logger.warning(f"Bundle not found: {bundle_path}")
            continue

        logger.info(f"Reading {bundle_path}")
        with open(bundle_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        uuid_lookup.update(build_lookup(data))

        # Build shortname -> (TA_id, uuid) lookup from x-mitre-tactic objects (this bundle only)
        tactic_lookup = {}
        techniques = []
        for obj in data.get('objects', []):
            if obj.get('x_mitre_deprecated', False) or obj.get('revoked', False):
                continue
            otype = obj.get('type')
            if otype == 'x-mitre-tactic':
                shortname = obj.get('x_mitre_shortname')
                ta_id = get_mitre_id(obj)
                if shortname and ta_id:
                    tactic_lookup[shortname] = (ta_id, obj['id'])
            elif otype == 'attack-pattern':
                techniques.append(obj)
        tactic_lookups.append(tactic_lookup)
        technique_lists.append(techniques)

        for obj in data.get('objects', []):
            if obj.get('type') != 'relationship':
                continue
            if obj.get('x_mitre_deprecated', False) or obj.get('revoked', False):
                continue
            rel_type = obj.get('relationship_type')
            if rel_type not in ('uses', 'mitigates', 'attributed-to', 'subtechnique-of'):
                continue
            all_relationships.append(obj)

    resolved = []
    skipped = 0

    for rel in all_relationships:
        source_ref = rel['source_ref']
        target_ref = rel['target_ref']

        source_info = uuid_lookup.get(source_ref)
        target_info = uuid_lookup.get(target_ref)

        if not source_info or not target_info:
            skipped += 1
            continue

        source_id, source_type = source_info
        target_id, target_type = target_info

        resolved.append({
            'source ID': source_id,
            'source type': source_type,
            'target ID': target_id,
            'target type': target_type,
            'source_ref': source_ref,
            'target_ref': target_ref,
            'relationship_type': rel['relationship_type'],
        })

    # Synthesize Technique -> Tactic edges from kill_chain_phases (per-bundle scope)
    tactic_edges = 0
    tactic_unresolved = 0
    for tactic_lookup, techniques in zip(tactic_lookups, technique_lists):
        for tech in techniques:
            t_id = get_mitre_id(tech)
            if not t_id:
                continue
            for kcp in tech.get('kill_chain_phases', []):
                phase = kcp.get('phase_name')
                tactic_entry = tactic_lookup.get(phase)
                if not tactic_entry:
                    tactic_unresolved += 1
                    continue
                ta_id, ta_uuid = tactic_entry
                resolved.append({
                    'source ID': t_id,
                    'source type': 'technique',
                    'target ID': ta_id,
                    'target type': 'tactic',
                    'source_ref': tech['id'],
                    'target_ref': ta_uuid,
                    'relationship_type': 'achieves',
                })
                tactic_edges += 1

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        json.dump(resolved, f, indent=2)

    logger.info(
        f"Wrote {len(resolved)} relationships to {OUTPUT_FILE} "
        f"(STIX skipped {skipped} unresolvable; "
        f"technique->tactic edges {tactic_edges}, unresolved phase_name {tactic_unresolved})"
    )


if __name__ == '__main__':
    download_stix_bundles()
    preprocess_relationships()
