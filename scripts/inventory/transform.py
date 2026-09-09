#!/usr/bin/env python3
"""Offline additive inventory reconciliation; never a provider acceptance gate.

Run: python3 transform.py --inputs inputs --output generated
Input files are frozen sanitized metadata, not contracts or schema exports.
Original fields are immutable; all additions live under integration namespaces.
"""
import argparse
from collections import Counter, defaultdict
from copy import deepcopy
import hashlib
import json
import re
from pathlib import Path
from urllib.parse import urlsplit, urldefrag

PRODUCTS = {'AFA': 'AFA / Horizon Security Analyzer', 'AppViz legacy': 'AppViz',
            'AppViz SaaS': 'AppViz', 'ACE': 'ACE', 'ObjectFlow': 'ObjectFlow', 'FireFlow': 'FireFlow'}
VERSIONS = {'a32.60': 'a32.60', 'a33.20': 'a33.20', 'a33.30': 'a33.30',
            'public saas catalog snapshot 2026-09-09': 'rolling-saas',
            'saas-2026-09-09': 'rolling-saas'}
FILES = ['inventory-candidate.json', 'native-ledger.json', 'url-resolution.json', 'saas-provenance.json', 'second-review-nominations.json']

def sha(data):
    return hashlib.sha256(data).hexdigest()

def digest(obj):
    return sha(json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False).encode())

def require(condition, message):
    if not condition:
        raise ValueError(message)

def load_inputs(folder):
    folder = Path(folder)
    manifest = json.loads((folder / 'manifest.json').read_text())
    for name, info in manifest.items():
        require(Path(name).name == name, 'Unsafe manifest path')
        require(sha((folder / name).read_bytes()) == info['sha256'], 'Input hash mismatch: ' + name)
    verification = json.loads((folder / 'verification.json').read_text())
    for name in ['inventory-candidate.json', 'audit-report.md', 'url-resolution.json', 'saas-provenance.json']:
        require(sha((folder / name).read_bytes()) == verification['files'][name], 'Independent verification hash mismatch: ' + name)
    return tuple(json.loads((folder / name).read_text()) for name in FILES)

class SourceIdentity:
    def __init__(self, aliases, provenance):
        self.redirects = {r['url']: r['resolved_url'] for r in aliases['records'] if r['status'] == 200}
        self.nodes = {}
        self.public = {}
        for node in provenance['public_node_metadata']:
            if node['type'] != 'http_operation':
                continue
            for label in [node['id'], node['slug']]:
                self.nodes[label] = node['id']
            self.public[node['id']] = node

    def key(self, url):
        url = urldefrag(url)[0]
        url = self.redirects.get(url, url)
        parsed = urlsplit(url)
        label = parsed.path.rsplit('/', 1)[-1]
        if parsed.hostname == 'api-docs.algosec.com' and label in self.nodes:
            return ('public_stoplight_operation_id', self.nodes[label])
        return ('official_documentation_url', url)

    def keys(self, urls):
        return {self.key(u) for u in urls}


def match_row(native, operations, identities):
    """No route normalization or version inference; ambiguity stays unresolved."""
    version = VERSIONS.get(native['version'])
    product = PRODUCTS.get(native['product'])
    same_source = identities.keys(native['evidence_urls'])
    possible = [o for o in operations if version == o['version']
                and product in [o['product'], *o['product_associations']]
                and native['protocol'] == o['protocol']
                and same_source & identities.keys(o['source_urls'])]
    if native['protocol'] == 'SOAP':
        possible = [o for o in possible if o['soap']['operation_name_literal'] == native.get('operation_name')]
        basis = 'version_product_source_and_literal_catalog_name_not_wsdl_identity'
    else:
        possible = [o for o in possible if o['method'] == native.get('method')]
        labels = {native.get('literal_route'), *native.get('raw_route_labels', [])} - {None, ''}
        label_hashes = {sha(label.encode()) for label in labels}
        hash_matches = [o for o in possible if label_hashes & set(o.get('misparsed_label_sha256', []))]
        if hash_matches:
            return hash_matches, 'version_product_source_method_and_exact_misparsed_label_sha256_not_executable_route'
        literal = [o for o in possible if labels & ({o['route'], *o['literal_labels']} - {None, ''})]
        if literal:
            possible = literal
            basis = 'version_product_source_method_and_exact_literal_or_selected_route'
        else:
            possible = []
            basis = 'unresolved_no_exact_literal_or_source_match_no_route_repair'
    return possible, basis


BASE_FIELDS = set('blockers classifications family id literal_labels live_acceptance method misparsed_label_sha256 node_ids product product_associations protocol provider_status published_client_functions research_rows route route_basis server_urls snapshot_ids soap source_classifications source_evidence source_urls version version_track'.split())
NATIVE_FIELDS = set('auth availability binding canonical_route catalog_title_route derived_route disposition documented_base documented_request_namespace documented_servers evidence_urls example_routes implementation literal_route live_verified method namespace operation_name operation_qname product protocol raw_route_labels reason retrieved_at service source_node_uri tests version'.split())
FORBIDDEN = set('schema schemas responses requestbody components openapi swagger examples example raw_html raw_xml raw_schema raw_response raw_request access_token refresh_token password secret api_key credentials authorization x-internal internal'.split())

def metadata_only(value):
    if isinstance(value, dict):
        for key, child in value.items():
            require(key.lower() not in FORBIDDEN, 'Forbidden raw/secret/internal field: ' + key)
            metadata_only(child)
    elif isinstance(value, list):
        for child in value:
            metadata_only(child)
    elif isinstance(value, str):
        require(not re.search(r'-----BEGIN [A-Z ]*PRIVATE KEY-----|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|(?:Bearer|Basic) [A-Za-z0-9+/=_-]{24,}', value), 'Credential-like material rejected')
        require('/home/' not in value, 'Private home path rejected')

def public_url(url):
    parsed = urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname in {'techdocs.algosec.com', 'api-docs.algosec.com'}
            and not parsed.username and not parsed.password, 'Evidence must be public official documentation')

def validate_metadata(base, native, aliases, provenance):
    for doc in [base, native, aliases, provenance]:
        metadata_only(doc)
    for o in base['operations']:
        require(set(o) <= BASE_FIELDS, 'Unexpected candidate fields')
        for url in o['source_urls']:
            public_url(url)
        for evidence in o['source_evidence']:
            public_url(evidence['url'])
        require(o['live_acceptance'] == 'not_performed', 'Unexpected live acceptance claim')
        if o['protocol'] == 'SOAP':
            require(all(o['soap'][k] is None for k in ['service', 'port', 'binding', 'operation_qname', 'soap_action', 'endpoint']), 'Unexpected certified SOAP identity')
    for o in native['operations']:
        require(set(o) <= NATIVE_FIELDS, 'Unexpected native fields')
        for url in o['evidence_urls']:
            public_url(url)
        require(o['live_verified'] is False, 'Unexpected native live acceptance')
    for excluded in base['excluded_internal_operations']:
        require(not any(o['version'] == excluded['version'] and o['method'] == excluded['method']
                        and excluded['literal_path'] in o['literal_labels'] for o in base['operations']),
                'Excluded internal operation reintroduced')


def reconcile(base, native, aliases, provenance, nominations=None):
    validate_metadata(base, native, aliases, provenance)
    require(len(base['operations']) == 975, 'Expected 975 accounting identities')
    require(len({r['id'] for r in base['operations']}) == 975, 'Duplicate base IDs')
    identities = SourceIdentity(aliases, provenance)
    result = deepcopy(base)
    result['integration_schema_version'] = 1
    result['integration_policy'] = {
        'scope': 'inventory_only_not_implementation_acceptance',
        'additive_fields': 'All original fields and record order retained exactly; integration fields are additive.',
        'version_aliases': VERSIONS,
        'product_aliases': PRODUCTS,
        'version_alias_meaning': 'SaaS snapshot labels map only to rolling-saas, not to any on-prem version or support claim.',
        'implementation_review': 'Every current-native claim provisional_not_reviewed, including changed baseline code. Published baseline retained separately.',
        'auth': 'Native auth text is attributed, not silently certified. Unknown or conflicting exact mapping remains explicit.',
        'safety': 'Sanitized metadata only; no raw schemas, credentials, internal operation acceptance or appliance requests.',
    }
    result['native_observations'] = []
    defects = []
    matched = defaultdict(list)
    baseline_ids = {i for row in base['published_baseline']['operations'] for i in row['inventory_ids']}
    for index, row in enumerate(native['operations']):
        possible, basis = match_row(row, base['operations'], identities)
        resolved = len(possible) == 1
        observation = {
            'source_type': 'native_inventory_observation', 'source_id': 'native-row-' + str(index),
            'artifact': 'native-ledger.json', 'index': index, 'record_sha256': digest(row),
            'native_product': row['product'], 'native_version': row['version'],
            'protocol': row['protocol'], 'method': row.get('method'),
            'literal_route': row.get('literal_route'), 'raw_route_labels': row.get('raw_route_labels', []),
            'operation_name': row.get('operation_name'), 'evidence_urls': row['evidence_urls'],
            'auth_assertion': row['auth'], 'native_disposition': row['disposition'],
            'native_reason': row['reason'], 'mapping_status': 'resolved' if resolved else 'unresolved',
            'native_contract_metadata': {k: deepcopy(row[k]) for k in ['namespace', 'documented_request_namespace', 'service', 'binding', 'operation_qname', 'source_node_uri', 'documented_servers', 'documented_base', 'derived_route', 'example_routes', 'catalog_title_route'] if k in row},
            'mapping_basis': basis, 'candidate_ids': [o['id'] for o in possible],
        }
        if 'misparsed_label_sha256' in basis:
            observation['misparsed_label_sha256'] = sha(row['literal_route'].encode())
            observation['literal_route'] = None
            observation['raw_route_labels'] = []
            observation['literal_preservation'] = 'Collapsed table retained by exact source hash only, never an executable route.'
        result['native_observations'].append(observation)
        if resolved:
            matched[possible[0]['id']].append((observation, row))
        else:
            defects.append({'kind': 'native_exact_mapping_unresolved', 'source_id': observation['source_id'],
                            'candidate_ids': observation['candidate_ids'],
                            'decision': 'Resolve exact source/version/operation identity; do not choose by similar spelling.',
                            'implemented_claim_affected': row['implementation'] is not None})
    artifact_hashes = {a['artifact']: a['sha256'] for a in base['input_artifacts']}
    for row in result['operations']:
        links = matched.get(row['id'], [])
        assertions = sorted({n['auth'] for _, n in links})
        source_mapping = []
        for r in row['research_rows']:
            if r['artifact'] == 'afa/operations.json':
                array = 'soap_catalog_operations' if row['protocol'] == 'SOAP' else 'rest_literal_operations'
            elif r['artifact'] in {'fireflow-boundaries/operations.json', 'inventory-reconciliation/recovered-operation-rows.json'}:
                array = None
            else:
                array = 'operations'
            pointer = ('/' + array if array else '') + '/' + str(r['index'])
            source_mapping.append({'source_type': 'research_observation', 'source_id': r['artifact'] + '#' + pointer,
                                   'artifact': r['artifact'], 'index': r['index'], 'artifact_sha256': artifact_hashes.get(r['artifact']),
                                   'json_pointer': pointer, 'protocol_boundary': row['protocol'],
                                   'locator_semantics': 'Exact typed source array; AFA REST/SOAP indices are independent, not one combined array.'})
        for evidence in row['source_evidence']:
            kind, identity = identities.key(evidence['url'])
            source = {'source_type': kind, 'source_id': identity, 'evidence': deepcopy(evidence)}
            if kind == 'public_stoplight_operation_id':
                node = identities.public[identity]
                source.update({'branch_node_id': node['branch_node_id'], 'source_node_uri': node['uri'],
                               'branch_id': node['branch_id'], 'project_id': node['project_id'],
                               'metadata_sha256': node['response_sha256'], 'payload_equality_verified': False})
            source_mapping.append(source)
        for snapshot in provenance['cache_nodes']:
            if snapshot['node_id'] in row.get('node_ids', []) and snapshot['snapshot_id'] in row.get('snapshot_ids', []):
                require('/paths/' in snapshot['uri'] and snapshot['matches_public_default_branch_node'], 'Nonpublic/reference snapshot cannot become an operation mapping')
                source_mapping.append({'source_type': 'cached_public_operation_snapshot_metadata',
                                       'source_id': 'snapshot-' + str(snapshot['snapshot_id']),
                                       'branch_node_id': snapshot['node_id'], 'snapshot_id': snapshot['snapshot_id'],
                                       'source_node_uri': snapshot['uri'], 'snapshot_data_sha256': snapshot['snapshot_data_sha256'],
                                       'payload_equality_verified': False})
        source_mapping.extend({'source_type': 'native_inventory_observation', 'source_id': o['source_id'],
                               'mapping_basis': o['mapping_basis']} for o, _ in links)
        families = [{'family': f['family'], 'status': f['status'], 'blocker_and_reopen': f.get('blocker_and_reopen'),
                     'source_urls': f.get('source_urls', [])} for f in base['families'] if row['id'] in f.get('operation_ids', [])]
        auth = {'status': 'attributed_requires_operation_specific_review' if len(assertions) == 1 else ('conflicting' if assertions else 'unresolved_no_exact_native_mapping'),
                'selected_native_assertion': assertions[0] if len(assertions) == 1 else None,
                'assertions': [{'source_id': o['source_id'], 'text': n['auth']} for o, n in links],
                'version_scope': row['version'], 'product_scope': row['product'], 'live_verified': False,
                'credential_values': 'not_collected'}
        if len(assertions) != 1:
            defects.append({'kind': 'auth_conflict' if assertions else 'auth_unresolved', 'operation_id': row['id'],
                            'decision': 'Obtain operation-specific public auth evidence; never inherit credentials or auth across product/version boundaries.'})
        if row['product'] == 'Shared ASMS' or (row['protocol'] == 'REST' and row['product'] == 'AFA / Horizon Security Analyzer' and row.get('route') and not row['route'].startswith(('/afa/api/v1', '/api/v1'))):
            auth['scope_warning'] = 'Generic native AFA auth does not establish auth for this wrapper/service/login. Review operation-specific evidence.'
            defects.append({'kind': 'auth_service_scope_review', 'operation_id': row['id'], 'decision': auth['scope_warning']})
        claims = []
        for observation, n in links:
            if not n['implementation']:
                continue
            claims.append({'source_id': observation['source_id'], 'scope': 'published_baseline_current_native_claim' if row['id'] in baseline_ids else 'new_unreleased',
                           'review_status': 'provisional_not_reviewed', 'support_version_scope': row['version'],
                           'native_version_label': n['version'], 'canonical_route': n['canonical_route'],
                           'implementation': deepcopy(n['implementation']), 'tests_referenced_not_executed': n['tests'],
                           'availability_claim': n.get('availability'), 'contract_choice_claim': n['reason'],
                           'live_verified': False, 'implementation_acceptance': False})
        row['integration'] = {'auth': auth, 'source_mapping': source_mapping,
                              'lifecycle': {'classifications': deepcopy(row['classifications']), 'family_decisions': families,
                                            'complete_managed_lifecycle_certified': False,
                                            'decision_status': 'candidate_or_blocked_not_implementation_acceptance',
                                            'blockers': deepcopy(row['blockers'])},
                              'implementation_claims': claims}
        if not links:
            defects.append({'kind': 'candidate_without_exact_native_mapping', 'operation_id': row['id'],
                            'decision': 'Retain independent identity and evidence; no native auth/implementation transferred.'})
        if row['protocol'] == 'REST' and row['route'] is None:
            defects.append({'kind': 'rest_route_unresolved', 'operation_id': row['id'], 'decision': 'Preserve literal labels; resolve official route/base contradictions before executable use.'})
        if row['protocol'] == 'SOAP':
            defects.append({'kind': 'soap_wsdl_identity_unresolved', 'operation_id': row['id'],
                            'decision': 'Documented request namespace/catalog name is not certified service/port/binding/QName/SOAPAction.'})
    result['integration_defects'] = defects
    claims = [c for o in result['operations'] for c in o['integration']['implementation_claims']]
    surfaces = {s for c in claims for s in c['implementation']['surfaces']}
    result['integration_counts'] = {
        'records': len(result['operations']), 'native_observations': len(native['operations']),
        'native_resolved': sum(o['mapping_status'] == 'resolved' for o in result['native_observations']),
        'native_unresolved': sum(o['mapping_status'] == 'unresolved' for o in result['native_observations']),
        'candidate_with_native_mapping': len(matched), 'candidate_without_native_mapping': len(result['operations']) - len(matched),
        'native_implemented_claims': sum(bool(o['implementation']) for o in native['operations']),
        'mapped_implementation_claims': len(claims),
        'mapped_published_baseline_claims': sum(c['scope'] == 'published_baseline_current_native_claim' for c in claims),
        'mapped_new_provisional_claims': sum(c['scope'] == 'new_unreleased' for c in claims),
        'mapped_claimed_resources': sum(s.startswith('resource.') for s in surfaces),
        'mapped_claimed_data_sources': sum(s.startswith('data.') for s in surfaces),
        'auth_status': dict(sorted(Counter(o['integration']['auth']['status'] for o in result['operations']).items())),
        'defects_by_kind': dict(sorted(Counter(d['kind'] for d in defects).items())),
        'defect_entries_nonexclusive': len(defects),
        'accepted_internal_operations': 0, 'implementation_acceptance_checks': 0,
    }
    result['integration_counts']['final_durable_family_closure'] = False
    if nominations is not None:
        metadata_only(nominations)
        result['integration_second_review'] = deepcopy(nominations)
        result['integration_policy']['decision_precedence'] = 'Original families/blockers/provider_status are frozen historical audit evidence. Current lifecycle active_nominations supersede blanket blockers only for their precise subset; no nomination is implemented acceptance. Final durable-family closure remains unfinished.'
        lookup = {o['id']: o for o in result['operations']}
        nominated_ids = set()
        for nomination in nominations['nominations']:
            require(nomination['status'] == 'experimental_candidate_nominated_not_implemented', 'Nomination cannot accept implementation')
            for selector in nomination['operation_selectors']:
                row = lookup.get(selector['id'])
                require(row is not None and all(row[k] == v for k, v in selector.items()), 'Unresolvable second-review exact selector: ' + selector['id'])
                require(row['version'] == nomination['version_scope'], 'Nomination version mismatch')
                lifecycle = row['integration']['lifecycle']
                if not lifecycle.get('active_nominations'):
                    lifecycle['historical_source_blockers'] = lifecycle.pop('blockers')
                    lifecycle['historical_family_decisions'] = lifecycle.pop('family_decisions')
                lifecycle['decision_status'] = nomination['status']
                lifecycle.setdefault('active_nominations', []).append(nomination['nomination_id'])
                lifecycle.setdefault('remaining_acceptance_requirements', []).extend(nomination['remaining_acceptance_requirements'])
                lifecycle.setdefault('broader_scope_not_solved', []).append(nomination['broader_scope_not_solved'])
                row['integration']['source_mapping'].append({'source_type': 'second_review_nomination', 'source_id': nomination['nomination_id'], 'report_artifact': nomination['report_artifact'], 'mapping_basis': 'exact_candidate_id_product_version_protocol_method_route_source_urls; subset nomination only'})
                nominated_ids.add(row['id'])
        result['integration_counts']['second_review_nominations'] = len(nominations['nominations'])
        result['integration_counts']['second_review_unique_operation_records'] = len(nominated_ids)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    inputs = args.inputs.resolve()
    output = args.output.resolve()
    require(output != inputs and inputs not in output.parents, 'Output cannot be inside inputs')
    require(not (output / 'cross-product-operations.json').exists(), 'Refuse overwrite existing output')
    require('terraform-provider-algosec' not in output.parts, 'No canonical checkout writes')
    data = load_inputs(inputs)
    result = reconcile(*data)
    output.mkdir(parents=True, exist_ok=True)
    files = {'cross-product-operations.json': result,
             'mapping-defects.json': {'counts': result['integration_counts'], 'defects': result['integration_defects'],
                                      'unresolved_native_observations': [o for o in result['native_observations'] if o['mapping_status'] != 'resolved']}}
    for name, doc in files.items():
        with (output / name).open('x') as stream:
            json.dump(doc, stream, indent=2, ensure_ascii=False)
            stream.write('\n')
    print(json.dumps(result['integration_counts'], indent=2))

if __name__ == '__main__':
    main()
