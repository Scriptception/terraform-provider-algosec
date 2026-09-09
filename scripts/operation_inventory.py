"""Offline cross-product evidence ledger validation; raw routes are never normalized."""
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit
import json

DISPOSITIONS = {'implemented', 'evidence_blocked', 'unassessed', 'workflow', 'read_only_deferred', 'helper_deferred'}

def require(ok, message):
    if not ok:
        raise ValueError(message)

def validate_legacy(document, root=None):
    operations = document['operations']
    seen = set()
    counts = Counter()
    for row in operations:
        require(row.get('product') and row.get('version'), 'Missing product/version')
        require(row.get('disposition') in DISPOSITIONS and row.get('reason'), 'Missing disposition/reason')
        require(row.get('auth') and row.get('retrieved_at'), 'Missing auth/retrieval boundary')
        require(row.get('live_verified') is False, 'No live evidence in this inventory')
        require(row.get('evidence_urls'), 'Missing evidence')
        for url in row['evidence_urls']:
            parsed = urlsplit(url)
            require(parsed.scheme == 'https' and parsed.hostname in {'techdocs.algosec.com', 'api-docs.algosec.com'}, 'Evidence must be official public HTTPS documentation')
        if row['protocol'] == 'REST':
            require(row.get('method') in {'GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'}, 'Invalid HTTP method')
            require(isinstance(row.get('literal_route'), str) and row['literal_route'], 'Missing literal route')
            key = (row['product'], row['version'], 'REST', row['method'], row['literal_route'])
            counts['rest_operations'] += 1
        elif row['protocol'] == 'SOAP':
            qname = row.get('operation_qname')
            if qname:
                require(qname.startswith('{') and '}' in qname and row.get('namespace') == qname[1:].split('}')[0], 'Invalid SOAP QName namespace')
            else:
                require(row.get('namespace') is None and row.get('operation_name'), 'Unresolved SOAP namespace must not be guessed')
            if not qname or not row.get('binding') or not row.get('service'):
                counts['unresolved_soap'] += 1
            else:
                counts['resolved_soap'] += 1
            key = (row['product'], row['version'], 'SOAP', row.get('service'), row.get('binding'), qname or ('unresolved:' + row['operation_name']))
        else:
            raise ValueError('Invalid protocol')
        require(key not in seen, 'Duplicate operation key: ' + str(key))
        seen.add(key)
        counts[row['disposition']] += 1
        if row['disposition'] == 'implemented':
            mapping = row.get('implementation')
            require(mapping and row.get('canonical_route') and row.get('tests'), 'Implemented operation requires canonical route, mapping and tests')
            require(mapping.get('surfaces') and mapping.get('client_function'), 'Missing implementation surface/function')
            if root:
                for filename in [mapping['source_file'], *row['tests']]:
                    p = Path(filename)
                    require(not p.is_absolute() and '..' not in p.parts and (root / p).is_file(), 'Invalid implementation/test path')
                source = (root / mapping['source_file']).read_text()
                require(mapping['client_function'].split('/')[0] + '(' in source, 'Missing mapped client function')
        else:
            require(row.get('implementation') is None and row.get('canonical_route') is None, 'Unimplemented operation has a selected implementation')
    counts['records'] = len(operations)
    return dict(counts)


# The frozen reconciliation is reproduced byte-for-byte as metadata. Current
# implementation is a separate additive overlay, never a rewrite of source labels.
import sys
sys.path.insert(0, str(Path(__file__).resolve().parent / 'inventory'))
from transform import load_inputs, SourceIdentity, VERSIONS, metadata_only
from verify_inventory import check_document

def current_mappings(document, api_inventory):
    inputs = load_inputs(Path(__file__).resolve().parent / 'inventory' / 'inputs')
    identity = SourceIdentity(inputs[2], inputs[3])
    result = []
    for op in api_inventory['implemented_operations']:
        version = VERSIONS[op['version_scope']]
        candidates = []
        tests = []
        for row in document['operations']:
            if row['protocol'] != 'REST' or row['version'] != version or row['method'] != op['method']:
                continue
            for claim in row['integration']['implementation_claims']:
                if claim['canonical_route'] == op['actual_route_template'] and claim['implementation']['client_function'] == op['client_function']:
                    candidates.append(row['id'])
                    tests.extend(claim['tests_referenced_not_executed'])
            if not row['integration']['implementation_claims'] and identity.key(op['documentation_url']) in {identity.key(u) for u in row['source_urls']}:
                candidates.append(row['id'])
        require(len(set(candidates)) == 1, 'Ambiguous or absent exact operation mapping: ' + str(op))
        if op.get('product') == 'AFA tags': tests = ['internal/client/tags_test.go', 'internal/provider/tag_test.go', 'internal/provider/tag_url_recovery_test.go']
        if op.get('product') == 'AFA URL/IP': tests = ['internal/client/url_ip_test.go', 'internal/provider/url_ip_test.go', 'internal/provider/tag_url_recovery_test.go']
        if 'resource.algosec_url_ip_membership' in op['surfaces']:
            tests.append('internal/provider/url_ip_test.go')
        result.append({'candidate_id': candidates[0], **op, 'tests': sorted(set(tests)), 'independent_final_review': 'pending', 'live_verified': False})
    return result

def validate(document, root=None):
    if 'integration_schema_version' not in document:
        return validate_legacy(document, root)
    root = Path(root) if root else Path(__file__).resolve().parents[1]
    frozen = {k:v for k,v in document.items() if k != 'current_implementation'}
    inputs = load_inputs(Path(__file__).resolve().parent / 'inventory' / 'inputs')
    check_document(frozen, inputs)
    require('current_implementation' in document, 'Missing current implementation mappings')
    actual = document['current_implementation']
    expected = current_mappings(document, json.loads((root / 'docs/api-inventory.json').read_text()))
    require(actual == expected, 'Current implementation mappings differ from exact source inventory')
    require(len({(o['method'],o['actual_route_template']) for o in actual}) == len(actual), 'Duplicate executable operation')
    for op in actual:
        require(op['tests'] and op['surfaces'] and not op['live_verified'], 'Missing test/surface boundary')
        for filename in [op['source_file'], *op['tests']]:
            p = Path(filename)
            require(not p.is_absolute() and '..' not in p.parts and (root/p).is_file(), 'Invalid mapped file')
        require(op['client_function'].split('/')[0]+'(' in (root/op['source_file']).read_text(), 'Missing client function')
    metadata_only(document)
    surfaces = {s for o in actual for s in o['surfaces']}
    rows = document['operations']
    return {'records':len(rows), 'input_observations':sum(len(o['research_rows']) for o in rows),
            'selected_rest':sum(o['protocol']=='REST' and o['route'] is not None for o in rows),
            'unresolved_rest':sum(o['protocol']=='REST' and o['route'] is None for o in rows),
            'unresolved_soap':sum(o['protocol']=='SOAP' for o in rows),
            'implemented_operations':len(actual),
            'resources':sum(s.startswith('resource.') for s in surfaces),
            'data_sources':sum(s.startswith('data.') for s in surfaces)}

if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1]
    file = root / 'docs/cross-product-operations.json'
    document = json.loads(file.read_text())
    if '--write' in sys.argv:
        document['current_implementation'] = current_mappings(document, json.loads((root/'docs/api-inventory.json').read_text()))
        file.write_text(json.dumps(document,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps(validate(document,root),sort_keys=True))
