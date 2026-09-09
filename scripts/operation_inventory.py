"""Offline cross-product evidence ledger validation; raw routes are never normalized."""
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit
import json

DISPOSITIONS = {'implemented', 'evidence_blocked', 'unassessed', 'workflow', 'read_only_deferred', 'helper_deferred'}

def require(ok, message):
    if not ok:
        raise ValueError(message)

def validate(document, root=None):
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

if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1]
    print(json.dumps(validate(json.loads((root / 'docs/cross-product-operations.json').read_text()), root), sort_keys=True))
