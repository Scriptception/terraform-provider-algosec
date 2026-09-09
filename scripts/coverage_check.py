#!/usr/bin/env python3
"""Offline deterministic catalog and implementation mapping consistency checks."""
import collections
import json
from pathlib import Path
import re
import sys
sys.dont_write_bytecode = True

root = Path(__file__).resolve().parents[1]
d = json.loads((root / 'docs/api-inventory.json').read_text())
pages = d['pages']
assert len({(p['version'], p['page']) for p in pages}) == len(pages) == 204
urls = {p['url'] for p in pages}
for version, count in [('a32.60', 85), ('a33.20', 119)]:
    scoped = [p for p in pages if p['version'] == version]
    assert len(scoped) == count == d['catalogs'][version]['unique_linked_pages_excluding_self']
    assert dict(collections.Counter(p['classification'] for p in scoped)) == d['catalogs'][version]['page_classifications']
    for p in scoped:
        assert f'/en/asms/{version}/asms-help/content/api-guide/' in p['url']
        assert p['url'].endswith('/' + p['page']) and p['reason'] and not p['live_verified']
        assert 'resource_blocks' in p and 'curl_url_evidence' in p
ops = d['implemented_operations']
assert len(ops) == len({(o['method'], o['actual_route_template']) for o in ops}) == 31
assert collections.Counter(o['version_scope'] for o in ops) == {'a32.60': 12, 'a33.20': 10, 'a33.30': 5, 'saas-2026-09-09': 4}
surfaces = set()
for o in ops:
    if o.get('product') in {'AFA tags', 'AFA URL/IP'}:
        assert o['method'] in {'GET','POST','PUT','DELETE'} and not o['live_verified']
        source = (root/o['source_file']).read_text()
        assert o['source_route_expression'] in re.sub(r'\s+', '', source)
        receiver = 'TagClient' if o['product'] == 'AFA tags' else 'URLIPClient'
        start = re.search(r'func \(t \*' + receiver + r'\) ' + o['client_function'] + r'\(',source).start()
        body = source[start:].split('\nfunc ',1)[0]
        if receiver == 'TagClient':
            assert 't.request(ctx, "'+o['method']+'",' in body
            assert '/en/horizon/a33.30/horizon-help/' in o['documentation_url']
        else:
            assert 'method := "DELETE"' in body and 'method = "PUT"' in body and 't.c.do(ctx, method,' in body
            assert '/en/asms/a33.20/asms-help/' in o['documentation_url']
        api = re.search(r'const api = "([^"]+)"',(root/'internal/client/client.go').read_text())[1]
        variables = {'api':api,'categoryPath':api+'/plugins/panorama/URLCategory/','part':'{tagId}','categoryPart':'{category}','urlPart':'{url}'}
        resolved = ''.join(json.loads(token) if token.startswith('"') else variables[token] for token in o['source_route_expression'].split('+'))
        assert resolved == o['actual_route_template']
        surfaces.update(o['surfaces'])
        continue
    if o.get('product') == 'AppViz SaaS':
        assert o['documentation_url'].startswith('https://api-docs.algosec.com/docs/appvizsaas-api-docs/')
        source = (root / o['source_file']).read_text()
        base = re.search(r'const appVizRolePath = "([^"]+)"', source)[1]
        suffix = '/new' if o['client_function'] == 'CreateRole' else ''
        assert o['actual_route_template'] == base + suffix
        assert o['source_route_expression'] in re.sub(r'\s+', '', source)
        start = source.index('func (c *AppVizClient) ' + o['client_function'] + '(')
        body = source[start:].split('\nfunc ', 1)[0]
        assert 'c.request(ctx, "' + o['method'] + '",' in body
        assert o['surfaces'] == ['resource.algosec_appviz_role'] and not o['live_verified']
        surfaces.update(o['surfaces'])
        continue
    assert o['documentation_url'] in urls
    assert f"/asms/{o['version_scope']}/" in o['documentation_url']
    assert o['method'] in {'GET', 'POST', 'PUT', 'DELETE'}
    assert o['actual_route_template'].startswith('/') and o['response_choice']
    source = (root / o['source_file']).read_text()
    assert o['client_function'].split('/')[0] + '(' in source
    # Resolve selected route expressions using source constants and explicit path segments.
    api = re.search(r'const api = "([^"]+)"', (root / 'internal/client/client.go').read_text())[1]
    category_suffix = re.search(r'const categoryPath = api \+ "([^"]+)"', (root / 'internal/client/categories.go').read_text())[1]
    variables = {'api': api, 'categoryPath': api + category_suffix}
    placeholders = re.findall(r'\{[^}]+\}', o['actual_route_template'])
    if placeholders:
        variables.update(part=placeholders[0], p=placeholders[0])
    if o['client_function'].startswith('UpdateDeviceGroup/'):
        variables['step.suffix'] = 'addDevices' if o['method'] == 'POST' else 'removeDevices'
        assert '"' + o['method'] + '", "' + variables['step.suffix'] + '"' in source
    expression = o['source_route_expression']
    assert expression in re.sub(r'\s+', '', source), expression
    function_name = o['client_function'].split('/')[0]
    start = re.search(r'func \(c \*Client\) ' + re.escape(function_name) + r'\(', source).start()
    body = source[start:].split('\nfunc ', 1)[0]
    if function_name in {'NetworkObjects', 'TrustedTraffic'}:
        assert 'paginate(ctx, c,' in body and o['method'] == 'GET'
        assert 'c.do(ctx, "GET", path,' in source
    elif not function_name.startswith('UpdateDeviceGroup'):
        assert re.search(r'c\.(?:do|request)\(ctx, "' + o['method'] + r'",', body)

    resolved = ''.join(json.loads(token) if token.startswith('"') else variables[token]
                       for token in expression.split('+'))
    assert resolved == o['actual_route_template'], (resolved, o['actual_route_template'])
    assert o['surfaces'] and not o['live_verified']
    surfaces.update(o['surfaces'])
expected = {'provider.algosec'}
for kind, folder in [('resource', 'resources'), ('data', 'data-sources')]:
    for file in (root / 'docs' / folder).glob('*.md'):
        expected.add(f'{kind}.algosec_{file.stem}')
assert surfaces == expected, (surfaces ^ expected)
assert len([s for s in surfaces if s.startswith('resource.')]) == 6
assert len([s for s in surfaces if s.startswith('data.')]) == 12
# Verify registration count independently of generated docs.
provider = (root / 'internal/provider/provider.go').read_text()
assert len(re.findall(r'New\w+Resource,?', provider)) == 6
assert len(re.findall(r'New\w+DataSource,?', provider)) == 12
serialized = json.dumps(d)
assert '/home/hermes/' not in serialized and '<html' not in serialized
for page in ['api-import-vuln.htm', 'merging-routers.htm', 'management-device-retrieve.htm', 'afa-ret-parent-obj.htm']:
    assert next(p for p in pages if p['version'] == 'a32.60' and p['page'] == page)['contract_notes']
for p in pages:
    if p['page'] == 'managing-issues.htm':
        assert p['classification'] == 'operational'
        assert 'acknowledge' in p['reason'] and 'activate' in p['reason']

def cell(s):
    return s.replace('|', '&#124;').replace('\n', ' ').replace('\u200b', '[U+200B]')

rendered = ''
for version in d['catalogs']:
    rendered += f'\n### {version.upper()} linked documentation pages\n\n| Page | Literal resource labels | Classification and reason |\n|---|---|---|\n'
    for p in sorted((p for p in pages if p['version'] == version), key=lambda p: p['page']):
        labels = '; '.join('/'.join(b['method_labels']) + ' ' + b['resource_label_text'] for b in p['resource_blocks']) or 'No resource label; see JSON notes'
        rendered += f"| [{cell(p['title'])}]({p['url'].replace(' ', '%20')}) | {cell(labels)} | **{p['classification']}** — {cell(p['reason'])} |\n"
file = root / 'docs/api-coverage.md'
marker = '<!-- BEGIN GENERATED PAGE INVENTORY -->\n'
text = file.read_text()
want = text.split(marker)[0] + marker + rendered
if '--write' in sys.argv:
    file.write_text(want)
else:
    assert text == want, 'Page tables differ: run python3 scripts/coverage_check.py --write'
print('Coverage consistent: 85 + 119 pages; 31 selected method/routes; 6 resources / 12 data sources.')

from operation_inventory import validate
summary = validate(json.loads((root / 'docs/cross-product-operations.json').read_text()), root)
print('Cross-product discovery:', json.dumps(summary, sort_keys=True))
