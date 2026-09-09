"""Synthetic catalog-integrity regressions; no network access."""
import copy
import unittest
from operation_inventory import validate

class InventoryTests(unittest.TestCase):
    def row(self):
        return {'product':'Synthetic','version':'v1','protocol':'REST','method':'GET',
                'literal_route':'/objects','canonical_route':None,'evidence_urls':['https://techdocs.algosec.com/synthetic'],
                'disposition':'unassessed','reason':'Needs lifecycle review','auth':'unknown',
                'retrieved_at':'2026-09-09','implementation':None,'tests':[], 'live_verified':False}
    def test_duplicate(self):
        row=self.row()
        with self.assertRaises(ValueError): validate({'operations':[row,copy.deepcopy(row)]})
    def test_no_evidence(self):
        row=self.row();row['evidence_urls']=[]
        with self.assertRaises(ValueError):validate({'operations':[row]})
    def test_unresolved_soap_is_not_rest(self):
        row=self.row();row.update(protocol='SOAP',service=None,binding=None,operation_qname=None,operation_name='Create',namespace=None)
        row.pop('method');row.pop('literal_route')
        result=validate({'operations':[row]});self.assertEqual(result['unresolved_soap'],1)
    def test_fake_implemented(self):
        row=self.row();row['disposition']='implemented'
        with self.assertRaises(ValueError):validate({'operations':[row]})
    def test_preserve_literal(self):
        a=self.row();b=self.row();b['literal_route']='/objects/'
        self.assertEqual(validate({'operations':[a,b]})['rest_operations'],2)

if __name__=='__main__':unittest.main()

class ReconciledInventoryTests(unittest.TestCase):
    def test_current_mapping_and_source_accounting(self):
        import json
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        doc = json.loads((root/'docs/cross-product-operations.json').read_text())
        result = validate(doc, root)
        self.assertEqual(result['input_observations'], sum(len(o['research_rows']) for o in doc['operations']))
        self.assertEqual(result['implemented_operations'], len(json.loads((root/'docs/api-inventory.json').read_text())['implemented_operations']))
        for mutation in ['drop_source', 'drop_mapping', 'wrong_version', 'invent_function']:
            with self.subTest(mutation=mutation):
                bad = copy.deepcopy(doc)
                if mutation == 'drop_source': bad['operations'][0]['research_rows'].pop()
                if mutation == 'drop_mapping': bad['current_implementation'].pop()
                if mutation == 'wrong_version': bad['current_implementation'][-1]['version_scope'] = 'a32.60'
                if mutation == 'invent_function': bad['current_implementation'][-1]['client_function'] = 'Invented'
                with self.assertRaises(ValueError): validate(bad, root)

    def test_consistently_wrong_route_rejected(self):
        import json, shutil, subprocess, sys, tempfile
        from pathlib import Path
        from operation_inventory import current_mappings
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix='algosec-route-regression-') as directory:
            target = Path(directory)
            for folder in ['scripts', 'docs', 'internal']:
                shutil.copytree(root/folder, target/folder)
            api_path = target/'docs/api-inventory.json'
            overlay_path = target/'docs/cross-product-operations.json'
            api = json.loads(api_path.read_text())
            overlay = json.loads(overlay_path.read_text())
            rename = next(o for o in api['implemented_operations'] if o.get('product') == 'AFA tags' and o['client_function'] == 'Rename')
            delete = next(o for o in api['implemented_operations'] if o.get('product') == 'AFA tags' and o['client_function'] == 'Delete')
            rename['actual_route_template'] = delete['actual_route_template']
            rename['source_route_expression'] = delete['source_route_expression']
            api_path.write_text(json.dumps(api))
            overlay['current_implementation'] = current_mappings(overlay, api)
            overlay_path.write_text(json.dumps(overlay))
            result = subprocess.run([sys.executable, '-B', 'scripts/coverage_check.py'], cwd=target, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, 'A consistently incorrect route and regenerated overlay passed')

    def test_ace_method_binding_rejected(self):
        import shutil, subprocess, sys, tempfile
        from pathlib import Path
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory(prefix='algosec-ace-method-regression-') as directory:
            target = Path(directory)
            for folder in ['scripts', 'docs', 'internal']:
                shutil.copytree(root/folder, target/folder)
            source_path = target/'internal/client/ace_jira.go'
            source = source_path.read_text()
            source_path.write_text(source.replace('c.request(ctx, "DELETE", aceJiraPath', 'c.request(ctx, "POST", aceJiraPath', 1))
            result = subprocess.run([sys.executable, '-B', 'scripts/coverage_check.py'], cwd=target, capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0, 'A changed ACE HTTP method passed coverage validation')
