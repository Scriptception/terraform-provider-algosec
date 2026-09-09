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
