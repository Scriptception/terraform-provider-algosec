"""Offline inventory tests. No provider implementation acceptance."""
import importlib.util
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent

class InventoryTests(unittest.TestCase):
    def test_second_review_nominations_supersede_broad_blockers_not_support(self):
        import transform
        result = transform.reconcile(*transform.load_inputs(ROOT / 'inputs'))
        self.assertIn('integration_second_review', result)
        self.assertEqual(len(result['integration_second_review']['nominations']), 9)
        nominated = [o for o in result['operations'] if o['integration']['lifecycle'].get('active_nominations')]
        self.assertEqual(len(nominated), 22)
        self.assertTrue(all(o['integration']['lifecycle']['decision_status'] == 'experimental_candidate_nominated_not_implemented' for o in nominated))
        self.assertTrue(all('historical_source_blockers' in o['integration']['lifecycle'] for o in nominated))
        self.assertEqual(result['integration_counts']['mapped_implementation_claims'], 24)
        self.assertEqual(result['integration_counts']['mapped_new_provisional_claims'], 4)
        self.assertFalse(result['integration_counts']['final_durable_family_closure'])

    def test_same_page_does_not_prove_different_literal_or_version(self):
        import transform
        from copy import deepcopy
        base, native, aliases, provenance, *_ = transform.load_inputs(ROOT / 'inputs')
        identities = transform.SourceIdentity(aliases, provenance)
        row = deepcopy(native['operations'][86])
        row['literal_route'] = '/invented-different-route'
        row['raw_route_labels'] = [row['literal_route']]
        matches, _ = transform.match_row(row, base['operations'], identities)
        self.assertEqual(matches, [])
        row = deepcopy(native['operations'][86])
        row['version'] = 'a33.30'
        matches, _ = transform.match_row(row, base['operations'], identities)
        self.assertEqual(matches, [])

    def test_portable_verifier_rejects_tampering(self):
        self.assertTrue((ROOT / 'verify_inventory.py').exists(), 'missing portable verifier')
        import transform
        import verify_inventory
        from copy import deepcopy
        inputs = transform.load_inputs(ROOT / 'inputs')
        result = transform.reconcile(*inputs)
        checks = verify_inventory.check_document(result, inputs)
        self.assertTrue(all(checks.values()))
        tampered = deepcopy(result)
        tampered['operations'][0]['route'] = '/invented'
        with self.assertRaises(ValueError):
            verify_inventory.check_document(tampered, inputs)

    def test_typed_public_snapshot_provenance(self):
        import transform
        result = transform.reconcile(*transform.load_inputs(ROOT / 'inputs'))
        role = next(o for o in result['operations'] if o['id'] == 'op-76d7c2058e2a188a')
        snapshots = [s for s in role['integration']['source_mapping'] if s['source_type'] == 'cached_public_operation_snapshot_metadata']
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(snapshots[0]['snapshot_id'], 1242088138)
        self.assertEqual(snapshots[0]['branch_node_id'], 413444467)
        self.assertEqual(len(snapshots[0]['snapshot_data_sha256']), 64)
        self.assertFalse(snapshots[0]['payload_equality_verified'])

    def test_hash_only_collapsed_observation_mapping(self):
        import transform
        base, native, aliases, provenance, *_ = transform.load_inputs(ROOT / 'inputs')
        result = transform.reconcile(base, native, aliases, provenance)
        for index, expected in [(155, 'op-cc21d71e12451fd8'), (333, 'op-fec6b6844d3d21da')]:
            observation = result['native_observations'][index]
            self.assertEqual(observation['candidate_ids'], [expected])
            self.assertEqual(observation['mapping_status'], 'resolved')
            self.assertIsNone(observation['literal_route'])
            self.assertEqual(observation['raw_route_labels'], [])
            self.assertEqual(observation['misparsed_label_sha256'], transform.sha(native['operations'][index]['literal_route'].encode()))

    def test_rejects_raw_schema_secret_and_internal_inputs(self):
        import transform
        from copy import deepcopy
        base, native, aliases, provenance, *_ = transform.load_inputs(ROOT / 'inputs')
        for key, value in [('responses', {'200': {'schema': {}}}), ('access_token', 'synthetic-secret'), ('x-internal', True)]:
            with self.subTest(key=key):
                changed = deepcopy(native)
                changed['operations'][0][key] = value
                with self.assertRaises(ValueError):
                    transform.reconcile(base, changed, aliases, provenance)
        changed = deepcopy(base)
        changed['operations'][0]['source_urls'] = ['https://private.example.test/api/internal']
        with self.assertRaises(ValueError):
            transform.reconcile(changed, native, aliases, provenance)

    def test_mapping_totals_equal_enumerated_rows(self):
        import transform
        result = transform.reconcile(*transform.load_inputs(ROOT / 'inputs'))
        actual = sum(any(s['source_type'] == 'native_inventory_observation' for s in o['integration']['source_mapping']) for o in result['operations'])
        self.assertEqual(result['integration_counts']['candidate_with_native_mapping'], actual)
        self.assertEqual(result['integration_counts']['candidate_without_native_mapping'], 975 - actual)

    def test_reconciliation_preserves_accounting_and_provisional_scope(self):
        self.assertTrue((ROOT / 'transform.py').exists(), 'missing reconciliation transform')
        import transform
        base, native, aliases, provenance, *_ = transform.load_inputs(ROOT / 'inputs')
        result = transform.reconcile(base, native, aliases, provenance)
        self.assertEqual(len(result['operations']), 975)
        for original, row in zip(base['operations'], result['operations']):
            self.assertEqual({k: row[k] for k in original}, original)
        claims = [c for row in result['operations'] for c in row['integration']['implementation_claims']]
        self.assertEqual(len(claims), 24)
        self.assertEqual(sum(c['scope'] == 'new_unreleased' for c in claims), 4)
        self.assertTrue(all(c['review_status'] == 'provisional_not_reviewed' for c in claims))
        self.assertFalse(any(row['integration']['implementation_claims'] for row in result['operations'] if row['version'] == 'a33.30'))
        self.assertEqual(result['published_baseline'], base['published_baseline'])

if __name__ == '__main__':
    unittest.main()
