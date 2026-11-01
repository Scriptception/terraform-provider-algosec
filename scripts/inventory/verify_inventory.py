#!/usr/bin/env python3
"""Validate reconciliation invariants independently; inventory only, offline."""
import argparse
from collections import Counter
import json
from pathlib import Path
from transform import load_inputs, reconcile, require, metadata_only, sha


def check_document(document, inputs):
    base, native, aliases, provenance = inputs[:4]
    rows = document['operations']
    checks = {}
    def check(name, value):
        require(value, name)
        checks[name] = True
    check('975_unique_ordered_identities', len(rows) == 975 and [o['id'] for o in rows] == [o['id'] for o in base['operations']] and len({o['id'] for o in rows}) == 975)
    check('every_original_operation_field_unchanged', all({k: row[k] for k in old} == old for old, row in zip(base['operations'], rows)))
    check('every_original_top_level_field_unchanged_except_additive_operations', all(document[k] == v for k, v in base.items() if k != 'operations'))
    observations = [(s['artifact'], s['index']) for row in rows for s in row['research_rows']]
    typed = [s['source_id'] for o in rows for s in o['integration']['source_mapping'] if s['source_type'] == 'research_observation']
    check('1048_typed_source_observations_preserved', len(observations) == 1048 and len(typed) == 1048 and len(set(typed)) == 1048)
    check('research_artifacts_all_have_typed_hash_mappings', all(s.get('artifact_sha256') and len(s['artifact_sha256']) == 64 for o in rows for s in o['integration']['source_mapping'] if s['source_type'] == 'research_observation'))
    check('747_selected_rest_66_unresolved_rest_162_unresolved_soap', Counter('soap' if o['protocol'] == 'SOAP' else ('rest_selected' if o['route'] else 'rest_unresolved') for o in rows) == {'soap': 162, 'rest_selected': 747, 'rest_unresolved': 66})
    check('zero_certified_soap_qnames', all(o['soap']['operation_qname'] is None and o['soap']['service'] is None and o['soap']['binding'] is None for o in rows if o['protocol'] == 'SOAP'))
    native_links = [o for o in document['native_observations'] if o['mapping_status'] == 'resolved']
    check('native_rows_accounted_once', len(document['native_observations']) == len(native['operations']) and [o['index'] for o in document['native_observations']] == list(range(len(native['operations']))))
    mapped = {i for link in native_links for i in link['candidate_ids']}
    check('enumerated_mapping_totals_match', len(mapped) == document['integration_counts']['candidate_with_native_mapping'] and len(rows)-len(mapped) == document['integration_counts']['candidate_without_native_mapping'])
    claims = [c for o in rows for c in o['integration']['implementation_claims']]
    check('24_claims_20_baseline_4_new', len(claims) == 24 and Counter(c['scope'] for c in claims) == {'published_baseline_current_native_claim': 20, 'new_unreleased': 4})
    check('all_current_native_claims_provisional_not_reviewed', all(c['review_status'] == 'provisional_not_reviewed' and c['implementation_acceptance'] is False for c in claims))
    check('no_implementation_transferred_to_a33_30', not any(o['integration']['implementation_claims'] for o in rows if o['version'] == 'a33.30'))
    check('every_auth_and_lifecycle_boundary_explicit', all(o['integration']['auth']['status'] and o['integration']['lifecycle']['classifications'] and not o['integration']['lifecycle']['complete_managed_lifecycle_certified'] for o in rows))
    check('no_live_acceptance_claimed', all(o['live_acceptance'] == 'not_performed' and not o['integration']['auth']['live_verified'] for o in rows))
    check('seven_internal_exclusions_retained_not_accepted', len(document['excluded_internal_operations']) == 7 and document['integration_counts']['accepted_internal_operations'] == 0)
    metadata_only(document)
    check('metadata_only_no_raw_schema_secret_fields_or_private_home_paths', True)
    check('misparsed_tables_hash_only_in_integrated_payload', all(o['literal_route'] is None and not o['raw_route_labels'] for o in document['native_observations'] if o.get('misparsed_label_sha256')))
    check('defect_totals_match_enumeration', dict(Counter(d['kind'] for d in document['integration_defects'])) == document['integration_counts']['defects_by_kind'])
    check('deterministic_transform_reproduction', document == reconcile(*inputs))
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inputs', type=Path, required=True)
    parser.add_argument('--inventory', type=Path, required=True)
    args = parser.parse_args()
    document = json.loads(args.inventory.read_text())
    checks = check_document(document, load_inputs(args.inputs))
    print(json.dumps({'scope': 'inventory_only_not_implementation_acceptance', 'checks': checks,
                      'counts': document['integration_counts'],
                      'inventory_sha256': sha(args.inventory.read_bytes()),
                      'frozen_inputs': json.loads((args.inputs / 'manifest.json').read_text())}, indent=2))

if __name__ == '__main__':
    main()
