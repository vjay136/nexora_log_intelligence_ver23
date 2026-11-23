#!/usr/bin/env python3
"""Produce a finite source/DOM verification inventory; never imply a click occurred."""
import argparse
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def line(text, index):
    return text.count('\n', 0, index) + 1


def section(text, name, following):
    return text[text.index(name):text.index(following, text.index(name))]


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--browser-inventory', required=True, type=Path)
    cli.add_argument('--output', required=True, type=Path)
    args = cli.parse_args()
    browser = json.loads(args.browser_inventory.read_text(encoding='utf-8'))
    app_path = ROOT / 'web/app.js'
    app = app_path.read_text(encoding='utf-8')
    sources = {name: (ROOT / name).read_text(encoding='utf-8') for name in ['web/app.js', 'web/ai-guidance.js', 'web/design-engine.js']}
    nav = section(app, '  const NAV = [', '  const TITLES =')
    routes = [dict(zip(['section', 'id', 'title'], match.groups())) for match in re.finditer(r"\['([^']+)', '([^']+)', '([^']+)'", nav)]
    assert len(routes) == 57 and {route['id'] for route in routes} == set(browser['routes'])
    assert browser['checks']['browser_exceptions'] == []
    assert browser['checks']['unexpected_http_5xx'] == []
    loaders = section(app, '  const LOADERS = {', '  async function submit(')
    action_handler = section(app, '  async function action(button)', '  function downloadJSON(')
    submit_handler = section(app, '  async function submit(form)', '  async function action(button)')
    switch_actions = set(re.findall(r"case ['\"]([a-z][a-z0-9-]*)['\"]", action_handler))
    submit_forms = set(re.findall(r"case ['\"]([a-z][a-z0-9-]*)['\"]", submit_handler))
    native_submit = {'client-action-request': 'client-action-form', 'client-directory-save-name': 'client-display-form', 'client-directory-save-group': 'client-group-form'}
    local_listener = {'known-key-bulk-preview': 'setupKnownKeyImport', 'known-key-bulk-reset': 'setupKnownKeyImport', 'parser-helper-generate': 'dedicated page click listener', 'parser-helper-validate': 'early branch in action(button)'}
    declared = defaultdict(list)
    dynamic_attributes = []
    for filename, source in sources.items():
        for match in re.finditer(r'data-action=[\"\']([a-z][a-z0-9-]*)[\"\']', source):
            declared[match.group(1)].append({'file': filename, 'line': line(source, match.start()), 'kind': 'literal data-action attribute'})
        for match in re.finditer(r"dataset\.action\s*=(?!=)\s*['\"]([a-z][a-z0-9-]*)['\"]", source):
            declared[match.group(1)].append({'file': filename, 'line': line(source, match.start()), 'kind': 'programmatic literal data-action assignment'})
        for match in re.finditer(r'data-action=[\"\'](\$\{[^\n]{1,180}?\})', source):
            dynamic_attributes.append({'file': filename, 'line': line(source, match.start()), 'expression': match.group(1), 'status': 'Dynamic expression; source scan does not enumerate every possible value.'})
    observed = defaultdict(set)
    route_views = defaultdict(list)
    for view in browser['views']:
        route_views[view['workspace']].append(view)
        for action in view['actions']:
            observed[action['id']].add(view['workspace'])
    observed_ids = set(observed)
    source_ids = set(declared)
    tests = []
    for path in [ROOT / 'web/ui.spec.js', ROOT / 'web/e2e.spec.js', *sorted((ROOT / 'tests').glob('*.test.js'))]:
        source = path.read_text(encoding='utf-8')
        matches = list(re.finditer(r"\btest\(\s*(['\"])([^\n]+?)\1", source))
        for index, match in enumerate(matches):
            body = source[match.start():matches[index + 1].start() if index + 1 < len(matches) else len(source)]
            tests.append({'file': path.relative_to(ROOT).as_posix(), 'line': line(source, match.start()), 'name': match.group(2), 'body': body})
    critical_workflows = {
        'policy-run-filter': 'R9 selective input previews exact raw before separate parse and resets',
        'policy-parse-matched': 'R9 selective input previews exact raw before separate parse and resets',
        'policy-run-output': 'R9 output field preview removes exact root names after parsing and resets',
        'known-key-bulk-preview': 'R9 known-key bulk import previews 1500 keys, imports file, rejects invalid entries and resets',
        'known-key-bulk-reset': 'R9 known-key bulk import previews 1500 keys, imports file, rejects invalid entries and resets',
        'client-directory-save-name': 'R9 client names and 1005-member groups retain IDs, freeze exact targets and require normal action approval',
        'client-directory-save-group': 'R9 client names and 1005-member groups retain IDs, freeze exact targets and require normal action approval',
        'client-directory-delete-group': 'R9 client names and 1005-member groups retain IDs, freeze exact targets and require normal action approval',
        'client-group-preview': 'R9 client names and 1005-member groups retain IDs, freeze exact targets and require normal action approval',
        'client-action-request': 'R9 client names and 1005-member groups retain IDs, freeze exact targets and require normal action approval',
    }
    actions = []
    unresolved = []
    for action_id in sorted(set(declared) | set(observed)):
        if action_id in native_submit:
            handler = {'kind': 'native form submission', 'form_id': native_submit[action_id], 'form_switch_case_exists': native_submit[action_id] in submit_forms}
        elif action_id in local_listener:
            handler = {'kind': 'dedicated listener / early handler branch', 'location': local_listener[action_id]}
        elif action_id in switch_actions:
            handler = {'kind': 'action(button) switch case', 'file': 'web/app.js', 'line': line(app, app.index("case '" + action_id + "'", app.index('  async function action(button)')))}
        else:
            handler = {'kind': 'not resolved by this finite scan'}
            unresolved.append(action_id)
        references = [{key: test[key] for key in ['file', 'line', 'name']} for test in tests if action_id in test['body']]
        actions.append({'id': action_id, 'declarations': declared.get(action_id, []), 'observed_in_navigation_fixture': action_id in observed_ids,
                        'observed_on_routes': sorted(observed.get(action_id, set())), 'source_handler': handler,
                        'test_source_references': references,
                        'navigation_walk_operation_status': 'Inventoried only; this audit does not click or mutate this action.',
                        'explicit_separately_exercised_r9_workflow': critical_workflows.get(action_id),
                        'coverage_note': 'A source test reference is not proof of execution or success. Check qualification results for the named workflow.'})
    route_matrix = []
    for route in routes:
        views = route_views[route['id']]
        forms = {form['id']: form for view in views for form in view['forms']}
        inputs = {(field['id'], field['name'], field['kind']): field for view in views for field in view['input_surfaces']}
        route_matrix.append({**route, 'loader_declared': bool(re.search(r"(?:['\"]" + re.escape(route['id']) + r"['\"]|\b" + re.escape(route['id']) + r")\s*:", loaders)),
            'navigation_fixture': 'passed route activation and no unexpected JS/HTTP5xx',
            'inner_tabs': browser['inner_tabs'].get(route['id'], []),
            'visible_action_ids': sorted({action['id'] for view in views for action in view['actions']}),
            'visible_forms': [{**form, 'app_submit_handler_declared': form['id'] in submit_forms,
                               'other_submit_protocol': 'web/ai-guidance.js local submit listener' if form['id'].startswith('ai-guidance-') else 'data-workspace-ai-form local submit listener' if 'data-workspace-ai-form' in form.get('protocols', []) else None,
                               'operation_coverage': 'Listed, not submitted by this navigation audit.'} for form in forms.values()],
            'visible_textarea_file_surfaces': list(inputs.values()),
            'sample_execution_note': 'A textarea or file input can hold configuration, key names or samples; its presence alone does not prove a parser result.'})
    report = {
        'release': 'v23.0.0-9', 'report_type': 'finite_ui_source_dom_verification_matrix',
        'source_sha256': {name: digest(ROOT / name) for name in sources},
        'fixture': browser['fixture'],
        'summary': {'routes': len(routes), 'activated_inner_tabs': sum(map(len, browser['inner_tabs'].values())), 'observed_views': len(browser['views']),
                    'literal_or_programmatic_source_action_ids': len(source_ids), 'visible_action_ids_in_fixture': len(observed_ids),
                    'unresolved_action_ids': unresolved, 'source_handler_resolution_is_runtime_execution': False},
        'evidence': {'navigation_walk': 'r9-ui-matrix-walk.log', 'rendered_inventory': args.browser_inventory.name,
                     'scope': 'Authenticated representative mocked controller. Real packaged navigation, real APIs, runtime stress and live-node delivery are separate qualification gates.'},
        'routes': route_matrix, 'actions': actions, 'dynamic_action_expressions': dynamic_attributes,
        'actual_sample_workflow_surfaces': [
            {'routes': ['selective-input', 'output-fields'], 'surfaces': ['raw/file records', 'literal/header rules', 'root field names', 'raw-first matches', 'before/after JSON'],
             'coverage': 'Separate browser workflows, controller lifecycle tests, million-record core/agent stress and packaged rollout tests supply execution evidence; this inventory only navigates.'},
            {'routes': ['assurance'], 'surfaces': ['Production parser assurance raw', 'corpus JSON cases', 'NAPI Synthesis discovery/held_out/negative datasets', 'Parser Creation Helper samples'],
             'backend_tests': ['TestNAPISynthesisCreatesEvidenceBackedDraftWithoutRawSamples', 'TestNAPISynthesisExplicitReviewRetentionSubmitsThroughBothCatalogs', 'TestNAPISynthesisRetainedExamplesCannotTurnWrongExpectedOutputIntoPassingEvidence'],
             'coverage': 'Separate backend and targeted browser workflow evidence required; navigation walk does not synthesize or submit.'},
            {'routes': ['header-templates', 'kv-templates'], 'surfaces': ['template-composition-sample', 'saved header and KV combined preview'],
             'coverage': 'Existing combined-template and runtime sample tests cover fixture grammars; arbitrary future log grammars are not proven.'},
            {'routes': ['field-mapping', 'building-blocks', 'quarantine-wizard', 'parser-workspace'], 'surfaces': ['nfi-raw', 'nfi-corpus', 'block-raw', 'gprs-manual-raw', 'samples and exact expected JSON cases'],
             'coverage': 'Manual/native mapping tests and approval workflow tests are separate from this read-only inventory.'},
            {'routes': ['knownkeys'], 'surfaces': ['keys_source / key_file: key identifiers, not raw logs', 'known_keys: key identifiers', 'optional raw AI/template sample'],
             'backend_tests': ['TestBulkKnownKeysPublicationRecognitionAndRuntime', 'TestKnownKeyBulkBoundaries'],
             'coverage': 'Targeted1500-key frontend import and backend publication/recognition/flat output/revoke tests;10000-key boundary unit checks.'},
            {'routes': ['clients'], 'surfaces': ['bulk_node_ids: enrolled IDs, not raw logs'],
             'backend_tests': ['TestClientDirectoryNamesGroupsAndRevisionedRestart', 'TestClientDirectoryGroupThousandClientsAndFrozenRolloutTargets', 'TestClientDirectoryFailurePreservesFleetAndAtomicStoredNames', 'TestClientDirectoryPermissionsBoundsAndUnknownIdentities'],
             'coverage': 'Targeted1005-member browser and backend group workflows; not1005 live network nodes.'},
            {'routes': ['reference-ai', 'ai', 'ai-guidance'], 'surfaces': ['questions, optional raw context and provider controls'],
             'coverage': 'Grounded catalog/provider fixtures are separate from the redacted live Gemini guidance evidence. This navigation audit does not contact a provider or train model weights.'},
        ],
        'explicit_not_executed_by_this_audit': ['Every individual conditional mutation button with real data', 'Destructive operations against production',
            'Live AWS fleet across1000+ clients', 'Paid external AI-provider requests', 'Every possible malformed log, network or hardware fault'],
        'interpretation': ['Static handler resolution detects missing wiring candidates; it does not prove runtime semantics.',
            'A rendered action is not marked executed merely because its label exists.',
            'Source test references are discovery aids; final qualification records state which tests actually passed.',
            'The source scan resolves literal action IDs and reports dynamic expressions separately.',
            'No input values, credentials, customer raw logs or provider replies are recorded.'],
    }
    assert all(route['loader_declared'] for route in route_matrix), 'Navigation route lacks declared loader'
    assert not unresolved, 'Review candidate unwired actions: ' + ', '.join(unresolved)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes((json.dumps(report, indent=2, ensure_ascii=False) + '\n').encode('utf-8'))
    print(json.dumps(report['summary'], indent=2))


if __name__ == '__main__':
    main()
