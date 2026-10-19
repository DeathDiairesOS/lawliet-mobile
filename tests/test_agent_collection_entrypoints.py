import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

from lawliet_mobile.app_backend import handle
from lawliet_mobile.core import connect, create_case, select_artifacts, UserError
from lawliet_mobile.parsed_import import import_parsed


class CollectionEntryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve(); self.ws = self.root/'cases'
        create_case(self.ws, 'A'); create_case(self.ws, 'B')

    def config(self):
        return dict(objective='Check synthetic messages',serial='LAWLIET-SYNTHETIC',
                    profiles=['sms-provider'],examiner='Fixture examiner',authorized=True)

    def test_gui_authorizes_without_collecting_and_keeps_case_scope(self):
        with patch('lawliet_mobile.provider_sms.collect_sms', side_effect=AssertionError('No phone action')):
            plan = handle(self.ws, dict(action='agent-collection-create',case='A',config=self.config()))
            self.assertEqual(plan['status'], 'authorized')
            self.assertEqual(plan['case_path'], str(self.ws/'A'))
            self.assertIn('run_lawliet_collection', plan['handoff_request'])
            self.assertIn(plan['id'], plan['handoff_request'])
            saved = handle(self.ws, dict(action='agent-collection-status',case='A',plan_id=plan['id']))
            self.assertEqual(saved['id'], plan['id'])
            self.assertEqual(len(handle(self.ws, dict(action='agent-collection-list',case='A'))), 1)
            with self.assertRaises(UserError):
                handle(self.ws, dict(action='agent-collection-status',case='B',plan_id=plan['id']))

    def test_missing_approval_and_unsupported_profile_are_refused(self):
        for change in ({'authorized':False},{'profiles':['private-apps']},{'profiles':['logical']}):
            with self.subTest(change=change), self.assertRaises(UserError):
                handle(self.ws, dict(action='agent-collection-create',case='A',config={**self.config(),**change}))

    def test_connection_setup_allows_collection_longer_than_default_tool_timeout(self):
        launcher = self.root/'reviewed launcher'
        launcher.write_text('#!/bin/sh\nexit 0\n'); launcher.chmod(0o700)
        with patch('lawliet_mobile.agent_collection_handoff.configuration', return_value={'mulder':str(launcher)}):
            plan = handle(self.ws, dict(action='agent-collection-create',case='A',config=self.config()))
        snippet = plan['launch_instructions'].split('[mcp_servers.lawliet_collection]',1)[1].split('Equivalent stdio endpoint command:',1)[0]
        settings = tomllib.loads('[mcp_servers.lawliet_collection]'+snippet)['mcp_servers']['lawliet_collection']
        self.assertEqual(settings['startup_timeout_sec'],60)
        self.assertEqual(settings['tool_timeout_sec'],7200)
        self.assertEqual(settings['args'][0], '-B')
        self.assertIn(str(self.ws/'A'),settings['args'])
        self.assertIn(str(launcher),settings['args'])

    def test_direct_packaged_endpoint_help_does_not_modify_bundle(self):
        source = Path(__file__).resolve().parents[1] / 'lawliet_mobile'
        package = self.root / 'signed-app-resources' / 'lawliet_mobile'
        package.mkdir(parents=True)
        for name in ('__init__.py', 'mulder_runtime.py', 'agent_collection_endpoint.py'):
            shutil.copy2(source / name, package / name)
        before = {p.relative_to(package): p.read_bytes() for p in package.rglob('*') if p.is_file()}
        env = {k: v for k, v in os.environ.items() if k not in {'PYTHONPATH', 'PYTHONDONTWRITEBYTECODE', 'PYTHONPYCACHEPREFIX'}}
        result = subprocess.run([sys.executable, str(package / 'agent_collection_endpoint.py'), '--help'],
                                env=env, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        after = {p.relative_to(package): p.read_bytes() for p in package.rglob('*') if p.is_file()}
        self.assertEqual(before, after)

    def test_multi_evidence_filter_is_bounded_paginated_and_empty_is_empty(self):
        identifiers = []
        with connect(self.ws, 'A') as (root, db):
            for n in range(3):
                source = self.root/f'{n}.jsonl'
                source.write_text(json.dumps({'id':str(n),'evidence_id':str(n),'title':'Fixture',
                                            'category':'messages','body':f'fixture {n}','data':{},
                                            'timestamp':f'2026-10-17T12:00:0{n}Z'})+'\n')
                imported = import_parsed(root, db, source, 'jsonl')
                identifiers.append(imported['evidence_id'])
            self.assertEqual(select_artifacts(db,evidence_ids=[]), [])
            pages = [select_artifacts(db,evidence_ids=identifiers[:2],limit=1,offset=n) for n in range(3)]
            self.assertEqual([len(p) for p in pages], [1,1,0])
            self.assertEqual({p[0]['evidence_id'] for p in pages[:2]}, set(identifiers[:2]))
            self.assertEqual(select_artifacts(db,evidence_ids=["x') OR 1=1 --"]), [])
            for invalid in ('all', [None], ['x']*101):
                with self.subTest(invalid=invalid), self.assertRaises(UserError):
                    select_artifacts(db,evidence_ids=invalid)
