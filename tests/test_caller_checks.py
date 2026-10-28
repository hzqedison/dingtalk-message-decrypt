"""Synthetic only: all child processes blocked; all artifacts in temporary dirs."""
import copy
import hashlib
import importlib
import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import sys
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
sys.path.insert(0, str(ROOT / 'references' / 'caller-integration'))
import caller_checks as checks

CIPHER = 'c3ludGhldGlj||2||1||9'
ROW = {'conversationId': 'synthetic-cid', 'messageId': 'synthetic-parent',
       'content': CIPHER,
       'quotedMessage': {'messageId': 'synthetic-quote', 'content': CIPHER}}


def artifact(folder, rows, *, count=None, status='decrypted_local', text='synthetic readable'):
    folder.mkdir(parents=True)
    summary = {'counts': {'input_rows': len(rows) if count is None else count},
               'status': 'complete_for_supplied_records',
               'resolution_complete_for_supplied_records': True,
               'unresolved_items': 0, 'local_crypto': {'stop_reason': None}}
    (folder/'summary.json').write_text(json.dumps(summary), encoding='utf-8')
    resolution = {'status': status, 'text': text, 'crypto_decryption_proven': True}
    checks.write_rows(folder/'resolved.jsonl', [
        {'original': row, 'resolution': {'body': resolution, 'quoted_message': resolution}}
        for row in rows])
    return summary


class CallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.blocker = patch('subprocess.run', side_effect=AssertionError('real process forbidden'))
        self.blocker.start()
        self.addCleanup(self.blocker.stop)
        self.collector = importlib.import_module('daily_collect')
        self.retry = importlib.import_module('fetch_only')
        self.cont = importlib.import_module('continue_saved')

    def test_import_has_no_process_or_filesystem_side_effect(self):
        with patch('pathlib.Path.read_text', side_effect=AssertionError('import read')):
            for module in (self.collector, self.retry, self.cont):
                importlib.reload(module)

    def test_command_preserves_unrelated_auto_and_modes(self):
        for client in ('auto', 'off'):
            for local in ('auto', 'off'):
                mode = checks.mode_config(client, local)
                cmd = self.collector.reader_command([{'conversationId': 'auto'}], Path('auto'), mode)
                for flag, value in [('--client', client), ('--local-crypto', mode['localCrypto']), ('--server', 'off'),
                                    ('--conversation-id', 'auto'), ('--out', 'auto')]:
                    self.assertEqual(cmd[cmd.index(flag)+1], value)
                    self.assertEqual(cmd.count(flag), 1)

    def test_modes_reject_server_full_or_invalid_values(self):
        with self.assertRaises(ValueError): checks.mode_config('invalid')
        with self.assertRaises(ValueError): checks.mode_args({'server': 'full', 'client': 'auto', 'localCrypto': 'auto'})

    def test_client_off_reports_effective_local_off(self):
        mode = checks.mode_config(client='off', local_crypto='auto')
        self.assertEqual(mode['localCrypto'], 'off')
        self.assertEqual(checks.mode_args(mode)[-1], 'off')

    def test_shared_checks_and_examples_are_deployed_and_hashed(self):
        from deployment_info import file_hashes
        manifest = file_hashes(ROOT)
        for name in ('scripts/caller_checks.py', 'references/caller-integration/README.md',
                     'references/caller-integration/daily_collect.py',
                     'references/caller-integration/fetch_only.py',
                     'references/caller-integration/continue_saved.py'):
            self.assertIn(name, manifest)

    def test_original_extraction_preserves_parent_and_quote(self):
        rows = checks.originals([{'original': ROW, 'resolution': {}}])
        target = self.root/'raw.jsonl'
        checks.write_rows(target, rows)
        self.assertEqual(checks.read_rows(target), [ROW])
        with self.assertRaises(FileExistsError): checks.write_rows(target, rows)

    def test_invalid_and_empty_inputs_rejected(self):
        for rows in ([], [{}], [{'original': {}}], [{'original': {'messageId': 'x'}}],
                     [{'original': {**ROW, 'original': {}}}]):
            with self.subTest(rows=rows), self.assertRaises(ValueError): checks.originals(rows)

    def test_cipher_detection_not_safechat_substring(self):
        self.assertTrue(checks.encrypted(CIPHER))
        for text in ('safechat documentation', '1_1_abcdef', 'abc||2||1||3', ''):
            self.assertFalse(checks.encrypted(text))

    def test_body_and_exact_parent_quote_pass(self):
        result = self.root/'good'
        artifact(result, [ROW])
        for kind in ('body', 'quote'):
            checks.validate_result(result, 0, [ROW], kind)
        changed = copy.deepcopy(ROW); changed['messageId'] = 'other-parent'
        with self.assertRaises(ValueError): checks.validate_result(result, 0, [changed], 'quote')

    def test_exit_two_rejected_even_with_success_artifacts(self):
        result = self.root/'good'; artifact(result, [ROW])
        with self.assertRaises(ValueError): checks.validate_result(result, 2, [ROW], 'body')

    def test_zero_missing_mismatch_or_noninteger_counts_rejected(self):
        for i, count in enumerate((0, 2, True, '1')):
            result = self.root/str(i); artifact(result, [ROW], count=count)
            with self.assertRaises(ValueError): checks.validate_result(result, 0, [ROW], 'body')
        result = self.root/'missing'; summary = artifact(result, [ROW])
        del summary['counts']['input_rows']
        (result/'summary.json').write_text(json.dumps(summary), encoding='utf-8')
        with self.assertRaises(ValueError): checks.validate_result(result, 0, [ROW], 'body')

    def test_missing_and_failed_completion_evidence_rejected(self):
        for i, (key, value) in enumerate((('status', 'partial'), ('unresolved_items', 1),
                    ('resolution_complete_for_supplied_records', False),
                    ('local_crypto', {'stop_reason': 'unsupported_client_fingerprint'}),
                    ('local_crypto', {}))):
            result = self.root/str(i); summary = artifact(result, [ROW]); summary[key] = value
            (result/'summary.json').write_text(json.dumps(summary), encoding='utf-8')
            with self.assertRaises(ValueError): checks.validate_result(result, 0, [ROW], 'body')

    def test_unreadable_or_noncrypto_success_rejected(self):
        for i, (status, text) in enumerate((('unresolved', 'text'), ('client_observed', 'text'),
                ('original_plaintext', 'text'), ('decrypted_local', ''),
                ('decrypted_local', '1_1_abcdef'), ('decrypted_local', CIPHER),
                ('decrypted_local', '[加密消息，无法解码]'))):
            result = self.root/str(i); artifact(result, [ROW], status=status, text=text)
            with self.assertRaises(ValueError): checks.validate_result(result, 0, [ROW], 'body')

    def continuation(self, failure=None):
        raw = self.root/'raw-fetch'; raw.mkdir()
        checks.write_rows(raw/'resolved.jsonl', [{'original': ROW, 'resolution': {}}])
        original_bytes = (raw/'resolved.jsonl').read_bytes()
        calls = []
        def fake(cmd, **kwargs):
            calls.append(cmd)
            source = Path(cmd[cmd.index('--input')+1]); result = Path(cmd[cmd.index('--out')+1])
            self.assertNotEqual(source.name, 'resolved.jsonl')
            rows = checks.read_rows(source)
            self.assertEqual(rows, [ROW])
            self.assertEqual(cmd[cmd.index('--server')+1], 'off')
            artifact(result, rows, count=0 if failure == 'zero' else None,
                     status='unresolved' if failure == 'body' or (failure == 'quote' and len(calls)==2) else 'decrypted_local')
            return SimpleNamespace(returncode=2 if failure == 'exit' else 0, stdout='', stderr='')
        with patch.multiple(self.cont, B=self.root, O=self.root, R=raw), patch('subprocess.run', side_effect=fake), patch('builtins.print'):
            if failure:
                with self.assertRaises(ValueError): self.cont.main()
            else:
                self.cont.main()
        self.assertEqual((raw/'resolved.jsonl').read_bytes(), original_bytes)
        return calls

    def test_continuation_extracts_raw_after_both_smokes(self):
        calls = self.continuation()
        self.assertEqual(len(calls), 3)
        source = calls[-1][calls[-1].index('--input')+1]
        self.assertEqual(Path(source).name, 'original-input.jsonl')

    def test_continuation_stops_on_failed_body(self):
        self.assertEqual(len(self.continuation('body')), 1)

    def test_continuation_stops_on_failed_quote(self):
        self.assertEqual(len(self.continuation('quote')), 2)

    def test_continuation_stops_on_exit_two(self):
        self.assertEqual(len(self.continuation('exit')), 1)

    def test_continuation_stops_on_zero_input(self):
        self.assertEqual(len(self.continuation('zero')), 1)

    def collector_run(self, count=1):
        module = self.collector
        auth = {'authenticated': True, 'refresh_token_valid': True, 'corp_id': 'fake', 'user_id': 'fake'}
        identity = {k: auth[k] for k in ('corp_id', 'user_id')}
        scope = 'dws-auth-'+hashlib.sha256(json.dumps(identity, sort_keys=True, separators=(',', ':')).encode()).hexdigest()
        pipeline = self.root/'raw-fetch'
        def invoke(args, label, **kwargs):
            responses = {'at-me': {'paging': {'hasMore': False, 'sourceExhausted': True}},
                         'conversation-list': {'complete': True, 'conversations': [{'conversationId': 'auto'}]},
                         'recent-page-1': {'meta': {'pagination': {'endpoint_exhausted': True}}}}
            return responses[label], []
        def fake(cmd, **kwargs):
            if cmd[1:3] == ['auth', 'status']:
                return SimpleNamespace(returncode=0, stdout=json.dumps(auth))
            self.assertEqual(Path(cmd[cmd.index('--out')+1]), pipeline)
            for flag in ('--client', '--local-crypto'): self.assertEqual(cmd[cmd.index(flag)+1], 'off')
            artifact(pipeline, [ROW], count=count)
            (pipeline/'fetch').mkdir()
            (pipeline/'fetch/fetch_report.json').write_text(json.dumps({'complete': True}), encoding='utf-8')
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        with patch.multiple(module, BASE=self.root, OUT=self.root, DISC=self.root/'discovery',
                            PRIOR=self.root/'absent.json', SCOPE=scope), patch.object(module, 'invoke', side_effect=invoke), patch('subprocess.run', side_effect=fake), patch('builtins.print'):
            if count:
                with self.assertRaises(SystemExit) as error: module.main(client='off', local_crypto='off', pipeline_dir=pipeline)
                self.assertEqual(error.exception.code, 0)
            else:
                with self.assertRaisesRegex(RuntimeError, 'input_rows'): module.main(client='off', local_crypto='off', pipeline_dir=pipeline)
        receipt = json.loads((self.root/'pipeline-run-1.json').read_text(encoding='utf-8'))
        self.assertEqual(receipt['mode'], {'server': 'off', 'client': 'off', 'localCrypto': 'off'})
        summary = json.loads((self.root/'collection-summary.json').read_text(encoding='utf-8'))
        self.assertIsNotNone(summary['pipelineSummary'])

    def test_collector_logs_effective_off_modes_and_reads_redirected_output(self):
        self.collector_run()

    def test_collector_refuses_zero_input_completion(self):
        self.collector_run(count=0)

    def retry_run(self, success):
        # Load the patched base collector but replace its main with a synthetic fetch.
        module = self.collector
        def synthetic_fetch(**kwargs):
            self.assertEqual(kwargs['client'], 'off')
            self.assertEqual(kwargs['local_crypto'], 'off')
            output = kwargs['pipeline_dir']
            artifact(output, [ROW])
            (output/'fetch').mkdir()
            (output/'fetch/fetch_report.json').write_text(json.dumps({'complete': True}), encoding='utf-8')
            raise SystemExit(2)  # Fetch-only encrypted records may remain unresolved.
        def fake(cmd, **kwargs):
            output = Path(cmd[cmd.index('--out')+1])
            artifact(output, [ROW], status='decrypted_local' if success else 'unresolved')
            return SimpleNamespace(returncode=0, stdout='', stderr='')
        fake_spec = SimpleNamespace(loader=SimpleNamespace(exec_module=lambda module: None))
        # Snapshot globals overridden by retry.run to avoid contaminating later tests.
        names = ('BASE', 'OUT', 'DISC', 'PRIOR', 'POLICY', 'START', 'END', 'SCOPE', 'PYTHON', 'SKILL')
        before = {key: getattr(module, key) for key in names}
        try:
            with patch.object(self.retry, 'BASE', self.root), patch.object(module, 'main', side_effect=synthetic_fetch), patch('importlib.util.spec_from_file_location', return_value=fake_spec), patch('importlib.util.module_from_spec', return_value=module), patch('subprocess.run', side_effect=fake), patch('builtins.print'):
                if success: self.retry.run('28', '27', '20261029')
                else:
                    with self.assertRaises(ValueError): self.retry.run('28', '27', '20261029')
        finally:
            for key, value in before.items(): setattr(module, key, value)
        output = self.root/'cache/heartbeat-20261029-full'
        self.assertEqual((output/'pipeline/fetch').exists(), success)
        self.assertEqual((output/'retry3-status.json').exists(), success)

    def test_retry_passes_modes_explicitly_and_checks_actual_smoke(self):
        self.retry_run(True)

    def test_retry_does_not_continue_when_exit_zero_but_unresolved(self):
        self.retry_run(False)


if __name__ == '__main__':
    unittest.main()
