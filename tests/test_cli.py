import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from batch_cli import execute, output_lock, parser


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.input = self.root / 'source.json'
        self.input.write_text(json.dumps({'messages': [{'conversationId': 'cid-a', 'messageId': 'msg-a',
            'content': {'textContent': {'text': 'hello'}}}]}), encoding='utf-8')
        self.out = self.root / 'output'

    def tearDown(self):
        self.tmp.cleanup()

    def args(self, *extra):
        return parser().parse_args(['--input', str(self.input), '--out', str(self.out),
            '--server', 'off', '--client', 'off', *extra])

    def test_offline_does_not_run_dws_or_client(self):
        with patch('subprocess.run', side_effect=AssertionError('Unexpected external call')):
            report = execute(self.args())
        self.assertEqual(report['counts']['readable_messages'], 1)

    def test_empty_client_index_does_not_reclassify_this_run_as_cache_hits(self):
        first = {'counts':{'encrypted_body_unresolved':1,'body_decrypted_local':2},
                 'local_crypto':{'safechat_calls':2}, 'status':'partial'}
        with patch('batch_cli.resolve_batch',return_value=first) as resolve, patch(
                'client_bridge.capture_loaded',return_value={'status':'captured','index':'empty.jsonl','api_bound_messages':0}):
            report = execute(self.args('--client','auto','--local-crypto','off'))
        resolve.assert_called_once()
        self.assertEqual(report['counts']['body_decrypted_local'],2)

    def test_auto_client_filters_malformed_target_cids_before_resolution(self):
        self.input.write_text(json.dumps({'messages':[
            {'conversationId':{'invalid':'cid'},'messageId':'bad-dict','content':'fixture'},
            {'conversationId':['invalid'],'messageId':'bad-list','content':'fixture'},
            {'conversationId':None,'messageId':'bad-null','content':'fixture'},
            {'conversationId':'cid-valid','messageId':'valid','content':'fixture'}]}),encoding='utf-8')
        with patch('native_decryptor.NativeDecryptor') as native, \
                patch('subprocess.Popen',side_effect=AssertionError('Unexpected process call')):
            native.return_value.summary.return_value={'status':'fixture'}
            report=execute(self.args('--client','auto'))
        self.assertEqual(native.call_args.kwargs['target_cids'],{'cid-valid'})
        self.assertEqual(report['counts']['unidentified_rows'],3)
        self.assertEqual(report['counts']['readable_messages'],1)
        self.assertEqual(report['status'],'partial')

    def test_auto_client_includes_cross_conversation_quote_in_scan_targets(self):
        self.input.write_text(json.dumps({'messages':[{
            'conversationId':'parent-cid','messageId':'parent','content':'parent fixture',
            'quotedMessage':{'openConversationId':'quote-cid','messageId':'quote','content':'quote fixture'}}]}),encoding='utf-8')
        with patch('native_decryptor.NativeDecryptor') as native, \
                patch('subprocess.Popen',side_effect=AssertionError('Unexpected process call')):
            native.return_value.summary.return_value={'status':'fixture'}
            report=execute(self.args('--client','auto'))
        self.assertEqual(native.call_args.kwargs['target_cids'],{'parent-cid','quote-cid'})
        self.assertEqual(report['counts']['readable_messages'],1)

    def test_invalid_quote_cid_preserves_parent_and_marks_only_quote_unresolved(self):
        for bad in ({'bad':'cid'},['bad'],{},[],1,False):
            with self.subTest(bad=bad):
                self.input.write_text(json.dumps({'messages':[{
                    'conversationId':'parent-cid','messageId':'parent','content':'parent fixture',
                    'quotedMessage':{'openConversationId':bad,'messageId':'quote','content':'quote fixture'}}]}),encoding='utf-8')
                with patch('subprocess.Popen',side_effect=AssertionError('Unexpected process call')):
                    report=execute(self.args())
                self.assertEqual(report['counts']['readable_messages'],1)
                self.assertEqual(report['status'],'partial')
                unresolved=[json.loads(line) for line in (self.out/'unresolved.jsonl').read_text(encoding='utf-8').splitlines()]
                self.assertEqual(len(unresolved),1)
                self.assertEqual(unresolved[0]['reason'],'invalid_quote_conversation_identity')

    def test_scope_change_rejected(self):
        execute(self.args('--scope', 'one'))
        with self.assertRaises(ValueError):
            execute(self.args('--scope', 'two'))

    def test_known_policy_seed_without_network(self):
        report = execute(self.args('--known-policy-disabled'))
        self.assertEqual(report['server_stop_reason'], 'CRYPTO_DISABLED')

    def test_conflicting_arguments(self):
        for extra in (['--days', '3'], ['--resume'], ['--conversation-id', 'cid-x'],
                      ['--decrypt-limit', '-1'], ['--known-policy-disabled', '--server', 'retry']):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                execute(self.args(*extra))

    def test_lock_excludes_simultaneous_writer(self):
        with output_lock(self.out):
            with self.assertRaises(ValueError):
                with output_lock(self.out):
                    self.fail('Second writer should not enter')
        with output_lock(self.out):
            pass

    def test_import_output_separation(self):
        args = self.args('--input', str(self.out))
        with self.assertRaises(ValueError):
            execute(args)

    def test_resume_uses_fixed_window_and_kind(self):
        fetch = self.out / 'fetch'
        fetch.mkdir(parents=True)
        (fetch / 'fetch_manifest.json').write_text(json.dumps({'kind': 'group'}), encoding='utf-8')
        args = parser().parse_args(['--out', str(self.out), '--resume', '--server', 'off', '--client', 'off'])
        with patch('batch_cli.fetch_snapshot', return_value=(self.input, {'complete': True})) as mocked:
            report = execute(args)
        self.assertIsNone(mocked.call_args.args[1])
        self.assertIsNone(mocked.call_args.args[2])
        self.assertEqual(mocked.call_args.kwargs['kind'], 'group')
        self.assertTrue(report['resolution_complete_for_supplied_records'])


if __name__ == '__main__':
    unittest.main()
