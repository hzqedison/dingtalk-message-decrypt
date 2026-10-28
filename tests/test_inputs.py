import json
import io
from contextlib import redirect_stdout
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from message_pipeline import ResolvedOutputInputError, load_inputs, resolve_batch
import batch_cli


class InputTests(unittest.TestCase):
    def test_cli_rejects_wrapper_without_leaking_input_or_reporting_complete(self):
        path = self.write('records.jsonl', [self.wrapped])
        output = self.root / 'out'
        stdout = io.StringIO()
        with patch.object(batch_cli, 'run_cli') as runner, redirect_stdout(stdout):
            code = batch_cli.main(['--input', str(path), '--out', str(output),
                                   '--server', 'off', '--client', 'off'])
        runner.assert_not_called()
        self.assertEqual(code, 1)
        report = json.loads(stdout.getvalue())
        self.assertEqual(report['reason'], 'resolved_output_not_raw_input')
        self.assertNotIn('fixture', stdout.getvalue())
        self.assertFalse((output / 'summary.json').exists())

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.raw = {
            'conversationId': 'fixture-cid', 'messageId': 'fixture-mid',
            'content': 'fixture body',
        }
        self.wrapped = {
            'original': self.raw,
            'resolution': {'body': {'status': 'original_plaintext', 'text': 'fixture body'}},
        }

    def tearDown(self):
        self.tmp.cleanup()

    def write(self, name, payload):
        path = self.root / name
        if path.suffix == '.jsonl':
            text = ''.join(json.dumps(item) + '\n' for item in payload)
        else:
            text = json.dumps(payload)
        path.write_text(text, encoding='utf-8')
        return path

    def assert_rejected(self, path):
        with self.assertRaises(ResolvedOutputInputError) as raised:
            load_inputs([path])
        message = str(raised.exception)
        self.assertIn('raw snapshot', message)
        self.assertIn('extract each original', message)
        self.assertNotIn('fixture', message)

    def test_resolved_records_rejected_in_json_and_jsonl(self):
        cases = {
            'object.json': self.wrapped,
            'array.json': [self.wrapped],
            'records.jsonl': [self.wrapped],
            'nested.json': {'data': {'messages': [self.wrapped]}},
        }
        for name, payload in cases.items():
            with self.subTest(name=name):
                self.assert_rejected(self.write(name, payload))

    def test_mixed_raw_and_resolved_input_is_not_partially_accepted(self):
        for suffix in ('json', 'jsonl'):
            for records in ([self.raw, self.wrapped], [self.wrapped, self.raw]):
                with self.subTest(suffix=suffix, wrapped_first=records[0] is self.wrapped):
                    self.assert_rejected(self.write('mixed.' + suffix, records))
        raw_path = self.write('raw.json', self.raw)
        wrapped_path = self.write('wrapped.jsonl', [self.wrapped])
        for paths in ([raw_path, wrapped_path], [wrapped_path, raw_path]):
            with self.assertRaises(ResolvedOutputInputError):
                load_inputs(paths)

    def test_wrapper_cannot_bypass_detection_with_message_id(self):
        record = {**self.wrapped, 'messageId': 'fixture-spoofed'}
        self.assert_rejected(self.write('spoofed.json', record))

    def test_raw_snapshots_and_explicit_original_extraction_are_preserved(self):
        cases = {
            'raw.json': self.raw,
            'array.json': [self.raw],
            'raw.jsonl': [self.raw],
            'nested.json': {'result': {'messages': [self.raw]}},
            'extracted.jsonl': [self.wrapped['original']],
        }
        for name, payload in cases.items():
            with self.subTest(name=name):
                rows, sources = load_inputs([self.write(name, payload)])
                self.assertEqual(rows, [self.raw])
                self.assertEqual(len(sources), 1)

    def test_raw_content_is_not_traversed_as_a_snapshot(self):
        raw = {**self.raw, 'content': json.dumps(self.wrapped)}
        rows, _ = load_inputs([self.write('raw-content.json', raw)])
        self.assertEqual(rows, [raw])

    def test_resolution_rejects_wrapper_before_runner_or_complete_report(self):
        path = self.write('mixed.jsonl', [self.raw, self.wrapped])
        out = self.root / 'output'
        runner = Mock(side_effect=AssertionError('Unexpected external call'))
        with self.assertRaises(ResolvedOutputInputError):
            resolve_batch([path], out, runner=runner)
        runner.assert_not_called()
        self.assertFalse((out / 'summary.json').exists())
        self.assertFalse((out / 'messages.jsonl').exists())
        self.assertFalse((out / 'resolution_cache.sqlite3').exists())

    def test_legal_empty_inputs_remain_empty(self):
        cases = {
            'array.json': [],
            'object.json': {},
            'messages.json': {'messages': []},
            'nested.json': {'result': {'messages': []}},
            'empty.jsonl': [],
        }
        for name, payload in cases.items():
            with self.subTest(name=name):
                rows, sources = load_inputs([self.write(name, payload)])
                self.assertEqual(rows, [])
                self.assertEqual(len(sources), 1)
        self.assertEqual(load_inputs([]), ([], []))


if __name__ == '__main__':
    unittest.main()
