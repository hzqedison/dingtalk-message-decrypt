"""Synthetic-memory runtime tests; never discover or open a real process."""
import hashlib
import base64
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / 'scripts' / 'client_runtime'
sys.path.insert(0, str(RUNTIME))
try:
    SPEC = importlib.util.spec_from_file_location('packaged_runtime_under_test', RUNTIME / 'capture_typed_messages.py')
    runtime = importlib.util.module_from_spec(SPEC)
    SPEC.loader.exec_module(runtime)
finally:
    sys.path.pop(0)

import client_compatibility


def fixture_profile(raw):
    return client_compatibility.ClientProfile(
        client_compatibility.LEGACY_PROFILE.id, 'synthetic',
        hashlib.sha256(raw).hexdigest(), ('typed_messages',))


class Memory:
    base = 0x180000000
    model = 0x20000
    content = 0x30000
    body = 0x40000
    head = 0x50000

    def __init__(self, external='cid-target', extra=None):
        self.blocks, self.calls = {}, []
        self.next_heap = 0x90000
        model, content = bytearray(0x180), bytearray(0x48)
        struct.pack_into('<QQ', model, 0, self.base + 0x81aff00, self.content)
        model[0x38:0x58] = self.string('123')
        struct.pack_into('<q', model, 0x58, 123456789)
        struct.pack_into('<q', model, 0xa0, 1790000000000)
        struct.pack_into('<i', model, 0xb8, 1)
        struct.pack_into('<Qi', content, 0, self.base + 0x81afd98, 1)
        body = '合成测试正文，不属于任何真实会话。'.encode()
        self.blocks[self.body] = bytearray(body+b'\0')
        content[0x28:0x48] = struct.pack('<QQQQ', self.body, 0, len(body), 127)
        values = {} if external is None else {'openConversationId': external}
        values.update(extra or {})
        self.map(values)
        struct.pack_into('<QQ', model, 0xc8, self.head, len(values))
        self.blocks[self.model], self.blocks[self.content] = model, content

    def string(self, value):
        raw = value.encode()
        if len(raw) <= 15:
            return raw+bytes(16-len(raw))+struct.pack('<QQ', len(raw), 15)
        address = self.next_heap
        self.next_heap += 0x1000
        self.blocks[address] = bytearray(raw+b'\0')
        return struct.pack('<QQQQ', address, 0, len(raw), max(31, len(raw)))

    def map(self, values):
        keys = sorted(values)
        assert len(keys) <= 3
        self.nodes = {key: 0x60000+i*0x1000 for i,key in enumerate(keys)}
        middle = len(keys)//2
        root = self.nodes[keys[middle]] if keys else self.head
        sentinel = bytearray(0x20)
        struct.pack_into('<QQQ', sentinel, 0,
                         self.nodes[keys[0]] if keys else self.head, root,
                         self.nodes[keys[-1]] if keys else self.head)
        sentinel[0x18:0x1a] = b'\1\1'
        self.blocks[self.head] = sentinel
        for index,key in enumerate(keys):
            node = bytearray(0x60)
            left = self.nodes[keys[0]] if index == middle and index > 0 else self.head
            right = self.nodes[keys[-1]] if index == middle and index < len(keys)-1 else self.head
            struct.pack_into('<QQQ', node, 0, left, self.head if index == middle else root, right)
            node[0x18] = int(index == middle)
            node[0x20:0x40], node[0x40:0x60] = self.string(key), self.string(values[key])
            self.blocks[self.nodes[key]] = node

    def read(self, address, size):
        self.calls.append((address,size))
        for base,data in self.blocks.items():
            if base <= address and address+size <= base+len(data):
                return bytes(data[address-base:address-base+size])
        raise runtime.Rejected('incomplete_read')

    def body_was_read(self):
        return any(address in (self.content, self.body) for address,_ in self.calls)

    def snapshot(self, stable=True, **overrides):
        options = dict(profile='im_chat', read_extensions=True, external_cids={'cid-target'})
        options.update(overrides)
        method = runtime.stable_snapshot if stable else runtime.snapshot
        return method(self.model, self.read, self.base, None, **options)


class ExternalConversationTests(unittest.TestCase):
    def test_matching_external_cid_reads_body_and_records_extension(self):
        mem = Memory()
        row = mem.snapshot()
        self.assertTrue(mem.body_was_read())
        self.assertEqual(row['native_message_id'], '123456789')
        self.assertEqual(row['extension_selected']['openConversationId'], 'cid-target')
        self.assertEqual(row['text_sha256'], hashlib.sha256(row['text'].encode()).hexdigest())

    def test_different_external_cid_rejected_before_content_or_body_read(self):
        mem = Memory('cid-other')
        with self.assertRaisesRegex(runtime.Rejected, 'external_conversation'):
            mem.snapshot()
        self.assertFalse(mem.body_was_read())

    def test_missing_external_cid_rejected_before_body_read(self):
        mem = Memory(None)
        with self.assertRaisesRegex(runtime.Rejected, 'external_conversation'):
            mem.snapshot()
        self.assertFalse(mem.body_was_read())

    def test_empty_external_allowlist_reads_no_body(self):
        mem = Memory()
        with self.assertRaises(runtime.Rejected):
            mem.snapshot(external_cids=set())
        self.assertFalse(mem.body_was_read())

    def test_no_scope_filter_rejected_before_body(self):
        mem = Memory()
        with self.assertRaisesRegex(runtime.Rejected, 'missing_conversation_filter'):
            mem.snapshot(external_cids=None)
        self.assertFalse(mem.body_was_read())

    def test_external_scope_cannot_be_silently_ignored_when_extensions_disabled(self):
        mem = Memory('cid-other')
        with self.assertRaises(runtime.Rejected):
            runtime.snapshot(mem.model, mem.read, mem.base, {'123'}, 'im_chat', False, {'cid-target'})
        self.assertFalse(mem.body_was_read())

    def test_extension_change_is_included_in_double_read(self):
        mem = Memory(extra={'editTime':'1', 'recallMessageTime':'0'})
        original = mem.read
        seen = 0
        def changing(address,size):
            nonlocal seen
            if address == mem.model:
                seen += 1
                if seen == 2:
                    mem.blocks[mem.nodes['editTime']][0x40:0x60] = mem.string('2')
            return original(address,size)
        mem.read = changing
        with self.assertRaisesRegex(runtime.Rejected, 'changed_on_reread'):
            mem.snapshot()

    def test_corrupt_extension_tree_rejected_before_body(self):
        mem = Memory()
        mem.blocks[mem.head][0x19] = 0
        with self.assertRaisesRegex(runtime.Rejected, 'extension_'):
            mem.snapshot()
        self.assertFalse(mem.body_was_read())

    def test_recall_marker_is_preserved_for_downstream_filter(self):
        mem = Memory(extra={'recallMessageTime':'1790000000001'})
        row = mem.snapshot()
        self.assertEqual(row['extension_selected']['recallMessageTime'], '1790000000001')


class SyntheticRunTests(unittest.TestCase):
    def run_fake(self, rows):
        mem = Memory()
        scan_base = 0x100000
        scan = b''.join(struct.pack('<Q', mem.base+0x81aff00) for _ in rows)
        disk_base = 0x180000000
        method_rva = 0x1000
        class FakePE:
            OPTIONAL_HEADER = SimpleNamespace(ImageBase=disk_base)
            def get_data(self, rva, size):
                return struct.pack('<Q', disk_base+method_rva)
        class FakeProcess:
            path = 'fixture/DingTalk.exe'
            created_filetime = 123
            def __init__(self,*args):
                pass
            def read(self,address,size):
                data = scan if address == scan_base else struct.pack('<Q',mem.base+method_rva)
                return data[:size], len(data) >= size
            def regions(self):
                yield scan_base,len(scan),0x1000,4,0x20000
            def close(self):
                pass
        matcher = SimpleNamespace(target_cids={'cid-target'}, internal_cids=set(),
                                  api_sha256='fixture-api-sha',native_bindings={},by_cipher={},by_id={})
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            dll = root/'fixture.dll'
            dll.write_bytes(b'fixture-not-a-real-dll')
            args = SimpleNamespace(profile='im_chat',dll=str(dll),api='unused-fixture',anchors=[],
                                   out=str(root/'out'),pid=0,exe='fixture',seconds=1,max_gib=.001,module_base=mem.base)
            with patch.object(runtime,'EXPECTED_SHA',runtime.digest(dll.read_bytes())), \
                 patch.object(client_compatibility, 'PROFILES', (fixture_profile(dll.read_bytes()),)), \
                 patch.object(runtime.pefile,'PE',return_value=FakePE()), \
                 patch.object(runtime,'ReadOnlyProcess',FakeProcess), \
                 patch.object(runtime,'ObjectProbe',return_value=matcher), \
                 patch.object(runtime,'stable_snapshot',side_effect=rows):
                report = runtime.run(args)
            exported = (root/'out'/'readable_messages.jsonl').read_text(encoding='utf-8')
        return report,exported

    def test_conflicting_body_for_same_native_id_is_not_exported(self):
        first = Memory().snapshot()
        second = dict(first,text='different fixture body',text_sha256=runtime.digest('different fixture body'))
        report,exported = self.run_fake([first,second])
        self.assertEqual(report['conflicting_native_messages'],1)
        self.assertEqual(report['readable_native_messages'],0)
        self.assertEqual(exported,'')

    def test_repeated_same_body_is_deduplicated_without_claiming_decryption(self):
        first = Memory().snapshot()
        report,exported = self.run_fake([dict(first),dict(first)])
        self.assertEqual(report['readable_native_messages'],1)
        self.assertFalse(json.loads(exported)['crypto_decryption_proven'])

    def test_conflicting_recall_marker_same_body_is_withheld(self):
        first = Memory(extra={'recallMessageTime':'0'}).snapshot()
        second = dict(first, extension_selected={**first['extension_selected'], 'recallMessageTime':'1790000000001'})
        report, exported = self.run_fake([second, first])
        self.assertEqual(report['conflicting_native_messages'], 1)
        self.assertEqual(exported, '')


class BridgeRecallTests(unittest.TestCase):
    def test_recalled_capture_is_excluded_from_both_index_and_supplement(self):
        sys.path.insert(0,str(ROOT/'scripts'))
        try:
            spec = importlib.util.spec_from_file_location('packaged_bridge_under_test',ROOT/'scripts'/'client_bridge.py')
            bridge = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(bridge)
        finally:
            sys.path.pop(0)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            source = root/'input.json'
            cipher = base64.b64encode(b'fixture-cipher').decode()+'||2||1||128'
            source.write_text(json.dumps({'messages':[
                {'messageId':mid,'conversationId':'cid-target','content':cipher,
                 'createTime':'2026-10-14 12:00:00'} for mid in ('m-recalled','m-kept')]}),encoding='utf-8')
            captured = []
            for mid,recall in [('m-recalled','1790000000001'),('m-kept','0')]:
                row = Memory(extra={'recallMessageTime':recall}).snapshot()
                row.update(api_message_id=mid,api_time_matches_to_second=True)
                captured.append(row)
            def fake_subprocess(command,**kwargs):
                output = Path(command[command.index('--out')+1])
                output.mkdir()
                (output/'observations.jsonl').write_text('',encoding='utf-8')
                if Path(command[1]).name == 'capture_typed_messages.py':
                    (output/'readable_messages.jsonl').write_text(
                        ''.join(json.dumps(row,ensure_ascii=False)+'\n' for row in captured),encoding='utf-8')
                return SimpleNamespace(returncode=0,stdout=b'',stderr=b'')
            dll = root/'fixture.dll'
            dll.write_bytes(b'fixture-not-a-real-dll')
            target = {'pid':0,'exe':'fixture','dll':str(dll),'module_base':Memory.base}
            with patch.object(bridge,'discover_client',return_value=(target,None)), \
                 patch.object(client_compatibility, 'PROFILES', (fixture_profile(dll.read_bytes()),)), \
                 patch.object(bridge.subprocess,'run',side_effect=fake_subprocess):
                result = bridge.capture_loaded([source],root/'out')
            self.assertEqual(result['excluded']['recall_marked'],1)
            self.assertEqual(result['native_readable_messages'],1)
            self.assertEqual(result['api_bound_messages'],1)
            index = Path(result['index']).read_text(encoding='utf-8')
            supplemental = Path(result['supplemental_messages']).read_text(encoding='utf-8')
            self.assertNotIn('m-recalled',index+supplemental)
            self.assertFalse(json.loads(index)['crypto_decryption_proven'])


if __name__ == '__main__':
    unittest.main()
