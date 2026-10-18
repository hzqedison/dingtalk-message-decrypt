"""Synthetic memory only. No client discovery, process access, or real keys."""
import importlib.util
import json
from pathlib import Path
import struct
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'scripts/client_runtime/ding_key_provider.py'
SPEC = importlib.util.spec_from_file_location('key_provider_under_test', PATH)
provider = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(provider)


class Memory:
    base, service, orgs = 0x180000000, 0x30000, 0x100000
    manager, head, node, records = 0x200000, 0x210000, 0x220000, 0x230000
    other_node, other_records = 0x240000, 0x250000
    def __init__(self):
        self.blocks, self.calls = {}, []
        self.put(self.base + provider.GETTER_RVA, b'G' * 57)
        self.put(self.base + provider.ORG_SLOT_RVA, struct.pack('<Q', self.service))
        self.put(self.base + provider.KEY_SLOT_RVA, struct.pack('<Q', self.manager))
        self.put(self.service, bytes(0x2650))
        self.put(self.service, struct.pack('<Q', self.base + provider.ORG_VTABLE_RVA))
        self.put(self.service + 0xBB8, b'\1')
        self.put(self.service + 0xBC0, struct.pack('<QQQ', self.orgs, self.orgs + 2*0x1EE8, self.orgs + 2*0x1EE8))
        self.put(self.orgs, bytes(2*0x1EE8))
        self.put(self.orgs + 0x30, struct.pack('<q', 91))
        self.put(self.orgs + 0x9A0, self.string('dingOther'))
        self.put(self.orgs + 0x1EE8 + 0x30, struct.pack('<q', 92))
        self.put(self.orgs + 0x1EE8 + 0x9A0, self.string('dingTarget'))
        self.put(self.manager, bytes(0xB0))
        self.put(self.manager, b'\1')
        self.put(self.manager + 0x98, struct.pack('<QQ', self.head, 2))
        self.put(self.head, struct.pack('<QQQBB', self.other_node, self.node, self.node, 1, 1))
        self.put(self.node, bytes(0x90))
        self.put(self.node, struct.pack('<QQQBB', self.other_node, self.head, self.head, 1, 0))
        self.put(self.node + 0x20, self.string('dingTarget'))
        self.put(self.node + 0x68, b'\1')
        self.put(self.node + 0x70, struct.pack('<QQQ', self.records, self.records + 0xC0, self.records + 0xC0))
        self.put(self.other_node, bytes(0x90))
        self.put(self.other_node, struct.pack('<QQQBB', self.head, self.node, self.head, 0, 0))
        self.put(self.other_node + 0x20, self.string('dingOther'))
        self.put(self.other_node + 0x68, b'\1')
        self.put(self.other_node + 0x70, struct.pack('<QQQ', self.other_records, self.other_records + 0x60, self.other_records + 0x60))
        self.put(self.records, bytes(0xC0))
        for address, version, value in ((self.records, 5, 'wrongVersion'), (self.records + 0x60, 7, 'wrappedTarget')):
            self.put(address, b'\1')
            self.put(address + 8, struct.pack('<q', version))
            self.put(address + 0x10, b'\1')
            self.put(address + 0x18, self.string(value))

    @staticmethod
    def string(value):
        raw = value.encode('ascii')
        assert len(raw) < 16
        return raw + bytes(16 - len(raw)) + struct.pack('<QQ', len(raw), 15)

    def put(self, address, data):
        for i, byte in enumerate(data):
            self.blocks[address+i] = byte

    def read(self, address, size):
        self.calls.append((address, size))
        try:
            return bytes(self.blocks[address+i] for i in range(size))
        except KeyError:
            raise AssertionError('Unexpected memory read') from None

    def touched(self, address, size=32):
        return any(a < address+size and a+s > address for a, s in self.calls)


class PureReaderTests(unittest.TestCase):
    def setUp(self):
        self.mem = Memory()

    def select(self, enterprise='dingTarget', version=7):
        return provider.select_wrapped_key(self.mem.read, self.mem.base, enterprise, version)

    def test_exact_identity_and_version_read_only(self):
        result = provider.read_target_snapshot(self.mem.read, self.mem.base, 92, 7)
        self.assertEqual(result[:2], ('dingTarget', 'wrappedTarget'))
        self.assertFalse(self.mem.touched(self.mem.orgs + 0x9A0))
        self.assertFalse(self.mem.touched(self.mem.records + 0x18))
        self.assertFalse(self.mem.touched(self.mem.other_node + 0x68, 0x28))
        self.assertFalse(self.mem.touched(self.mem.other_records, 0x60))

    def test_missing_org_never_reads_keys_or_other_names(self):
        with self.assertRaisesRegex(ValueError, 'organization not available'):
            provider.read_target_snapshot(self.mem.read, self.mem.base, 99, 7)
        self.assertFalse(self.mem.touched(self.mem.manager, 0xB0))
        self.assertFalse(self.mem.touched(self.mem.orgs + 0x9A0))

    def test_enterprise_mismatch_never_reads_record_vectors(self):
        with self.assertRaisesRegex(ValueError, 'enterprise not cached'):
            self.select('dingMissing')
        self.assertFalse(self.mem.touched(self.mem.node + 0x68, 0x28))
        self.assertFalse(self.mem.touched(self.mem.other_node + 0x68, 0x28))

    def test_version_mismatch_never_reads_any_key(self):
        with self.assertRaisesRegex(ValueError, 'version missing'):
            self.select(version=8)
        self.assertFalse(self.mem.touched(self.mem.records + 0x18))
        self.assertFalse(self.mem.touched(self.mem.records + 0x78))

    def test_duplicate_version_rejected_before_key_read(self):
        self.mem.put(self.mem.records + 8, struct.pack('<q', 7))
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            self.select()
        self.assertFalse(self.mem.touched(self.mem.records + 0x18))
        self.assertFalse(self.mem.touched(self.mem.records + 0x78))

    def test_bad_flags_fail_closed(self):
        for location in (self.mem.manager, self.mem.node + 0x68, self.mem.records,
                         self.mem.records + 0x70):
            with self.subTest(location=location):
                self.mem = Memory()
                self.mem.put(location, b'\2')
                with self.assertRaisesRegex(ValueError, 'presence flag'):
                    self.select()

    def test_absent_record_skipped_without_version_or_key(self):
        self.mem.put(self.mem.records, b'\0')
        self.assertEqual(self.select(), 'wrappedTarget')
        self.assertFalse(self.mem.touched(self.mem.records + 8, 8))
        self.assertFalse(self.mem.touched(self.mem.records + 0x18))

    def test_missing_key_flag_prevents_wrapper_read(self):
        self.mem.put(self.mem.records + 0x70, b'\0')
        with self.assertRaisesRegex(ValueError, 'key absent'):
            self.select()
        self.assertFalse(self.mem.touched(self.mem.records + 0x78))

    def test_bad_tree_links_and_sentinel(self):
        mutations = ((self.mem.head+25, b'\0'),
                     (self.mem.node+8, struct.pack('<Q', self.mem.node)),
                     (self.mem.node, struct.pack('<Q', self.mem.node)),
                     (self.mem.node+16, struct.pack('<Q', 3)))
        for address, data in mutations:
            with self.subTest(address=address):
                self.mem = Memory()
                self.mem.put(address, data)
                with self.assertRaises(ValueError):
                    self.select()
                self.assertFalse(self.mem.touched(self.mem.records + 0x78))

    def test_bad_string_length_and_terminator(self):
        for offset, data in ((16, struct.pack('<Q', 5000)), (13, b'X')):
            self.mem = Memory()
            self.mem.put(self.mem.records+0x78+offset, data)
            with self.assertRaises(ValueError):
                self.select()

    def test_vector_crosses_address_limit(self):
        self.mem.put(self.mem.node+0x70, struct.pack('<QQQ', 0x7fffffffffa0, 0x800000000000, 0x800000000000))
        with self.assertRaisesRegex(ValueError, 'vector bounds'):
            self.select()

    def test_partial_read_and_input_types(self):
        with self.assertRaisesRegex(ValueError, 'Incomplete'):
            provider.resolve_enterprise(lambda a, n: bytes(n-1), self.mem.base, 92)
        for value in (True, '92', None):
            with self.assertRaises(TypeError):
                provider.resolve_enterprise(self.mem.read, self.mem.base, value)
        with self.assertRaises(ValueError):
            provider.validate_pointer(0x800000000000)

    def test_additional_mapping_and_conflicting_org(self):
        extra = 0x400000
        self.mem.put(self.mem.service+0x2630, b'\1')
        self.mem.put(self.mem.service+0x2638, struct.pack('<QQQ', extra, extra+0x458, extra+0x458))
        self.mem.put(extra, bytes(0x458))
        self.mem.put(extra, b'\1')
        self.mem.put(extra+0x10, struct.pack('<q', 92))
        self.mem.put(extra+0x1D0, self.mem.string('dingOther'))
        with self.assertRaisesRegex(ValueError, 'Ambiguous'):
            provider.resolve_enterprise(self.mem.read, self.mem.base, 92)


class FakeProcess:
    pid, created_filetime = 123, 456
    def __init__(self, memory):
        self.memory, self.closed = memory, False
    def read(self, address, size):
        return self.memory.read(address, size), True
    def close(self):
        self.closed = True


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.memory = Memory()
        self.proc = FakeProcess(self.memory)
        self.target = {'pid': 123, 'module_base': self.memory.base, 'exe': 'synthetic/DingTalk.exe',
                       'dll': 'synthetic/MainFrame.dll', 'process_created_filetime': 456}
        self.patches = [patch.object(provider, '_load_binary', return_value=(b'G'*57, b'M'*36)),
                        patch.object(provider, '_open_process', return_value=self.proc),
                        patch.object(provider, '_unwrap', return_value=b'K'*32)]
        self.mocks = [p.start() for p in self.patches]
        for p in self.patches:
            self.addCleanup(p.stop)

    def test_context_shared_cache_and_no_secrets_in_metadata(self):
        with provider.WindowsDingKeyProvider(self.target) as reader:
            self.assertEqual(reader.resolve_enterprise(92), 'dingTarget')
            self.assertEqual(reader.get_key(92, 7, 2), b'K'*32)
            self.memory.calls.clear()
            self.assertEqual(reader.get_key_for_enterprise('dingTarget', 7, 2), b'K'*32)
            self.assertFalse(self.memory.touched(self.memory.records+0x78))
            self.assertEqual(self.mocks[2].call_count, 1)
            self.assertEqual(reader.metadata['cache_hits'], 1)
            self.assertNotIn('wrappedTarget', json.dumps(reader.metadata))
            self.assertNotIn('KKKK', json.dumps(reader.metadata))
        self.assertTrue(self.proc.closed)
        self.assertEqual(reader.metadata['cached_key_count'], 0)
        self.assertIsNone(reader._material)
        with self.assertRaises(RuntimeError):
            reader.get_key_for_enterprise('dingTarget', 7, 2)

    def test_changed_wrapper_rejected_without_unwrap(self):
        original = self.memory.read
        count = 0
        def changing(address, size):
            nonlocal count
            if address == self.memory.records+0x78:
                count += 1
                if count == 2:
                    self.memory.put(address, self.memory.string('changedTarget'))
            return original(address, size)
        self.memory.read = changing
        with provider.WindowsDingKeyProvider(self.target) as reader:
            with self.assertRaisesRegex(ValueError, 'snapshot changed'):
                reader.get_key_for_enterprise('dingTarget', 7, 2)
        self.mocks[2].assert_not_called()

    def test_constructor_ready_and_cached_key_requires_live_validation(self):
        reader = provider.WindowsDingKeyProvider(self.target)
        try:
            self.assertEqual(reader.dll_sha256, provider.EXPECTED_SHA)
            self.assertEqual(reader.get_key_for_enterprise('dingTarget', 7, 2), b'K'*32)
            self.memory.put(self.memory.base+provider.GETTER_RVA, b'X')
            with self.assertRaisesRegex(ValueError, 'Live getter mismatch'):
                reader.get_key_for_enterprise('dingTarget', 7, 2)
        finally:
            reader.close()
        self.assertTrue(self.proc.closed)

    def test_read_time_budget(self):
        reader = provider.WindowsDingKeyProvider(self.target)
        try:
            with patch.object(provider.time, 'monotonic', side_effect=[0, 11]):
                with self.assertRaisesRegex(ValueError, 'time budget'):
                    reader.get_key_for_enterprise('dingTarget', 7, 2)
        finally:
            reader.close()

    def test_changed_tree_metadata_rejected_even_same_wrapper(self):
        original = self.memory.read
        count = 0
        def changing(address, size):
            nonlocal count
            if address == self.memory.manager+0x98:
                count += 1
                if count == 2:
                    self.memory.put(address+8, struct.pack('<Q', 3))
            return original(address, size)
        self.memory.read = changing
        with provider.WindowsDingKeyProvider(self.target) as reader:
            with self.assertRaisesRegex(ValueError, 'snapshot changed'):
                reader.get_key_for_enterprise('dingTarget', 7, 2)
        self.mocks[2].assert_not_called()

    def test_hash_failure_opens_no_process(self):
        self.mocks[0].side_effect = ValueError('Unsupported MainFrame.dll hash')
        with self.assertRaisesRegex(ValueError, 'hash'):
            with provider.WindowsDingKeyProvider(self.target):
                pass
        self.mocks[1].assert_not_called()

    def test_live_getter_vtable_identity_failures_close_handle(self):
        for kind in ('getter', 'vtable', 'creation'):
            with self.subTest(kind=kind):
                self.memory = Memory()
                self.proc = FakeProcess(self.memory)
                self.mocks[1].return_value = self.proc
                if kind == 'getter':
                    self.memory.put(self.memory.base+provider.GETTER_RVA, b'X')
                elif kind == 'vtable':
                    self.memory.put(self.memory.service, struct.pack('<Q', self.memory.base))
                else:
                    self.proc.created_filetime = 999
                with self.assertRaises(ValueError):
                    with provider.WindowsDingKeyProvider(self.target):
                        pass
                self.assertTrue(self.proc.closed)

    def test_budget_blocks_before_oversized_read(self):
        with provider.WindowsDingKeyProvider(self.target, byte_budget=100, request_byte_budget=100) as reader:
            with self.assertRaisesRegex(ValueError, 'budget'):
                reader.get_key_for_enterprise('dingTarget', 7, 2)
            self.assertLessEqual(reader.metadata['bytes_read'], 100)
        self.assertTrue(self.proc.closed)

    def test_type_and_crypto_length_rejected(self):
        with provider.WindowsDingKeyProvider(self.target) as reader:
            for args in ((92, True, 2), (92, 7, '2')):
                with self.assertRaises(TypeError):
                    reader.get_key(*args)
            with self.assertRaises(ValueError):
                reader.get_key(92, 7, 3)
            self.mocks[2].return_value = b'bad'
            with self.assertRaisesRegex(ValueError, 'length mismatch'):
                reader.get_key(92, 7, 2)
            self.assertEqual(reader.metadata['cached_key_count'], 0)


if __name__ == '__main__':
    unittest.main()
