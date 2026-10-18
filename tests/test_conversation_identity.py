"""Synthetic Conversation objects; no Windows processes or real conversations."""
import importlib.util
from pathlib import Path
import struct
from types import SimpleNamespace
import unittest
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'scripts/client_runtime/conversation_identity.py'
SPEC = importlib.util.spec_from_file_location('conversation_identity_under_test', PATH)
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class Memory:
    base = 0x180000000
    def __init__(self):
        self.data, self.calls, self.regions = {}, [], []
        self.heap = 0x700000
        self.put(self.base+runtime.VTABLE_RVA, struct.pack('<Q', self.base+0xF84400))

    def put(self, address, data):
        self.data.update({address+i: value for i, value in enumerate(data)})

    def read(self, address, size):
        self.calls.append((address, size))
        try:
            return bytes(self.data[address+i] for i in range(size))
        except KeyError:
            raise runtime.CandidateRejected('unmapped_synthetic_memory') from None

    def string(self, value):
        data = value.encode()
        if len(data) <= 15:
            return data + bytes(16-len(data)) + struct.pack('<QQ', len(data), 15)
        address = self.heap
        self.heap += 0x1000
        self.put(address, data+b'\0')
        return struct.pack('<QQQQ', address, 0, len(data), max(31, len(data)))

    def object(self, address=0x200000, cid='cid/target', native='123:456', org='92', preferred=0,
               values=None):
        self.put(address, bytes(0x3B8))
        self.put(address, struct.pack('<Q', self.base+runtime.VTABLE_RVA))
        self.put(address+0x70, self.string(native))
        self.put(address+0x3B0, struct.pack('<q', preferred))
        values = {'id': org, 'openConversationId': cid, 'org_id': org} if values is None else values
        assert 1 <= len(values) <= 3
        keys = sorted(values)
        head = address+0x1000
        nodes = [head+0x100+i*0x100 for i in range(len(keys))]
        middle = len(keys)//2
        root = nodes[middle]
        self.put(head, struct.pack('<QQQBB', nodes[0], root, nodes[-1], 1, 1)+bytes(6))
        for i, (key, node) in enumerate(zip(keys, nodes)):
            parent = head if i == middle else root
            left = nodes[0] if i == middle and middle else head
            right = nodes[-1] if i == middle and middle+1 < len(nodes) else head
            color = 0 if len(keys) == 2 and i != middle else 1
            self.put(node, struct.pack('<QQQBB', left, parent, right, color, 0)+bytes(6)+self.string(key)+self.string(values[key]))
        self.put(address+0x150, struct.pack('<QQ', head, len(nodes)))
        self.regions.append((address, 0x3B8, 0x1000, 4, 0x20000))
        return address


class Process:
    pid, created_filetime = 7, 123
    def __init__(self, memory):
        self.memory, self.closed = memory, False
    def read(self, address, size):
        return self.memory.read(address, size), True
    def close(self):
        self.closed = True


class SelectionTests(unittest.TestCase):
    def test_region_enumerator_must_reach_real_system_limit_without_gaps(self):
        class SystemInfoCall:
            def __call__(self, pointer):
                pointer._obj.maximum = 0x2FFFF
        process = SimpleNamespace(k=SimpleNamespace(GetNativeSystemInfo=SystemInfoCall()))
        full = [(0, 0x10000, 0, 0, 0), (0x10000, 0x20000, 0, 0, 0)]
        process.regions = lambda: iter(full)
        self.assertEqual(list(runtime._checked_regions(process)), full)
        process.regions = lambda: iter(full[:1])
        with self.assertRaisesRegex(runtime.ScanIncomplete, 'enumeration_incomplete'):
            list(runtime._checked_regions(process))
        process.regions = lambda: iter([(0x10000, 0x20000, 0, 0, 0)])
        with self.assertRaisesRegex(runtime.ScanIncomplete, 'invalid_region_enumeration'):
            list(runtime._checked_regions(process))

    def test_switch_paths_same_positive(self):
        for preferred, values in ((0, {'id':'92', 'org_id':'0'}),
                                  (0, {'id':'92', 'org_id':'92'}),
                                  (92, {'id':'92', 'org_id':'93'}),
                                  (0, {'orgId':'92'})):
            self.assertEqual(runtime.select_org_consensus(preferred, values), 92)

    def test_disagreement_and_invalid_fallback_are_rejected(self):
        for preferred, values in ((93, {'id':'92'}), (0, {'id':'92','org_id':'93'}),
                                  (0, {'id':'0','orgId':'92'}), (0, {'id':'','orgId':'92'}),
                                  (0, {'id':'92x'}), (0, {'orgId':'0'}),
                                  (0, {'id':'93', 'org_id':'92x'}),
                                  (0, {'id':str(2**63)}), (0, {})):
            with self.subTest(preferred=preferred, values=values):
                with self.assertRaises(runtime.CandidateRejected):
                    runtime.select_org_consensus(preferred, values)

    def test_snapshot_exact_type_and_cid(self):
        memory = Memory()
        address = memory.object()
        result = runtime.snapshot(address, memory.read, memory.base, {'cid/target'})
        self.assertEqual(result['org_id'], 92)
        self.assertEqual(result['native_conversation_id'], '123:456')
        memory.put(address, struct.pack('<Q', memory.base+runtime.VTABLE_RVA+16))
        with self.assertRaisesRegex(runtime.CandidateRejected, 'vtable_mismatch'):
            runtime.snapshot(address, memory.read, memory.base, {'cid/target'})

    def test_other_cid_does_not_read_internal_org_fields(self):
        memory = Memory()
        address = memory.object(cid='cid/other')
        with self.assertRaisesRegex(runtime.CandidateRejected, 'other_conversation'):
            runtime.snapshot(address, memory.read, memory.base, {'cid/target'})
        self.assertNotIn((address+0x3B0, 8), memory.calls)
        self.assertNotIn((address+0x70, 32), memory.calls)

    def test_bad_known_target_retains_cid_for_blocking(self):
        memory = Memory()
        address = memory.object(preferred=99)
        with self.assertRaises(runtime.CandidateRejected) as caught:
            runtime.snapshot(address, memory.read, memory.base, {'cid/target'})
        self.assertEqual(caught.exception.cid, 'cid/target')


class ProviderTests(unittest.TestCase):
    def setUp(self):
        self.memory = Memory()
        self.process = Process(self.memory)
        self.target = {'pid':7, 'exe':'synthetic/DingTalk.exe', 'dll':'synthetic/MainFrame.dll',
                       'module_base':self.memory.base, 'process_created_filetime':123}
        self.patches = [patch.object(runtime, '_load_verified_vtable', return_value=struct.pack('<Q', self.memory.base+0xF84400)),
                        patch.object(runtime, '_open_process', return_value=self.process),
                        patch.object(runtime, '_checked_regions', side_effect=lambda p: iter(self.memory.regions))]
        self.mocks = [p.start() for p in self.patches]
        for p in self.patches:
            self.addCleanup(p.stop)

    def make(self, cids=('cid/target',), **kwargs):
        return runtime.ConversationIdentityProvider(self.target, cids, **kwargs)

    def test_complete_consensus_and_closed_process(self):
        self.memory.object()
        self.memory.object(0x300000)
        reader = self.make()
        result = reader.resolve('cid/target')
        self.assertTrue(reader.summary['scan_completed'])
        self.assertTrue(self.process.closed)
        self.assertEqual(result['org_id'], 92)
        self.assertEqual(result['identity_source'], 'native_conversation_candidate_consensus')
        self.assertEqual(result['evidence']['candidate_count'], 2)
        self.assertFalse(result['evidence']['historical_identity_stable'])
        self.assertFalse(result['evidence']['native_service_cache_selection_proven'])
        result['evidence']['candidate_count'] = 999
        self.assertEqual(reader.resolve('cid/target')['evidence']['candidate_count'], 2)
        self.assertIsNone(reader.resolve('cid/not-requested'))

    def test_multiple_targets_one_scan(self):
        self.memory.object()
        self.memory.object(0x300000, cid='cid/second', native='222', org='93')
        reader = self.make(('cid/target', 'cid/second', 'cid/missing'))
        self.assertEqual(reader.resolve('cid/target')['org_id'], 92)
        self.assertEqual(reader.resolve('cid/second')['org_id'], 93)
        self.assertIsNone(reader.resolve('cid/missing'))
        self.mocks[1].assert_called_once()
        self.mocks[2].assert_called_once()

    def test_conflicting_native_or_org_rejects_entire_cid(self):
        for native, org in (('other', '92'), ('123:456', '93')):
            with self.subTest(native=native, org=org):
                self.memory = Memory()
                self.process.memory = self.memory
                self.memory.object()
                self.memory.object(0x300000, native=native, org=org)
                reader = self.make()
                self.assertIsNone(reader.resolve('cid/target'))
                self.assertEqual(reader.summary['conflicts']['cid/target'], 'candidate_identity_conflict')

    def test_invalid_target_candidate_blocks_valid_candidate(self):
        self.memory.object()
        self.memory.object(0x300000, preferred=99)
        reader = self.make()
        self.assertIsNone(reader.resolve('cid/target'))
        self.assertEqual(reader.summary['conflicts']['cid/target'], 'rejected_target_candidate')

    def test_changed_preferred_blocks_known_target(self):
        address = self.memory.object()
        original = self.memory.read
        count = 0
        def changing(location, size):
            nonlocal count
            if location == address+0x3B0:
                count += 1
                if count == 2:
                    self.memory.put(location, struct.pack('<q', 92))
            return original(location, size)
        self.memory.read = changing
        reader = self.make()
        self.assertIsNone(reader.resolve('cid/target'))
        self.assertEqual(reader.summary['rejected']['changed_on_reread'], 1)

    def test_partial_region_invalidates_all_successes(self):
        self.memory.object()
        self.memory.regions.append((0x600000, 0x1000, 0x1000, 4, 0x20000))
        original = self.process.read
        def partial(address, size):
            return (b'', False) if address == 0x600000 else original(address, size)
        self.process.read = partial
        reader = self.make()
        self.assertEqual(reader.summary['stable_candidates'], 1)
        self.assertFalse(reader.summary['scan_completed'])
        self.assertIsNone(reader.resolve('cid/target'))

    def test_budget_interrupt_not_complete(self):
        self.memory.object()
        reader = self.make(byte_budget=1000)
        self.assertFalse(reader.summary['scan_completed'])
        self.assertIsNone(reader.resolve('cid/target'))
        self.assertTrue(self.process.closed)

    def test_enumeration_failure_after_candidate_invalidates_result(self):
        self.memory.object()
        def broken(process):
            yield self.memory.regions[0]
            raise runtime.ScanIncomplete('region_enumeration_incomplete')
        self.mocks[2].side_effect = broken
        reader = self.make()
        self.assertFalse(reader.summary['scan_completed'])
        self.assertIsNone(reader.resolve('cid/target'))

    def test_no_candidates_is_not_identity_success(self):
        reader = self.make()
        self.assertTrue(reader.summary['scan_completed'])
        self.assertEqual(reader.summary['resolved_conversations'], 0)
        self.assertIsNone(reader.resolve('cid/target'))

    def test_live_vtable_or_identity_mismatch_closes(self):
        self.memory.put(self.memory.base+runtime.VTABLE_RVA, bytes(8))
        with self.assertRaisesRegex(ValueError, 'Live Conversation'):
            self.make()
        self.assertTrue(self.process.closed)
        self.process.created_filetime = 999
        with self.assertRaisesRegex(ValueError, 'identity mismatch'):
            self.make()

    def test_hash_mismatch_opens_no_handle(self):
        self.mocks[0].side_effect = ValueError('Unsupported MainFrame.dll hash')
        with self.assertRaises(ValueError):
            self.make()
        self.mocks[1].assert_not_called()

    def test_chunk_overlap_candidate_seen_once(self):
        address = self.memory.object(0x200010)
        self.memory.put(0x200000, bytes(16))
        self.memory.regions[0] = (0x200000, 0x3C8, 0x1000, 4, 0x20000)
        reader = self.make(chunk_size=23)
        self.assertEqual(reader.summary['candidates'], 1)
        self.assertEqual(reader.resolve('cid/target')['evidence']['candidate_objects'][0]['object_address'], hex(address))

    def test_excluded_noaccess_region_is_diagnosed(self):
        self.memory.object()
        self.memory.regions.append((0x600000, 0x1000, 0x1000, 1, 0x20000))
        reader = self.make()
        self.assertEqual(reader.summary['unreadable_regions_excluded'], 1)
        self.assertTrue(reader.summary['scan_completed'])


if __name__ == '__main__':
    unittest.main()
