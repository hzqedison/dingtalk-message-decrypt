"""Bounded candidate consensus for current native Conversation identity.

This is not proof of native service cache selection or historical message org.
No messages, keys, target calls, process writes, UI actions, or network.
"""
from collections import Counter, defaultdict
import copy
import ctypes
from datetime import datetime, timezone
import hashlib
from pathlib import Path
import re
import struct
import sys
import time

# Existing runtime scripts use sibling imports. Restore the caller's path.
sys.path.insert(0, str(Path(__file__).resolve().parent))
try:
    from capture_message_evidence import ReadOnlyProcess
    from capture_typed_messages import EXPECTED_SHA, read_string
    from native_string_map import read_string_map
finally:
    sys.path.pop(0)

VTABLE_RVA = 0x6DF44C8
SELECTED = frozenset({'openConversationId', 'id', 'org_id', 'orgId'})
SOURCE = 'native_conversation_candidate_consensus'
LIMIT = 0x800000000000


class CandidateRejected(ValueError):
    def __init__(self, reason, cid=None):
        super().__init__(reason)
        self.cid = cid


class ScanIncomplete(ValueError):
    pass


def _pointer(value):
    if type(value) is not int or value % 8 or not 0x10000 <= value < LIMIT:
        raise CandidateRejected('invalid_pointer')
    return value


def _positive(value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9]{1,19}', value):
        return None
    number = int(value)
    return number if 0 < number <= 0x7fffffffffffffff else None


def select_org_consensus(preferred, extension):
    """Both native switch paths must select the same positive org, without guessing."""
    if type(preferred) is not int or not -(2**63) <= preferred < 2**63:
        raise CandidateRejected('invalid_preferred_org')
    if not isinstance(extension, dict):
        raise TypeError('extension must be a dict')
    # Presence, not validity, of id suppresses fallback to orgId in native code.
    fallback = _positive(extension['id']) if 'id' in extension else _positive(extension.get('orgId'))
    alternative = None
    if preferred <= 0 and 'org_id' in extension:
        raw = extension['org_id']
        # Do not guess native partial-number parsing for malformed input.
        if not isinstance(raw, str) or not re.fullmatch(r'-?[0-9]{1,19}', raw) or not -(2**63) <= int(raw) < 2**63:
            raise CandidateRejected('invalid_extension_org_id')
        alternative = int(raw) if int(raw) > 0 else None
    switched = preferred if preferred > 0 else (alternative or fallback)
    if fallback is None or switched != fallback:
        raise CandidateRejected('org_switch_paths_disagree_or_nonpositive')
    return fallback


def snapshot(address, read, module_base, target_cids):
    """Same-object relevant fields with full read/address fingerprint; no process I/O."""
    _pointer(address)
    _pointer(module_base)
    cid = None
    fingerprint = hashlib.sha256()
    def exact(location, size):
        if type(location) is not int or not 0x10000 <= location < LIMIT or not 0 < size <= 65536 or location+size > LIMIT:
            raise CandidateRejected('invalid_read_range', cid)
        raw = read(location, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise CandidateRejected('incomplete_candidate_read', cid)
        fingerprint.update(struct.pack('<QQ', location, size))
        fingerprint.update(raw)
        return raw
    try:
        if struct.unpack('<Q', exact(address, 8))[0] != module_base + VTABLE_RVA:
            raise CandidateRejected('vtable_mismatch')
        header = exact(address+0x150, 16)
        identity = read_string_map(header, exact, {'openConversationId'})
        cid = identity['values'].get('openConversationId')
        if cid not in target_cids:
            raise CandidateRejected('other_conversation')
        extension = read_string_map(header, exact, SELECTED)
        if extension['values'].get('openConversationId') != cid or extension['keys'] != identity['keys']:
            raise CandidateRejected('extension_changed', cid)
        native_header = exact(address+0x70, 32)
        native, _ = read_string(native_header, address+0x70, exact, 128)
        if not native or any(ord(c) < 32 for c in native):
            raise CandidateRejected('invalid_native_cid', cid)
        preferred = struct.unpack('<q', exact(address+0x3B0, 8))[0]
        org_id = select_org_consensus(preferred, extension['values'])
        return {'api_conversation_id': cid, 'native_conversation_id': native,
                'org_id': org_id, 'preferred_org_id': preferred,
                'extension_selected': extension['values'],
                'snapshot_sha256': fingerprint.hexdigest(),
                'extension_fingerprint_sha256': extension['fingerprint_sha256']}
    except ScanIncomplete:
        raise
    except (ValueError, IndexError, struct.error) as error:
        reason = str(error) if isinstance(error, ValueError) else 'malformed_candidate'
        raise CandidateRejected(reason, cid if cid in target_cids else None) from None


def aggregate_candidates(candidates, blocked_cids=()):
    """Reject any known target conflict; stable duplicates must agree on CID and org."""
    groups = defaultdict(list)
    blocked = set(blocked_cids)
    for item in candidates:
        groups[item['api_conversation_id']].append(item)
    accepted, conflicts = {}, {}
    for cid, items in groups.items():
        identities = {(row['native_conversation_id'], row['org_id']) for row in items}
        if cid in blocked or len(identities) != 1:
            conflicts[cid] = 'rejected_target_candidate' if cid in blocked else 'candidate_identity_conflict'
            continue
        native, org_id = next(iter(identities))
        accepted[cid] = {'org_id': org_id, 'native_conversation_id': native,
                         'api_conversation_id': cid, 'identity_source': SOURCE,
                         'historical_identity_proven': False,
                         'evidence': {'candidate_count': len(items),
                                      'same_object_double_read': True,
                                      'org_switch_paths_agree': True,
                                      'native_service_cache_selection_proven': False,
                                      'historical_identity_stable': False,
                                      'candidate_objects': [
                                          {key: row[key] for key in ('object_address', 'snapshot_sha256',
                                                                    'extension_fingerprint_sha256')}
                                          for row in items]}}
    for cid in blocked:
        conflicts.setdefault(cid, 'rejected_target_candidate')
    return accepted, conflicts


def _load_verified_vtable(path, base):
    import pefile
    raw = Path(path).read_bytes()
    if hashlib.sha256(raw).hexdigest() != EXPECTED_SHA:
        raise ValueError('Unsupported MainFrame.dll hash')
    pe = pefile.PE(data=raw, fast_load=True)
    try:
        slot = pe.get_data(VTABLE_RVA, 8)
        if len(slot) != 8:
            raise ValueError('Incomplete Conversation vtable')
        function_rva = struct.unpack('<Q', slot)[0] - pe.OPTIONAL_HEADER.ImageBase
        if function_rva != 0xF84400:
            raise ValueError('Unexpected Conversation vtable layout')
        return struct.pack('<Q', base + function_rva)
    finally:
        pe.close()


def _open_process(target):
    return ReadOnlyProcess(target['pid'], target['exe'])


def _checked_regions(process):
    """ReadOnlyProcess.regions silently stops on failure; verify actual address-space end."""
    class SystemInfo(ctypes.Structure):
        _fields_ = [('oem', ctypes.c_uint32), ('page_size', ctypes.c_uint32),
                    ('minimum', ctypes.c_void_p), ('maximum', ctypes.c_void_p),
                    ('mask', ctypes.c_size_t), ('processors', ctypes.c_uint32),
                    ('processor_type', ctypes.c_uint32), ('granularity', ctypes.c_uint32),
                    ('level', ctypes.c_uint16), ('revision', ctypes.c_uint16)]
    info = SystemInfo()
    process.k.GetNativeSystemInfo.argtypes = [ctypes.POINTER(SystemInfo)]
    process.k.GetNativeSystemInfo.restype = None
    process.k.GetNativeSystemInfo(ctypes.byref(info))
    maximum = info.maximum or 0
    if not 0x10000 <= maximum < LIMIT:
        raise ScanIncomplete('invalid_system_address_limit')
    end = 0
    for region in process.regions():
        base, size, state, protect, kind = region
        if type(base) is not int or type(size) is not int or base != end or size <= 0 or base+size > LIMIT:
            raise ScanIncomplete('invalid_region_enumeration')
        end = base + size
        yield region
        if end > maximum:
            return
    if end <= maximum:
        raise ScanIncomplete('region_enumeration_incomplete')


class ConversationIdentityProvider:
    """Scan once at construction; resolve only immutable, completed-scan consensus."""
    def __init__(self, target, target_cids, *, seconds=40, byte_budget=3*1024**3,
                 chunk_size=4*1024**2):
        if not isinstance(target, dict):
            raise TypeError('target must be a dict')
        if isinstance(target_cids, (str, bytes)):
            raise TypeError('target_cids must be a collection of exact CIDs')
        self.target_cids = frozenset(target_cids)
        if not self.target_cids or any(not isinstance(cid, str) or not cid or len(cid)>512 or any(ord(c)<32 for c in cid) for cid in self.target_cids):
            raise ValueError('Invalid target CIDs')
        if type(target.get('pid')) is not int or not 0 < target['pid'] <= 0xffffffff:
            raise ValueError('Invalid target pid')
        self.base = _pointer(target.get('module_base'))
        for key in ('dll', 'exe'):
            if not isinstance(target.get(key), (str, Path)) or not str(target[key]):
                raise TypeError(key + ' must be a path')
        if type(seconds) not in (int, float) or not 0 < seconds <= 40:
            raise ValueError('seconds must be between 0 and 40')
        if type(byte_budget) is not int or not 0 < byte_budget <= 3*1024**3:
            raise ValueError('Invalid byte budget')
        if type(chunk_size) is not int or not 16 <= chunk_size <= 4*1024**2:
            raise ValueError('Invalid scan chunk size')
        expected = _load_verified_vtable(target['dll'], self.base)
        self._resolved = {}
        self._process = None
        self._closed = False
        started = time.monotonic()
        deadline = started + seconds
        rejected, blocked, seen, candidates = Counter(), set(), set(), []
        self.summary = {'pid': target['pid'], 'dll_sha256': EXPECTED_SHA,
                        'vtable_rva': hex(VTABLE_RVA), 'bytes_read': 0,
                        'scan_completed': False, 'candidates': 0, 'regions_scanned': 0,
                        'regions_excluded': 0, 'unreadable_regions_excluded': 0,
                        'target_conversation_count': len(self.target_cids),
                        'started_utc': datetime.now(timezone.utc).isoformat(),
                        'identity_source': SOURCE, 'historical_identity_stable': False,
                        'native_service_cache_selection_proven': False}

        def read(address, size):
            if time.monotonic() >= deadline or self.summary['bytes_read']+size > byte_budget:
                raise ScanIncomplete('time_or_byte_budget')
            self.summary['bytes_read'] += size
            data, complete = self._process.read(address, size)
            if not complete or not isinstance(data, bytes) or len(data) != size:
                raise CandidateRejected('incomplete_read')
            return data

        incomplete = False
        try:
            self._process = _open_process(target)
            self.summary['process_created_filetime'] = self._process.created_filetime
            expected_created = target.get('process_created_filetime')
            if self._process.pid != target['pid'] or (expected_created is not None and expected_created != self._process.created_filetime):
                raise ValueError('Process identity mismatch')
            if read(self.base+VTABLE_RVA, 8) != expected:
                raise ValueError('Live Conversation vtable mismatch')
            needle = struct.pack('<Q', self.base + VTABLE_RVA)
            for base, size, state, protect, kind in _checked_regions(self._process):
                if time.monotonic() >= deadline:
                    raise ScanIncomplete('time_or_byte_budget')
                eligible = state == 0x1000 and kind in (0x20000, 0x40000) and not protect & 0x101 and protect & 0xff in (2, 4, 8)
                if not eligible:
                    self.summary['regions_excluded'] += 1
                    if state == 0x1000 and (protect & 0x101 or protect & 0xff not in (2, 4, 8, 0x10, 0x20, 0x40, 0x80)):
                        self.summary['unreadable_regions_excluded'] += 1
                    continue
                self.summary['regions_scanned'] += 1
                offset = 0
                while offset < size:
                    count = min(chunk_size, size-offset)
                    try:
                        raw = read(base+offset, count)
                    except CandidateRejected:
                        rejected['incomplete_region_read'] += 1
                        incomplete = True
                        break
                    pos = raw.find(needle)
                    while pos >= 0:
                        if time.monotonic() >= deadline:
                            raise ScanIncomplete('time_or_byte_budget')
                        address = base+offset+pos
                        if address % 8 == 0 and address not in seen:
                            seen.add(address)
                            self.summary['candidates'] += 1
                            first = None
                            try:
                                first = snapshot(address, read, self.base, self.target_cids)
                                second = snapshot(address, read, self.base, self.target_cids)
                                if first != second:
                                    blocked.add(second['api_conversation_id'])
                                    raise CandidateRejected('changed_on_reread', first['api_conversation_id'])
                                candidates.append({**first, 'object_address': hex(address)})
                            except CandidateRejected as error:
                                rejected[str(error)] += 1
                                if error.cid:
                                    blocked.add(error.cid)
                                if first:
                                    blocked.add(first['api_conversation_id'])
                        pos = raw.find(needle, pos+1)
                    if offset+count >= size:
                        break
                    offset += count-7
            if read(self.base+VTABLE_RVA, 8) != expected:
                raise ScanIncomplete('live_vtable_changed')
            if not incomplete and time.monotonic() < deadline:
                self.summary['scan_completed'] = True
        except ScanIncomplete as error:
            rejected[str(error)] += 1
        except CandidateRejected as error:
            rejected[str(error)] += 1
        except OSError:
            rejected['process_or_enumeration_error'] += 1
        finally:
            self.close()
        accepted, conflicts = aggregate_candidates(candidates, blocked)
        if self.summary['scan_completed']:
            self._resolved = accepted
            for result in self._resolved.values():
                result['evidence'].update(scan_completed=True, dll_sha256=EXPECTED_SHA,
                                          process_created_filetime=self.summary['process_created_filetime'])
        self.summary.update(elapsed_seconds=time.monotonic()-started, rejected=dict(rejected),
                            stable_candidates=len(candidates), conflicts=conflicts,
                            resolved_conversations=len(self._resolved),
                            unresolved_conversations=len(self.target_cids)-len(self._resolved),
                            process_handle_closed=True)

    def resolve(self, cid):
        if not isinstance(cid, str):
            raise TypeError('cid must be a string')
        return copy.deepcopy(self._resolved.get(cid)) if cid in self.target_cids else None

    def close(self):
        process, self._process = self._process, None
        self._closed = True
        if process is not None:
            process.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
