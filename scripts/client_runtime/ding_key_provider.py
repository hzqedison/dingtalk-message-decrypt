"""Version-locked, bounded reads of one organization's cached DING key.

No discovery, scanning, target calls, process writes, network, or key persistence.
Closing drops Python references; it does not promise secure memory erasure.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
import struct
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from client_compatibility import LEGACY_PROFILE, require_binary
finally:
    sys.path.pop(0)

EXPECTED_SHA = LEGACY_PROFILE.dll_sha256
GETTER_RVA, KEY_SLOT_RVA = 0x59AAF40, 0x9D70CD8
ORG_SLOT_RVA, ORG_VTABLE_RVA = 0x9D5F148, 0x82C0E30
MATERIAL_TABLE_RVA = 0x84EF581
ADDRESS_LIMIT = 0x800000000000


def _integer(value, name, low, high):
    if type(value) is not int:
        raise TypeError(name + ' must be an integer')
    if not low <= value <= high:
        raise ValueError(name + ' outside supported range')
    return value


def validate_pointer(value):
    _integer(value, 'pointer', 0x10000, ADDRESS_LIMIT - 1)
    if value % 8:
        raise ValueError('Unaligned pointer')
    return value


def _exact(read, address, size):
    _integer(address, 'read address', 0x10000, ADDRESS_LIMIT - 1)
    _integer(size, 'read size', 1, 8192)
    if address + size > ADDRESS_LIMIT:
        raise ValueError('Read crosses address limit')
    value = read(address, size)
    if not isinstance(value, bytes) or len(value) != size:
        raise ValueError('Incomplete memory read')
    return value


def _u64(read, address):
    return struct.unpack('<Q', _exact(read, address, 8))[0]


def _flag(read, address):
    value = _exact(read, address, 1)[0]
    if value not in (0, 1):
        raise ValueError('Invalid presence flag')
    return value


def _string(read, address, maximum):
    header = _exact(read, address, 32)
    length, capacity = struct.unpack_from('<QQ', header, 16)
    if not 0 < length <= maximum or not length <= capacity <= 8192:
        raise ValueError('Invalid string bounds')
    if capacity < 16:
        if capacity != 15:
            raise ValueError('Invalid inline string capacity')
        raw = header[:length + 1]
    else:
        raw = _exact(read, validate_pointer(struct.unpack_from('<Q', header)[0]), length + 1)
    if not raw.endswith(b'\0') or b'\0' in raw[:-1]:
        raise ValueError('Invalid string terminator')
    try:
        return raw[:-1].decode('ascii')
    except UnicodeDecodeError:
        raise ValueError('Invalid ASCII string') from None


def _enterprise(value):
    if not isinstance(value, str):
        raise TypeError('enterprise must be a string')
    if not re.fullmatch(r'ding[A-Za-z0-9]{1,252}', value):
        raise ValueError('Invalid enterprise identifier')
    return value


def _vector(read, address, stride):
    start, end, limit = struct.unpack('<QQQ', _exact(read, address, 24))
    if (start, end, limit) == (0, 0, 0):
        return range(0)
    validate_pointer(start)
    if not start <= end <= limit < ADDRESS_LIMIT or (end-start) % stride or (limit-start) % stride or (limit-start)//stride > 1024:
        raise ValueError('Invalid vector bounds')
    return range(start, end, stride)


def resolve_enterprise(read, base, org_id):
    """Read IDs only for other organizations, and names only for exact matches."""
    validate_pointer(base)
    _integer(org_id, 'org_id', 1, 0x7fffffffffffffff)
    service = validate_pointer(_u64(read, base + ORG_SLOT_RVA))
    if _u64(read, service) != base + ORG_VTABLE_RVA:
        raise ValueError('Organization service vtable mismatch')
    matches = []
    for flag, vector, stride, oid, corp, additional in (
        (0xBB8, 0xBC0, 0x1EE8, 0x30, 0x9A0, False),
        (0x2630, 0x2638, 0x458, 0x10, 0x1D0, True),
    ):
        if not _flag(read, service + flag):
            continue
        for entry in _vector(read, service + vector, stride):
            if additional and not _flag(read, entry):
                continue
            value = struct.unpack('<q', _exact(read, entry + oid, 8))[0]
            if value == org_id:
                matches.append(_enterprise(_string(read, entry + corp, 256)))
    if not matches:
        raise ValueError('Requested organization not available')
    if len(set(matches)) != 1:
        raise ValueError('Ambiguous organization mapping')
    return matches[0]


def select_wrapped_key(read, base, enterprise, version):
    """Search a bounded tree path; never read another enterprise/version's key."""
    validate_pointer(base)
    _enterprise(enterprise)
    _integer(version, 'version', 0, 0x7fffffff)
    manager = validate_pointer(_u64(read, base + KEY_SLOT_RVA))
    if not _flag(read, manager):
        raise ValueError('Key manager not initialized')
    head, count = struct.unpack('<QQ', _exact(read, manager + 0x98, 16))
    validate_pointer(head)
    if not 0 <= count <= 256:
        raise ValueError('Invalid enterprise map count')
    sentinel = _exact(read, head, 26)
    left, root, right = struct.unpack_from('<QQQ', sentinel)
    if sentinel[25] != 1 or sentinel[24] != 1:
        raise ValueError('Invalid map sentinel')
    for pointer in (left, root, right):
        validate_pointer(pointer)
    if not count:
        if (left, root, right) != (head, head, head):
            raise ValueError('Invalid empty map')
        raise ValueError('Requested enterprise not cached')
    if head in (left, root, right):
        raise ValueError('Invalid nonempty map')
    node, parent, seen, low, high = root, head, set(), None, None
    while node != head:
        validate_pointer(node)
        if node in seen or len(seen) >= count:
            raise ValueError('Enterprise tree cycle/count mismatch')
        seen.add(node)
        links = _exact(read, node, 26)
        lchild, actual_parent, rchild = struct.unpack_from('<QQQ', links)
        for pointer in (lchild, actual_parent, rchild):
            validate_pointer(pointer)
        if links[25] != 0 or links[24] not in (0, 1) or actual_parent != parent:
            raise ValueError('Invalid enterprise tree links')
        if node in (lchild, rchild) or (lchild == rchild and lchild != head):
            raise ValueError('Invalid enterprise tree children')
        current = _enterprise(_string(read, node + 0x20, 256))
        if (low is not None and current <= low) or (high is not None and current >= high):
            raise ValueError('Enterprise tree ordering mismatch')
        if current != enterprise:
            parent = node
            if enterprise < current:
                high, node = current, lchild
            else:
                low, node = current, rchild
            continue
        if not _flag(read, node + 0x68):
            raise ValueError('Requested enterprise has no key records')
        matches = []
        for record in _vector(read, node + 0x70, 0x60):
            if not _flag(read, record):
                continue
            candidate = struct.unpack('<q', _exact(read, record + 8, 8))[0]
            if not 0 <= candidate <= 0x7fffffff:
                raise ValueError('Invalid cached version')
            if candidate == version:
                matches.append(record)
        if len(matches) != 1:
            raise ValueError('Requested version missing or ambiguous')
        if not _flag(read, matches[0] + 0x10):
            raise ValueError('Requested key absent')
        return _string(read, matches[0] + 0x18, 4096)
    raise ValueError('Requested enterprise not cached')


def read_target_snapshot(read, base, org_id, version):
    """Pure reader. Fingerprint stays internal and includes every read/address."""
    digest = hashlib.sha256()
    def recorded(address, size):
        data = _exact(read, address, size)
        digest.update(struct.pack('<QI', address, size))
        digest.update(data)
        return data
    enterprise = resolve_enterprise(recorded, base, org_id)
    wrapped = select_wrapped_key(recorded, base, enterprise, version)
    return enterprise, wrapped, digest.digest()


def _snapshot(read, operation):
    digest = hashlib.sha256()
    def recorded(address, size):
        data = _exact(read, address, size)
        digest.update(struct.pack('<QI', address, size))
        digest.update(data)
        return data
    return operation(recorded), digest.digest()


def _load_binary(path):
    import pefile
    raw = Path(path).read_bytes()
    require_binary(raw, 'ding_key_provider')
    pe = pefile.PE(data=raw, fast_load=True)
    try:
        getter = pe.get_data(GETTER_RVA, 57)
        first = pe.get_data(MATERIAL_TABLE_RVA + 0x4D, 36)
        second = pe.get_data(MATERIAL_TABLE_RVA + 0x7F, 36)
        if len(getter) != 57 or len(first) != 36 or len(second) != 36:
            raise ValueError('Incomplete verified DLL layout')
        return getter, bytes(a ^ b for a, b in zip(first, second))
    finally:
        pe.close()


def _open_process(pid, exe):
    # Existing runtime uses sibling imports; preserve caller import paths.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    try:
        from capture_message_evidence import ReadOnlyProcess
    finally:
        sys.path.pop(0)
    return ReadOnlyProcess(pid, exe)


def _unwrap(wrapped, material, crypto_type):
    try:
        from ..ding_codec import unwrap_cached_key
    except ImportError:
        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        try:
            from ding_codec import unwrap_cached_key
        finally:
            sys.path.pop(0)
    return unwrap_cached_key(wrapped, material, crypto_type=crypto_type)


class WindowsDingKeyProvider:
    """One process handle and bounded in-memory cache for a context lifetime."""
    def __init__(self, target, *, byte_budget=8 * 1024 * 1024,
                 request_byte_budget=128 * 1024, request_seconds=10):
        if not isinstance(target, dict):
            raise TypeError('target must be a dict')
        self.target = dict(target)
        self.pid = _integer(target.get('pid'), 'pid', 1, 0xffffffff)
        self.base = validate_pointer(target.get('module_base'))
        for field in ('exe', 'dll'):
            if not isinstance(target.get(field), (str, Path)) or not str(target[field]):
                raise TypeError(field + ' must be a path')
        self.byte_budget = _integer(byte_budget, 'byte_budget', 1, 1024**3)
        self.request_byte_budget = _integer(request_byte_budget, 'request_byte_budget', 1, self.byte_budget)
        if type(request_seconds) not in (int, float) or not 0 < request_seconds <= 60:
            raise ValueError('request_seconds must be between 0 and 60')
        self.request_seconds = request_seconds
        self._process = None
        self._cache = {}
        self._getter = self._material = None
        self._closed = False
        self._bytes = self._hits = self._requests = 0
        self._created = None
        try:
            self._getter, self._material = _load_binary(self.target['dll'])
            self._process = _open_process(self.pid, self.target['exe'])
            self._created = self._process.created_filetime
            expected = self.target.get('process_created_filetime')
            if expected is not None and expected != self._created:
                raise ValueError('Process creation identity mismatch')
            self._begin_request()
            self._validate_live()
        except Exception:
            self.close()
            raise

    def __enter__(self):
        if self._closed or self._process is None:
            raise RuntimeError('Provider is closed')
        return self

    def _begin_request(self):
        self._request_start = self._bytes
        self._deadline = time.monotonic() + self.request_seconds

    def _read(self, address, size):
        if time.monotonic() >= self._deadline:
            raise ValueError('Read time budget exceeded')
        if self._bytes + size > self.byte_budget or self._bytes - self._request_start + size > self.request_byte_budget:
            raise ValueError('Read byte budget exceeded')
        self._bytes += size  # Charge attempted reads, including partial failures.
        data, complete = self._process.read(address, size)
        if not complete or not isinstance(data, bytes) or len(data) != size:
            raise ValueError('Incomplete process read')
        return data

    def _validate_live(self):
        if self._process.pid != self.pid or self._process.created_filetime != self._created:
            raise ValueError('Process identity mismatch')
        if _exact(self._read, self.base + GETTER_RVA, len(self._getter)) != self._getter:
            raise ValueError('Live getter mismatch')
        service = validate_pointer(_u64(self._read, self.base + ORG_SLOT_RVA))
        if _u64(self._read, service) != self.base + ORG_VTABLE_RVA:
            raise ValueError('Organization service vtable mismatch')

    def get_key(self, org_id, version, crypto_type):
        _integer(org_id, 'org_id', 1, 0x7fffffffffffffff)
        _integer(version, 'version', 0, 0x7fffffff)
        _integer(crypto_type, 'crypto_type', 1, 2)
        enterprise = self.resolve_enterprise(org_id)
        key = self.get_key_for_enterprise(enterprise, version, crypto_type)
        if self.resolve_enterprise(org_id) != enterprise:
            raise ValueError('Organization mapping changed during key lookup')
        return key

    def _prepare(self):
        if self._process is None or self._closed:
            raise RuntimeError('Provider requires an open context')
        self._begin_request()
        self._validate_live()

    def resolve_enterprise(self, org_id):
        _integer(org_id, 'org_id', 1, 0x7fffffffffffffff)
        self._prepare()
        operation = lambda read: resolve_enterprise(read, self.base, org_id)
        first = _snapshot(self._read, operation)
        if first != _snapshot(self._read, operation):
            raise ValueError('Organization mapping changed during read')
        return first[0]

    def get_key_for_enterprise(self, enterprise, version, crypto_type):
        """Caller must bind this enterprise to the exact requested conversation."""
        _enterprise(enterprise)
        _integer(version, 'version', 0, 0x7fffffff)
        _integer(crypto_type, 'crypto_type', 1, 2)
        self._prepare()
        self._requests += 1
        cache_id = (enterprise, version, crypto_type)
        if cache_id in self._cache:
            self._hits += 1
            return self._cache[cache_id]
        operation = lambda read: select_wrapped_key(read, self.base, enterprise, version)
        first = _snapshot(self._read, operation)
        if first != _snapshot(self._read, operation):
            raise ValueError('Target key snapshot changed during read')
        self._validate_live()
        key = _unwrap(first[0], self._material, crypto_type)
        if not isinstance(key, bytes) or len(key) != {1: 16, 2: 32}[crypto_type]:
            raise ValueError('Unwrapped key length mismatch')
        self._cache[cache_id] = key
        return key

    @property
    def dll_sha256(self):
        return EXPECTED_SHA

    @property
    def metadata(self):
        """Safe operational metadata; no keys, wrappers, or key fingerprints."""
        return {'pid': self.pid, 'process_created_filetime': self._created,
                'dll_sha256': EXPECTED_SHA, 'bytes_read': self._bytes,
                'requests': self._requests, 'cache_hits': self._hits,
                'cached_key_count': len(self._cache), 'closed': self._closed,
                'keys_written_to_disk': False, 'target_functions_called': False}

    def close(self):
        process, self._process = self._process, None
        self._cache.clear()
        self._material = self._getter = None
        self._closed = True
        if process is not None:
            process.close()

    def __exit__(self, exc_type, exc_value, traceback):
        self.close()
        return False
