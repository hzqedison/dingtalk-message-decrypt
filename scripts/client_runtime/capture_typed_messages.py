"""Bounded VM_READ-only capture of version-locked native Message/Text objects.

Uses two exact vtables, same-object CID/ID/time, strict strings, and double reads.
No target function calls, injection, keys, database access, UI actions, or writes.
Resident native objects alone do not prove their UI context or crypto invocation.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
import json
from pathlib import Path
import struct
import sys
import time

import pefile
from capture_message_evidence import ReadOnlyProcess, now
from message_evidence import canonical_cipher, digest, plaintext_ok
from probe_message_objects import ObjectProbe
from native_string_map import read_string_map, NativeMapRejected

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:
    from client_compatibility import LEGACY_PROFILE
    from client_layouts import LEGACY_LAYOUT, select_binary_layout
finally:
    sys.path.pop(0)

EXPECTED_SHA = LEGACY_PROFILE.dll_sha256
MODEL_VTABLE = LEGACY_LAYOUT.mj_model_vtable
TEXT_VTABLE = LEGACY_LAYOUT.mj_text_vtable
PROFILES = {kind: LEGACY_LAYOUT.message(kind) for kind in ('mj', 'im_chat')}


class Rejected(ValueError):
    pass


def u64(raw, offset=0):
    return struct.unpack_from('<Q', raw, offset)[0]


def read_string(header, address, read, max_length=32768):
    size, capacity = u64(header, 16), u64(header, 24)
    if size > max_length or capacity < size or capacity > 1048576:
        raise Rejected('string_bounds')
    if capacity < 16:
        if capacity != 15 or size > 15:
            raise Rejected('invalid_inline_string')
        raw = header[:size]
        if header[size] != 0:
            raise Rejected('missing_inline_terminator')
    else:
        pointer = u64(header)
        if not 0x10000 <= pointer < 0x0000800000000000:
            raise Rejected('invalid_string_pointer')
        data = read(pointer, size + 1)
        if data[-1] != 0:
            raise Rejected('missing_heap_terminator')
        raw = data[:-1]
    try:
        return raw.decode('utf-8', errors='strict'), raw
    except UnicodeError as error:
        raise Rejected('invalid_utf8') from error


def snapshot(address, read, module_base, target_cids, profile='mj', read_extensions=False, external_cids=None,
             client_layout=LEGACY_LAYOUT):
    if external_cids is not None and not read_extensions:
        raise Rejected('external_filter_requires_extensions')
    layout = client_layout.message(profile)
    model = read(address, 0x180)
    if u64(model) != module_base + layout['model_vtable']:
        raise Rejected('model_vtable_mismatch')
    cid, cid_bytes = read_string(model[0x38:0x58], address + 0x38, read, 128)
    if target_cids is not None and cid not in target_cids:
        raise Rejected('other_conversation')
    extension = None
    if read_extensions:
        if profile != 'im_chat':
            raise Rejected('extension_layout_not_enabled')
        try:
            extension = read_string_map(model[0xc8:0xd8], read,
                {'openConversationId', 'recallMessageTime', 'editCount', 'editTime'})
        except NativeMapRejected as error:
            raise Rejected('extension_' + str(error)) from error
        if external_cids is not None and extension['values'].get('openConversationId') not in external_cids:
            raise Rejected('other_external_conversation')
    if target_cids is None and (external_cids is None or extension is None):
        raise Rejected('missing_conversation_filter')
    native_id = struct.unpack_from('<q', model, 0x58)[0]
    if layout['require_status_one'] and struct.unpack_from('<i', model, 0xb8)[0] != 1:
        raise Rejected('unsupported_message_identity')
    timestamp = struct.unpack_from('<q', model, 0xa0)[0]
    if native_id <= 0 or not 1577836800000 <= timestamp <= 4133980800000:
        raise Rejected('invalid_id_or_time')
    content_address = u64(model, 8)
    if not 0x10000 <= content_address < 0x0000800000000000:
        raise Rejected('invalid_content_pointer')
    text_offset = layout['text_offset']
    content = read(content_address, text_offset + 32)
    if u64(content) != module_base + layout['text_vtable'] or struct.unpack_from('<i', content, 8)[0] != 1:
        raise Rejected(f"not_supported_text_type:{struct.unpack_from('<i', content, 8)[0]}:vtable_rva={hex(u64(content)-module_base)}")
    text, text_bytes = read_string(content[text_offset:text_offset+32], content_address + text_offset, read)
    result = {'native_conversation_id': cid, 'native_message_id': str(native_id),
            'created_at_ms': timestamp, 'text': text, 'text_sha256': digest(text_bytes),
            'content_address': hex(content_address),
            'native_decrypt_status': struct.unpack_from('<i', model, 0x178)[0],
            'native_status_at_b8': struct.unpack_from('<i', model, 0xb8)[0], 'model_profile': profile,
            'snapshot_sha256': digest(model + content + cid_bytes + text_bytes)}
    if extension is not None:
        result['extension_keys'] = extension['keys']
        result['extension_selected'] = extension['values']
        result['extension_fingerprint_sha256'] = extension['fingerprint_sha256']
    return result


def stable_snapshot(address, read, module_base, target_cids, profile='mj', read_extensions=False, external_cids=None,
                    client_layout=LEGACY_LAYOUT):
    first = snapshot(address, read, module_base, target_cids, profile, read_extensions, external_cids, client_layout)
    second = snapshot(address, read, module_base, target_cids, profile, read_extensions, external_cids, client_layout)
    if first != second:
        raise Rejected('changed_on_reread')
    return first


def check_api_time(row, api_rows):
    """API fixture timestamps are Asia/Singapore local time, at second precision."""
    expected = set()
    for item in api_rows:
        value = item.get('createTime')
        if isinstance(value, str):
            stamp = datetime.fromisoformat(value)
            if stamp.tzinfo is None:
                stamp = stamp.replace(tzinfo=timezone(timedelta(hours=8)))
            expected.add(int(stamp.timestamp()))
    if not expected or expected != {row['created_at_ms'] // 1000}:
        raise Rejected('api_time_mismatch_or_missing')


def run(args):
    dll = Path(args.dll)
    binary = dll.read_bytes()
    client_profile, client_layout = select_binary_layout(binary, 'typed_messages')
    layout = client_layout.message(args.profile)
    matcher = ObjectProbe(args.api, args.anchors)
    if not matcher.target_cids or (args.profile != 'im_chat' and not matcher.internal_cids):
        raise ValueError('No validated target conversation scope')
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=False)
    pe = pefile.PE(data=binary, fast_load=True)
    proc = ReadOnlyProcess(args.pid, args.exe)
    started = time.monotonic()
    deadline = started + args.seconds
    budget = int(args.max_gib * 1024**3)
    report = {'started_utc': now(), 'pid': args.pid, 'process_path': proc.path,
              'process_created_filetime': proc.created_filetime,
              'dll_sha256': client_profile.dll_sha256, 'module_base': hex(args.module_base),
              'client_profile': client_profile.id, 'adapter_validation': client_profile.validation,
              'model_profile': args.profile,
              'model_vtable_rva': hex(layout['model_vtable']), 'text_vtable_rva': hex(layout['text_vtable']),
              'api_source_sha256': matcher.api_sha256, 'memory_access': 'QUERY_INFORMATION | VM_READ',
              'bytes_read': 0, 'partial_reads': 0, 'model_locations': 0, 'scan_completed': False,
              'limitations': ['Version-specific native layout; resident objects may include quoted or cached messages.',
                             'Completed scan means address-space enumeration ended; inaccessible, executable and image pages are excluded.',
                             'Native decrypt-status values are observed integers, not interpreted as success.',
                             'API linkage requires exact ciphertext or an explicitly recorded prior same-object binding.',
                             'No standalone ciphertext decryption, function invocation, or full-history coverage is established.']}
    reject = Counter()
    observations = []

    def read(address, size):
        if time.monotonic() >= deadline or report['bytes_read'] + size > budget:
            raise Rejected('budget')
        data, complete = proc.read(address, size)
        report['bytes_read'] += len(data)
        if not complete:
            report['partial_reads'] += 1
            raise Rejected('incomplete_read')
        return data

    try:
        # Validate both live vtable method pointers against the version-locked PE.
        for rva in (layout['model_vtable'], layout['text_vtable']):
            disk_va = u64(pe.get_data(rva, 8))
            expected = args.module_base + disk_va - pe.OPTIONAL_HEADER.ImageBase
            if u64(read(args.module_base + rva, 8)) != expected:
                raise ValueError('Live module/vtable identity mismatch')
        seen_addresses = set()
        needle = struct.pack('<Q', args.module_base + layout['model_vtable'])
        with (out / 'observations.jsonl').open('w', encoding='utf-8') as sink:
            for base, region_size, state, protect, kind in proc.regions():
                if time.monotonic() >= deadline or report['bytes_read'] >= budget:
                    break
                if state != 0x1000 or kind not in (0x20000, 0x40000) or protect & 0x101 or (protect & 0xff) not in (2, 4, 8):
                    continue
                offset = 0
                while offset < region_size:
                    count = min(4 * 1024**2, region_size-offset, budget-report['bytes_read'])
                    if count <= 0 or time.monotonic() >= deadline:
                        break
                    try:
                        raw = read(base+offset, count)
                    except Rejected as error:
                        reject[str(error)] += 1
                        break
                    pos = raw.find(needle)
                    while pos >= 0 and time.monotonic() < deadline:
                        address = base+offset+pos
                        if address % 8 == 0 and address not in seen_addresses:
                            seen_addresses.add(address)
                            report['model_locations'] += 1
                            try:
                                row = stable_snapshot(address, read, args.module_base,
                                                      None if args.profile == 'im_chat' else matcher.internal_cids,
                                                      args.profile, read_extensions=args.profile == 'im_chat',
                                                      external_cids=matcher.target_cids if args.profile == 'im_chat' else None,
                                                      client_layout=client_layout)
                                if args.profile == 'im_chat' and row['extension_selected'].get('openConversationId') not in matcher.target_cids:
                                    raise Rejected('external_conversation_mismatch')
                                row.update(kind='native_typed_message_body', model_address=hex(address),
                                           captured_utc=now(), immediate_reread_equal=True,
                                           process_created_filetime=proc.created_filetime,
                                           api_source_sha256=matcher.api_sha256,
                                           crypto_decryption_proven=False, api_message_id=None)
                                cipher = canonical_cipher(row['text'])
                                row['body_state'] = ('outer_cipher' if cipher else
                                    'readable_candidate' if plaintext_ok(row['text']) else 'invalid_or_envelope')
                                prior = matcher.native_bindings.get((row['native_conversation_id'], row['native_message_id']), set())
                                if len(prior) == 1:
                                    row['api_message_id'] = next(iter(prior))
                                    row['api_identity_basis'] = 'native_id_and_cid_from_prior_full_cipher_object'
                                if cipher:
                                    direct = {r['messageId'] for r in matcher.by_cipher.get(cipher, [])}
                                    if len(direct) == 1:
                                        direct_id = next(iter(direct))
                                        if row['api_message_id'] and row['api_message_id'] != direct_id:
                                            raise Rejected('conflicting_api_binding')
                                        row['api_message_id'] = direct_id
                                        row['api_identity_basis'] = 'exact_full_cipher'
                                if row['api_message_id']:
                                    check_api_time(row, matcher.by_id[row['api_message_id']])
                                    row['api_time_matches_to_second'] = True
                                observations.append(row)
                                sink.write(json.dumps(row, ensure_ascii=False)+'\n')
                                sink.flush()
                            except Rejected as error:
                                reject[str(error)] += 1
                        pos = raw.find(needle, pos+1)
                    if offset + count >= region_size or count <= 7:
                        break
                    offset += count-7
            else:
                report['scan_completed'] = time.monotonic() < deadline and report['bytes_read'] < budget
    finally:
        proc.close()
        grouped = defaultdict(set)
        for row in observations:
            identity_state = (row['text_sha256'], row['created_at_ms'],
                              json.dumps(row.get('extension_selected', {}), sort_keys=True))
            grouped[(row['native_conversation_id'], row['native_message_id'])].add(identity_state)
        conflicts = {key for key, texts in grouped.items() if len(texts) > 1}
        unique = {(r['native_conversation_id'], r['native_message_id']): r for r in observations}
        readable = [r for key, r in unique.items() if key not in conflicts and r['body_state'] == 'readable_candidate']
        report.update(observations=len(observations), unique_native_messages=len(unique),
                      readable_native_messages=len(readable), conflicting_native_messages=len(conflicts),
                      api_bound_readable_messages=len({r['api_message_id'] for r in readable if r['api_message_id']}),
                      body_states=dict(Counter(r['body_state'] for r in unique.values())),
                      rejections=dict(reject), elapsed_seconds=round(time.monotonic()-started, 3), finished_utc=now())
        (out/'readable_messages.jsonl').write_text(''.join(json.dumps(r, ensure_ascii=False)+'\n' for r in readable), encoding='utf-8')
        (out/'summary.json').write_text(json.dumps(report, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')
    return report


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    for name in ('api', 'exe', 'dll', 'out'):
        p.add_argument('--'+name, required=True)
    p.add_argument('--anchors', nargs='*', default=[])
    p.add_argument('--pid', type=int, required=True)
    p.add_argument('--profile', choices=sorted(PROFILES), default='mj')
    p.add_argument('--module-base', type=lambda value: int(value, 0), required=True)
    p.add_argument('--seconds', type=float, default=45)
    p.add_argument('--max-gib', type=float, default=3)
    args = p.parse_args()
    if not (0 < args.seconds <= 60 and 0 < args.max_gib <= 8):
        p.error('Use 0 < seconds <= 60 and 0 < max-gib <= 8')
    print(json.dumps(run(args), ensure_ascii=True, indent=2))
