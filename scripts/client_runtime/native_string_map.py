"""Strict version-specific MSVC string map reader; performs no process I/O itself.

The caller supplies a bounded exact-read callback and repeats the whole operation
to establish snapshot stability. Unselected values are never dereferenced.
"""
from __future__ import annotations

import hashlib
import struct


class NativeMapRejected(ValueError):
    pass


def read_string_map(map_header_bytes, read, selected_keys, max_nodes=128):
    if not isinstance(selected_keys, (set, frozenset)) or any(
        not isinstance(key, str) or not key or '*' in key for key in selected_keys
    ):
        raise NativeMapRejected('selected_keys_must_be_explicit_set')
    if not isinstance(max_nodes, int) or not 0 <= max_nodes <= 4096:
        raise NativeMapRejected('invalid_node_limit')
    if not isinstance(map_header_bytes, bytes) or len(map_header_bytes) != 16:
        raise NativeMapRejected('invalid_map_header')
    head, count = struct.unpack('<QQ', map_header_bytes)
    if count > max_nodes:
        raise NativeMapRejected('node_limit')
    fingerprint = hashlib.sha256(b'native-string-map-v1\0' + map_header_bytes)
    bytes_read = 0

    def pointer(address):
        if not isinstance(address, int) or not 0x10000 <= address < 0x800000000000:
            raise NativeMapRejected('invalid_pointer')

    def exact(address, size):
        nonlocal bytes_read
        pointer(address)
        if address + size > 0x800000000000:
            raise NativeMapRejected('invalid_read_range')
        raw = read(address, size)
        if not isinstance(raw, bytes) or len(raw) != size:
            raise NativeMapRejected('incomplete_read')
        fingerprint.update(struct.pack('<QQ', address, size))
        fingerprint.update(raw)
        bytes_read += size
        return raw

    def string(header, max_size):
        size, capacity = struct.unpack_from('<QQ', header, 16)
        if size > max_size or capacity < size or capacity > 1048576:
            raise NativeMapRejected('string_bounds')
        if capacity < 16:
            if capacity != 15 or size > 15:
                raise NativeMapRejected('invalid_inline_capacity')
            raw = header[:size + 1]
        else:
            raw = exact(struct.unpack_from('<Q', header)[0], size + 1)
        if not raw or raw[-1] != 0 or b'\0' in raw[:-1]:
            raise NativeMapRejected('invalid_string_terminator')
        try:
            return raw[:-1].decode('utf-8', errors='strict'), raw[:-1]
        except UnicodeDecodeError as error:
            raise NativeMapRejected('invalid_utf8') from error

    sentinel = exact(head, 0x20)
    minimum, root, maximum = struct.unpack_from('<QQQ', sentinel)
    if sentinel[0x19] != 1 or sentinel[0x18] != 1:
        raise NativeMapRejected('invalid_sentinel')
    if count == 0:
        if (minimum, root, maximum) != (head, head, head):
            raise NativeMapRejected('nonempty_links_for_empty_map')
        return {'keys': [], 'values': {}, 'selected_value_evidence': {},
                'node_count': 0, 'bytes_read': bytes_read,
                'fingerprint_sha256': fingerprint.hexdigest(),
                'stability_requires_caller_reread': True}
    if head in (minimum, root, maximum):
        raise NativeMapRejected('empty_link_for_nonempty_map')
    nodes = {}
    stack = [(root, head, None, None)]
    while stack:
        address, parent_expected, lower, upper = stack.pop()
        if address in nodes:
            raise NativeMapRejected('cycle_or_shared_node')
        if len(nodes) >= count:
            raise NativeMapRejected('node_count_exceeded')
        # Do not read unselected value headers or heap strings.
        raw = exact(address, 0x40)
        left, parent, right = struct.unpack_from('<QQQ', raw)
        if raw[0x19] != 0 or raw[0x18] not in (0, 1):
            raise NativeMapRejected('invalid_node_flags')
        if parent != parent_expected:
            raise NativeMapRejected('parent_mismatch')
        key, key_bytes = string(raw[0x20:0x40], 1024)
        if ((lower is not None and key_bytes <= lower) or
                (upper is not None and key_bytes >= upper)):
            raise NativeMapRejected('key_order_or_duplicate')
        nodes[address] = {'left': left, 'right': right, 'key': key,
                          'key_bytes': key_bytes, 'color': raw[0x18]}
        for child, low, high in ((right, key_bytes, upper), (left, lower, key_bytes)):
            pointer(child)
            if child != head:
                stack.append((child, address, low, high))
    if len(nodes) != count:
        raise NativeMapRejected('node_count_mismatch')
    ordered = sorted(nodes, key=lambda address: nodes[address]['key_bytes'])
    if ordered[0] != minimum or ordered[-1] != maximum:
        raise NativeMapRejected('sentinel_extrema_mismatch')
    if nodes[root]['color'] != 1:
        raise NativeMapRejected('root_not_black')
    # Iterative post-order validates red-black invariants without recursive depth.
    heights = {head: 1}
    pending = [(root, False)]
    while pending:
        address, finishing = pending.pop()
        if address == head:
            continue
        node = nodes[address]
        left, right = node['left'], node['right']
        if not finishing:
            pending.extend(((address, True), (right, False), (left, False)))
            continue
        if heights[left] != heights[right]:
            raise NativeMapRejected('black_height_mismatch')
        if node['color'] == 0 and any(
            child != head and nodes[child]['color'] == 0 for child in (left, right)
        ):
            raise NativeMapRejected('red_parent_and_child')
        heights[address] = heights[left] + node['color']
    values, evidence = {}, {}
    for address in ordered:
        key = nodes[address]['key']
        if key in selected_keys:
            value, value_bytes = string(exact(address + 0x40, 0x20), 32768)
            values[key] = value
            evidence[key] = {'node_address': hex(address),
                             'value_sha256': hashlib.sha256(value_bytes).hexdigest(),
                             'utf8_bytes': len(value_bytes)}
    return {'keys': [nodes[address]['key'] for address in ordered],
            'values': values, 'selected_value_evidence': evidence,
            'node_count': count, 'bytes_read': bytes_read,
            'fingerprint_sha256': fingerprint.hexdigest(),
            'stability_requires_caller_reread': True}
