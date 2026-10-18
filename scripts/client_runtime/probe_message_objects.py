"""Read-only inventory of target conversation JSON objects, not a decryptor.

Keeps selected message fields and shape metadata only. No sibling identity joins.
Standalone objects are context-unknown: absence of a quote ancestor is not proof
that an object was loaded as an ordinary message.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import time

from capture_message_evidence import capture
from message_evidence import EvidenceMatcher, body_text, canonical_cipher, digest, plaintext_ok, unpack


def text_state(value):
    if not isinstance(value, str):
        return "absent"
    if canonical_cipher(value):
        return "outer_cipher"
    if plaintext_ok(value):
        return "readable_candidate"
    return "envelope_or_placeholder_or_invalid"


class ObjectProbe(EvidenceMatcher):
    def __init__(self, api_file, anchor_files=()):
        super().__init__(api_file)
        self.target_cids = {r.get('openConversationId') or r.get('conversationId')
                            for rows in self.by_cipher.values() for r in rows}
        self.by_id = defaultdict(list)
        self.internal_cids = set()
        self.native_bindings = defaultdict(set)
        for row in self.api.get('messages', []):
            for mid in {row.get('messageId'), row.get('openMessageId')} - {None}:
                self.by_id[str(mid)].append(row)
        for path in anchor_files:
            for line in Path(path).read_text(encoding='utf-8').splitlines():
                row = json.loads(line)
                if row.get('api_source_sha256') != self.api_sha256:
                    continue
                # Reproduce full-cipher/CID association, rather than trusting saved IDs.
                obj = row.get('complete_message_object')
                matches = EvidenceMatcher.inspect(self, obj, {})
                for match in matches:
                    if match['json_path'] != '$' or match['object_sha256'] != row.get('object_sha256'):
                        continue
                    internal_cid = obj.get('conversationId')
                    if isinstance(internal_cid, str) and internal_cid.isdigit():
                        self.internal_cids.add(internal_cid)
                        self.native_bindings[(internal_cid, match['native_message_id'])].add(match['api_message_id'])

    def locator_needles(self, existing):
        # Full validation below; prefixes only locate candidate byte windows.
        # Cipher markers find objects that do not carry the external conversation ID.
        return list(dict.fromkeys(existing + [c.encode('ascii') for c in self.internal_cids]))

    def inspect(self, obj, provenance, json_path='$', depth=0, deadline=None):
        if depth > 20 or (deadline is not None and time.monotonic() >= deadline):
            return []
        obj = unpack(obj)
        results = []
        if isinstance(obj, dict):
            ext = unpack(obj.get('extension'))
            ext = ext if isinstance(ext, dict) else {}
            cid_values = {v for v in (obj.get('openConversationId'), ext.get('openConversationId'),
                          obj.get('conversationId')) if isinstance(v, str) and v.startswith('cid')}
            native_id = obj.get('messageId') or obj.get('openMessageId')
            internal_cid = obj.get('conversationId')
            internal_match = isinstance(internal_cid, str) and internal_cid in self.internal_cids
            body = body_text(obj)
            cipher = canonical_cipher(body)
            cipher_rows = self.by_cipher.get(cipher, [])
            direct_ids = {str(obj[k]) for k in ('openMessageId', 'messageId')
                          if obj.get(k) is not None and str(obj[k]).startswith('msg')}
            direct_rows = [r for mid in direct_ids for r in self.by_id.get(mid, [])]
            identity_rows = cipher_rows or direct_rows
            api_ids = {r['messageId'] for r in identity_rows}
            relevant = bool(cid_values & self.target_cids or identity_rows or internal_match)
            cid_conflict = bool(cid_values - self.target_cids)
            id_conflict = bool(direct_ids and api_ids and direct_ids - api_ids)
            if native_id and relevant and not cid_conflict:
                mid = next(iter(api_ids)) if len(api_ids) == 1 and not id_conflict else None
                if mid and cipher_rows:
                    identity_basis = 'full_cipher_unique_api_message'
                elif mid:
                    identity_basis = 'literal_api_message_id'
                else:
                    identity_basis = 'target_conversation_only_no_api_message_binding'
                if not mid and not id_conflict and internal_match:
                    known = self.native_bindings.get((internal_cid, str(native_id)), set())
                    if len(known) == 1:
                        mid = next(iter(known))
                        identity_basis = 'native_id_and_internal_cid_from_prior_full_cipher_object'
                        identity_rows = self.by_id[mid]
                if cid_values & self.target_cids:
                    identity_basis += '_and_exact_conversation'
                context = ('quoted_source' if any(part in json_path for part in
                           ('.sourceMessageModel', '.quotedMessage', '.quoteMessage')) else
                           'standalone_context_unknown' if json_path == '$' else 'non_quote_path_candidate')
                origin = ext.get('origin_text')
                content = unpack(obj.get('content'))
                encoded = json.dumps(obj, ensure_ascii=False, separators=(',', ':'))
                selected = {k: obj[k] for k in ('messageId', 'openMessageId', 'conversationId',
                            'openConversationId', 'createdAt', 'createTime', 'type', 'contentVersion', 'version') if k in obj}
                results.append({
                    'kind': 'target_message_structure_probe', 'api_source_sha256': self.api_sha256,
                    'api_message_id': mid, 'native_message_id': str(native_id),
                    'identity_basis': identity_basis, 'identity_conflict': id_conflict,
                    'api_body_encrypted': bool(mid and any(canonical_cipher(body_text(r)) for r in identity_rows)),
                    'context': context, 'json_path': json_path, 'selected_fields': selected,
                    'object_keys': sorted(obj), 'extension_keys': sorted(ext),
                    'content_keys': sorted(content) if isinstance(content, dict) else [],
                    'body_state': text_state(body), 'origin_state': text_state(origin),
                    'body_text': body if plaintext_ok(body) else None,
                    'origin_text': origin if plaintext_ok(origin) else None,
                    'cipher_sha256': digest(cipher) if cipher else None,
                    'object_sha256': digest(encoded), 'provenance': dict(provenance),
                    'limitation': 'Structure observation only; no crypto proof. Context unknown for standalone objects; no numeric-ID conversion assumed.',
                })
            for key, value in obj.items():
                if isinstance(value, (dict, list)) or (isinstance(value, str) and value.lstrip().startswith(('{', '['))):
                    results.extend(self.inspect(value, provenance, f'{json_path}.{key}', depth + 1, deadline))
        elif isinstance(obj, list):
            for index, value in enumerate(obj):
                results.extend(self.inspect(value, provenance, f'{json_path}[{index}]', depth + 1, deadline))
        return results


def summarize_probe(rows):
    unique = {(r['object_sha256'], r['context']): r for r in rows}
    items = list(unique.values())
    shapes = Counter((r['context'], r['body_state'], r['origin_state']) for r in items)
    recovered = [r for r in items if r['api_body_encrypted'] and r['body_state'] == 'readable_candidate'
                 and r['identity_basis'].startswith('literal_api_message_id') and not r['identity_conflict']]
    return {'observations': len(rows), 'unique_object_contexts': len(items),
            'unique_native_messages': len({r['native_message_id'] for r in items}),
            'unique_api_messages': len({r['api_message_id'] for r in items if r['api_message_id']}),
            'readable_body_bound_to_encrypted_api_ids': len({r['api_message_id'] for r in recovered}),
            'shapes': [{'context': k[0], 'body_state': k[1], 'origin_state': k[2], 'count': n}
                       for k, n in sorted(shapes.items())]}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--api', required=True)
    parser.add_argument('--pid', type=int, required=True)
    parser.add_argument('--exe', required=True)
    parser.add_argument('--out', required=True)
    parser.add_argument('--anchors', nargs='*', default=[])
    parser.add_argument('--seconds', type=float, default=45)
    parser.add_argument('--max-gib', type=float, default=3)
    args = parser.parse_args()
    if not (0 < args.seconds <= 60 and 0 < args.max_gib <= 8):
        parser.error('Use 0 < seconds <= 60 and 0 < max-gib <= 8')
    print(json.dumps(capture(args, lambda api: ObjectProbe(api, args.anchors), summarize_probe), ensure_ascii=False, indent=2))
