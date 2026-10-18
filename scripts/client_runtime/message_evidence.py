"""Strict, offline validation of DingTalk message objects against saved API data.

This module does not decrypt, access a process, or call a network service.
Only complete JSON objects and full ciphertext matches establish associations.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
import time
from collections import Counter, defaultdict
from pathlib import Path

ENVELOPE = re.compile(r"^\d+_\d+_[0-9a-fA-F]+$")
CIPHER = re.compile(r"^([A-Za-z0-9+/=\r\n\t ]+)\|\|(\d+)\|\|(\d+)\|\|(\d+)$")
START = re.compile(r'\{\s*"|"(?=\{\\"|\[\{\\")')


def digest(value: str | bytes) -> str:
    return hashlib.sha256(value.encode("utf-8") if isinstance(value, str) else value).hexdigest()


def canonical_cipher(value):
    if not isinstance(value, str):
        return None
    match = CIPHER.fullmatch(value)
    if not match:
        return None
    body = re.sub(r"[\r\n\t ]", "", match[1])
    try:
        decoded = base64.b64decode(body, validate=True)
    except (ValueError, base64.binascii.Error):
        return None
    if not decoded or base64.b64encode(decoded).decode("ascii") != body:
        return None
    return body + "||" + "||".join(match.groups()[1:])


def no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out


DECODER = json.JSONDecoder(object_pairs_hook=no_duplicates,
                          parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))


def unpack(value):
    """Decode only complete JSON-serialized containers, never repair fragments."""
    for _ in range(4):
        if not isinstance(value, str) or not value.lstrip().startswith(("{", "[", '"{')):
            break
        try:
            new = DECODER.decode(value)
        except (ValueError, RecursionError):
            break
        if new == value:
            break
        value = new
    return value


def body_text(obj):
    content = unpack(obj.get("content"))
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        text_content = unpack(content.get("textContent"))
        if isinstance(text_content, dict) and isinstance(text_content.get("text"), str):
            return text_content["text"]
        if isinstance(content.get("text"), str):
            return content["text"]
    return None


def plaintext_ok(text):
    return (isinstance(text, str) and bool(text.strip()) and
            not canonical_cipher(text.strip()) and not ENVELOPE.fullmatch(text.strip()) and
            not re.search(r"\|\|\d+\|\|\d+\|\|\d+\s*$", text) and
            not re.match(r"^\d+_\d+_", text.strip()) and
            "[加密消息" not in text and text.strip() not in {"该消息被撤回", "[不可读消息]"} and
            not any(ord(ch) < 32 and ch not in "\r\n\t" for ch in text) and
            not any(0xD800 <= ord(ch) <= 0xDFFF for ch in text))


class EvidenceMatcher:
    def __init__(self, api_file):
        self.api_file = str(Path(api_file).resolve())
        raw = Path(api_file).read_bytes()
        self.api_sha256 = digest(raw)
        self.api = json.loads(raw)
        self.by_cipher = defaultdict(list)
        self.stats = Counter()
        for row in self.api.get("messages", []):
            cipher = canonical_cipher(body_text(row))
            if cipher:
                self.by_cipher[cipher].append(row)
        self.stats["api_encrypted_body_messages"] = sum(map(len, self.by_cipher.values()))

    def inspect(self, obj, provenance, json_path="$", depth=0, deadline=None):
        if deadline is not None and time.monotonic() >= deadline:
            self.stats["deadline_reached"] += 1
            return []
        if depth > 20:
            self.stats["depth_limit"] += 1
            return []
        obj = unpack(obj)
        results = []
        if isinstance(obj, dict):
            cipher = canonical_cipher(body_text(obj))
            extension = unpack(obj.get("extension"))
            if cipher in self.by_cipher:
                self.stats["exact_cipher_objects"] += 1
                rows = self.by_cipher[cipher]
                ids = {str(r.get("messageId")) for r in rows}
                if len(ids) != 1:
                    self.stats["ambiguous_api_identity"] += 1
                else:
                    row = rows[0]
                    expected_cid = row.get("openConversationId") or row.get("conversationId")
                    cids = {str(v) for v in [obj.get("openConversationId"),
                            extension.get("openConversationId") if isinstance(extension, dict) else None,
                            obj.get("conversationId") if str(obj.get("conversationId", "")).startswith("cid") else None] if v}
                    native_id = obj.get("messageId") or obj.get("openMessageId")
                    open_id = obj.get("openMessageId")
                    api_ids = {str(v) for v in (row.get("messageId"), row.get("openMessageId")) if v}
                    text = extension.get("origin_text") if isinstance(extension, dict) else None
                    identity_conflict = bool(open_id and str(open_id) != str(row.get("openMessageId") or row["messageId"]))
                    if isinstance(native_id, str) and native_id.startswith("msg") and native_id not in api_ids:
                        identity_conflict = True
                    if cids and cids != {expected_cid}:
                        self.stats["conversation_conflict"] += 1
                    elif identity_conflict:
                        self.stats["message_identity_conflict"] += 1
                    elif not plaintext_ok(text):
                        self.stats["exact_cipher_without_valid_origin_text"] += 1
                    elif not native_id or not cids:
                        self.stats["pair_without_complete_identity"] += 1
                    else:
                        encoded = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
                        results.append({
                            "kind": "same_object_full_cipher_and_origin_text",
                            "api_message_id": row["messageId"],
                            "api_conversation_id": expected_cid,
                            "api_create_time": row.get("createTime"),
                            "native_message_id": str(native_id),
                            "identity_basis": "full_cipher_unique_api_message_and_exact_conversation",
                            "native_id_mapping_verified": str(native_id) in api_ids,
                            "cipher_sha256": digest(cipher),
                            "plaintext_sha256": digest(text),
                            "plaintext": text,
                            "complete_message_object": obj,
                            "object_sha256": digest(encoded),
                            "json_path": json_path,
                            "provenance": dict(provenance),
                            "api_source_sha256": self.api_sha256,
                            "limitation": "Associated origin_text only; not proof of full original plaintext, native/API ID mapping, a cryptographic invocation or offline decryption.",
                        })
            # Inspect nested messages separately: never borrow a parent's or sibling's fields.
            for key, value in obj.items():
                if isinstance(value, (dict, list)) or (isinstance(value, str) and value.lstrip().startswith(("{", "["))):
                    results.extend(self.inspect(value, provenance, f"{json_path}.{key}", depth + 1, deadline))
        elif isinstance(obj, list):
            for index, value in enumerate(obj):
                results.extend(self.inspect(value, provenance, f"{json_path}[{index}]", depth + 1, deadline))
        return results

    def carve(self, raw: bytes, provenance, deadline=None, encoding="utf-8"):
        """Carve complete JSON; preserve invalid surrounding bytes, reject invalid object bytes."""
        if encoding not in ("utf-8", "utf-16-le"):
            raise ValueError("Unsupported encoding")
        errors = "surrogateescape" if encoding == "utf-8" else "surrogatepass"
        if encoding == "utf-16-le" and len(raw) % 2:
            raise ValueError("UTF-16 window must contain complete code units")
        text = raw.decode(encoding, errors=errors)
        results = []
        consumed_to = -1
        for match in START.finditer(text):
            if deadline is not None and time.monotonic() >= deadline:
                self.stats["deadline_reached"] += 1
                break
            start = match.start()
            if start < consumed_to:
                continue
            try:
                value, end = DECODER.raw_decode(text, start)
                serialized = text[start:end]
                object_raw = serialized.encode(encoding, errors="strict")
            except (ValueError, UnicodeError, RecursionError):
                continue
            consumed_to = end
            self.stats["complete_json_values"] += 1
            # Character offsets are explicit; byte offset handles non-ASCII prefixes.
            byte_offset = len(text[:start].encode(encoding, errors=errors))
            source = {**provenance, "object_offset_bytes": byte_offset,
                      "encoding": encoding,
                      "raw_json_sha256": digest(object_raw), "raw_json_bytes": len(object_raw)}
            # Retain only matched message objects, not their enclosing cache/container.
            found = self.inspect(value, source, deadline=deadline)
            results.extend(found)
        return results


def summarize(observations):
    pairs = defaultdict(set)
    for row in observations:
        pairs[row["api_message_id"]].add(row["plaintext_sha256"])
    conflicts = sorted(mid for mid, texts in pairs.items() if len(texts) != 1)
    return {"observations": len(observations), "unique_messages": len(pairs),
            "conflicting_message_ids": conflicts,
            "unambiguous_messages": len(pairs) - len(conflicts)}


def audit_saved(api_file, contexts_file, out_dir):
    matcher = EvidenceMatcher(api_file)
    path = Path(contexts_file)
    raw = path.read_bytes()
    contexts = json.loads(raw)
    observations = []
    for index, row in enumerate(contexts):
        context = row.get("ctx")
        if not isinstance(context, str):
            continue
        observations.extend(matcher.carve(context.encode("utf-8"), {
            "kind": "historical_context_string", "path": str(path.resolve()),
            "source_sha256": digest(raw), "context_index": index,
            "limitation": "Old capture decoded memory with errors=ignore; raw memory bytes unavailable.",
        }))
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    (out / "observations.jsonl").write_text("".join(json.dumps(r, ensure_ascii=False) + "\n" for r in observations), encoding="utf-8")
    report = {**summarize(observations), "counters": dict(matcher.stats)}
    (out / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--api", required=True)
    parser.add_argument("--contexts", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    print(json.dumps(audit_saved(args.api, args.contexts, args.out), ensure_ascii=False, indent=2))
