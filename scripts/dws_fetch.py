"""Resumable local DWS fetcher. No decryption and no implicit account selection.

Raw pages preserve complete CLI JSON. The filtered snapshot includes both bounds
in the machine's local timezone. Pagination completeness says nothing about body
readability. Callers must bind an output directory to the current account scope.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import subprocess


def _runner(cmd, timeout=120, cwd=None):
    try:
        p = subprocess.run(cmd, timeout=timeout, cwd=cwd, capture_output=True)
        return p.returncode, p.stdout.decode("utf-8"), p.stderr.decode("utf-8")
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as exc:
        return -1, "", type(exc).__name__


def _write(path, value):
    temporary = path.with_name(path.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2, allow_nan=False)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _append(path, value):
    with path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(value, ensure_ascii=False, allow_nan=False) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def _time(value):
    if not isinstance(value, str) or not value:
        raise ValueError("timestamp must be a nonempty ISO/local datetime string")
    parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo:
        parsed = parsed.astimezone().replace(tzinfo=None)
    return parsed


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _invalid_constant(value):
    raise ValueError("nonfinite JSON number")


def _json(text):
    return json.loads(text, object_pairs_hook=_pairs, parse_constant=_invalid_constant)


def _call(runner, cmd, timeout):
    try:
        rc, stdout, _ = runner(cmd, timeout=timeout, cwd=None)
        if rc != 0:
            return None, "command_failed"
        result = _json(stdout)
        if not isinstance(result, dict):
            return None, "invalid_response_shape"
        if result.get("ok") is False or result.get("success") is False:
            return None, "business_error"
        return result, None
    except Exception as exc:
        return None, "runner_" + type(exc).__name__


def _message_payload(response):
    for value in (response, response.get("data"), response.get("result")):
        if isinstance(value, dict) and isinstance(value.get("messages"), list):
            return value
    return None


def _checkpoint_page(response, request_time, hi, pages):
    payload = _message_payload(response)
    state = {"pages": pages, "cursor": request_time, "complete": False,
             "stop_reason": "invalid_response_shape"}
    if payload is None:
        return state
    for value in (response, payload):
        if (any(value.get(flag) is True for flag in ("truncated", "truncatedByPageLimit", "truncatedByResultLimit"))
                or value.get("failedCount", 0) or value.get("failures")):
            state["stop_reason"] = "upstream_partial"
            return state
    messages = payload["messages"]
    times = []
    try:
        times = [_time(m.get("createTime")) for m in messages]
    except (AttributeError, ValueError, TypeError):
        state["stop_reason"] = "invalid_message_time"
        return state
    more = payload.get("hasMore", response.get("hasMore"))
    if more is False:
        state.update(complete=True, stop_reason="source_complete")
        return state
    if times and min(times) > hi:
        state.update(complete=True, stop_reason="window_complete")
        return state
    if more is not True:
        state["stop_reason"] = "pagination_unknown"
        return state
    next_page = payload.get("nextPage", response.get("nextPage"))
    next_time = next_page.get("time") if isinstance(next_page, dict) else None
    try:
        advancing = _time(next_time) > _time(request_time)
    except (TypeError, ValueError):
        advancing = False
    if not messages or not advancing:
        state["stop_reason"] = "pagination_no_progress"
        return state
    state.update(cursor=next_time, stop_reason="more")
    return state


def _read_pages(path):
    pages = []
    if not path.exists():
        return pages, None
    try:
        with path.open(encoding="utf-8") as stream:
            for line in stream:
                if not line.strip():
                    continue
                page = _json(line)
                if not isinstance(page, dict) or not isinstance(page.get("response"), dict):
                    return pages, "raw_page_invalid"
                pages.append(page)
    except (OSError, ValueError, UnicodeError):
        return pages, "raw_page_invalid"
    return pages, None


def fetch_snapshot(out_dir, start, end, conversation_ids=None, kind="all",
                   resume=False, runner=None, max_pages=2000):
    """Return (Path to api_snapshot.json, machine-readable completeness report).

    New runs require start/end. Resume accepts None for either bound and loads
    the fixed manifest value; explicit mismatches raise ValueError before any
    command or raw-file mutation. The same applies to conversation_ids/kind.
    CLI errors and stalled pagination return a partial report, never success.
    No process-wide/global state, network library, or account selection is used.
    """
    runner = runner or _runner
    root = Path(out_dir)
    if kind not in ("all", "direct", "group") or not isinstance(max_pages, int) or max_pages < 1:
        raise ValueError("invalid kind or max_pages")
    requested = None
    if conversation_ids is not None:
        if isinstance(conversation_ids, str):
            raise ValueError("conversation_ids must be a sequence of identifiers")
        requested = sorted(set(conversation_ids))
        if not requested or any(not isinstance(cid, str) or not cid for cid in requested):
            raise ValueError("conversation_ids must contain nonempty identifiers")
    manifest_path = root / "fetch_manifest.json"
    if manifest_path.exists():
        if not resume:
            raise ValueError("existing fetch manifest requires resume=True or a new output directory")
        manifest = _json(manifest_path.read_text(encoding="utf-8"))
        if manifest.get("version") != 1:
            raise ValueError("unsupported fetch manifest")
        for key, supplied in (("start", start), ("end", end), ("conversation_ids", requested)):
            if supplied is not None and supplied != manifest[key]:
                raise ValueError("resume scope mismatch: " + key)
        if kind != manifest["kind"]:
            raise ValueError("resume scope mismatch: kind")
        start, end, requested = manifest["start"], manifest["end"], manifest["conversation_ids"]
    else:
        if resume:
            raise ValueError("resume requested but fetch manifest is missing")
        _time(start)
        _time(end)
        if root.exists() and any(root.glob("raw/fetch-*.jsonl")):
            raise ValueError("orphan fetch raw data requires recovery, not a fresh run")
        manifest = {"version": 1, "start": start, "end": end,
                    "kind": kind, "conversation_ids": requested,
                    "discovery": {"cursor": None, "seen_cursors": [], "complete": requested is not None,
                                  "conversations": [{"conversationId": cid} for cid in requested or []]}}
    lo, hi = _time(start), _time(end)
    if lo > hi:
        raise ValueError("start is later than end")
    root.mkdir(parents=True, exist_ok=True)
    raw = root / "raw"
    raw.mkdir(exist_ok=True)
    _write(manifest_path, manifest)
    discovery = manifest["discovery"]
    errors = []
    if not discovery["complete"]:
        for _ in range(max_pages):
            cmd = ["dws", "chat", "+recent-conversations", "--start", start, "--end", end,
                   "--limit", "100", "--page-limit", "500", "--page-delay", "100",
                   "--total-timeout", "480", "--format", "json", "--timeout", "120"]
            cursor = discovery["cursor"]
            if cursor:
                cmd.extend(["--cursor", cursor])
            response, error = _call(runner, cmd, 560)
            if error:
                errors.append({"stage": "conversations", "reason": error})
                break
            _append(raw / "fetch-conversations.jsonl", {"cursor": cursor, "response": response})
            blocks = response.get("data", {}).get("succeeded", []) if isinstance(response.get("data"), dict) else None
            pagination = response.get("meta", {}).get("pagination") if isinstance(response.get("meta"), dict) else None
            if not isinstance(blocks, list) or not isinstance(pagination, dict):
                errors.append({"stage": "conversations", "reason": "invalid_response_shape"})
                break
            known = {c["conversationId"]: c for c in discovery["conversations"]}
            invalid = False
            for block in blocks:
                if not isinstance(block, dict) or not isinstance(block.get("conversations"), list):
                    invalid = True
                    break
                for conv in block["conversations"]:
                    if not isinstance(conv, dict) or not isinstance(conv.get("conversationId"), str) or not conv["conversationId"]:
                        invalid = True
                        break
                    known[conv["conversationId"]] = conv
            discovery["conversations"] = list(known.values())
            next_cursor = pagination.get("next_token")
            exhausted = pagination.get("endpoint_exhausted") is True
            failed_blocks = response.get("data", {}).get("failed")
            if invalid or failed_blocks or response.get("failedCount", 0):
                error = "upstream_partial"
            elif exhausted:
                discovery["complete"] = True
                error = None
            elif not isinstance(next_cursor, str) or not next_cursor or next_cursor == cursor or next_cursor in discovery["seen_cursors"]:
                error = "pagination_no_progress"
            else:
                if cursor:
                    discovery["seen_cursors"].append(cursor)
                discovery["cursor"] = next_cursor
                error = None
            _write(manifest_path, manifest)
            if error:
                errors.append({"stage": "conversations", "reason": error})
                break
            if discovery["complete"]:
                break
        else:
            errors.append({"stage": "conversations", "reason": "max_pages"})
    targets = [c for c in discovery["conversations"] if requested is not None or kind == "all" or c.get("type") == kind]
    statuses = []
    unique = {}
    conflicts = set()
    raw_count = outside_count = invalid_count = duplicate_count = 0
    for conv in targets:
        cid = conv["conversationId"]
        token = hashlib.sha256(cid.encode("utf-8")).hexdigest()
        raw_path = raw / ("fetch-" + token + ".jsonl")
        state_path = root / ("fetch-state-" + token + ".json")
        pages, error = _read_pages(raw_path)
        state = {"pages": 0, "cursor": start, "complete": False, "stop_reason": "new"}
        if pages:
            previous = pages[-1].get("checkpoint")
            if not isinstance(previous, dict) or previous.get("pages") != len(pages):
                error = "raw_checkpoint_invalid"
            else:
                state = dict(previous)
        if error:
            state.update(complete=False, stop_reason=error)
        else:
            for _ in range(max_pages):
                if state["complete"]:
                    break
                cmd = ["dws", "chat", "message", "list", "--conversation-id", cid,
                       "--time", state["cursor"], "--direction", "newer", "--limit", "100",
                       "--format", "json", "--timeout", "45"]
                response, error = _call(runner, cmd, 60)
                if error:
                    state.update(complete=False, stop_reason=error)
                    break
                checkpoint = _checkpoint_page(response, state["cursor"], hi, len(pages) + 1)
                page = {"conversationId": cid, "request_time": state["cursor"],
                        "response": response, "checkpoint": checkpoint}
                _append(raw_path, page)
                pages.append(page)
                state = checkpoint
                _write(state_path, {"conversationId": cid, **state})
                if state["complete"] or state["stop_reason"] != "more":
                    break
            else:
                state.update(complete=False, stop_reason="max_pages")
        for page in pages:
            payload = _message_payload(page["response"])
            if payload is None:
                continue
            for message in payload["messages"]:
                raw_count += 1
                if not isinstance(message, dict):
                    invalid_count += 1
                    continue
                mid = message.get("messageId") or message.get("openMessageId")
                if not isinstance(mid, str) or not mid or message.get("conversationId", cid) != cid:
                    invalid_count += 1
                    continue
                try:
                    timestamp = _time(message.get("createTime"))
                except (ValueError, TypeError):
                    invalid_count += 1
                    continue
                if not lo <= timestamp <= hi:
                    outside_count += 1
                    continue
                record = dict(message)
                record.setdefault("conversationId", cid)
                key = (cid, mid)
                if key in unique:
                    duplicate_count += 1
                    if record != unique[key]:
                        conflicts.add(key)
                else:
                    unique[key] = record
        _write(state_path, {"conversationId": cid, **state})
        statuses.append({"conversationId": cid, **state, "raw_file": str(raw_path)})
        if not state["complete"]:
            errors.append({"stage": "messages", "conversationId": cid, "reason": state["stop_reason"]})
    if invalid_count:
        errors.append({"stage": "snapshot", "reason": "invalid_message_records", "count": invalid_count})
    if conflicts:
        errors.append({"stage": "snapshot", "reason": "conflicting_message_records", "count": len(conflicts)})
    messages = [record for key, record in unique.items() if key not in conflicts]
    messages.sort(key=lambda m: (_time(m["createTime"]), m["conversationId"], m.get("messageId") or m["openMessageId"]))
    complete = bool(discovery["complete"] and all(s["complete"] for s in statuses) and not errors)
    report = {"version": 1, "start": start, "end": end, "bounds": "inclusive; machine local timezone",
              "complete": complete, "partial": not complete, "discovery_complete": discovery["complete"],
              "conversations": statuses, "conversation_count": len(targets), "message_count": len(messages),
              "raw_message_count": raw_count, "out_of_window_records": outside_count,
              "duplicate_records": duplicate_count, "invalid_records": invalid_count,
              "conflicting_message_count": len(conflicts), "errors": errors,
              "readability_assessed": False, "decryption_attempted": False}
    snapshot_path = root / "api_snapshot.json"
    _write(snapshot_path, {"messages": messages, "count": len(messages), "complete": complete,
                           "partial": not complete, "fetchReport": report})
    _write(root / "fetch_report.json", report)
    return snapshot_path, report
