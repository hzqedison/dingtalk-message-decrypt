"""Bounded read-only Windows capture of complete message JSON objects.

No debugger, injection, memory writes, UI input, key extraction or network access.
Only API-matched objects are retained; all unmatched memory is discarded.
"""
from __future__ import annotations

import argparse
import ctypes as C
from ctypes import wintypes as W
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import time

from message_evidence import EvidenceMatcher, digest, summarize


def now():
    return datetime.now(timezone.utc).isoformat()


class MBI(C.Structure):
    _fields_ = [("BaseAddress", C.c_void_p), ("AllocationBase", C.c_void_p),
                ("AllocationProtect", W.DWORD), ("PartitionId", W.WORD),
                ("RegionSize", C.c_size_t), ("State", W.DWORD),
                ("Protect", W.DWORD), ("Type", W.DWORD)]


class ReadOnlyProcess:
    def __init__(self, pid, expected_exe):
        if os.name != "nt" or C.sizeof(C.c_void_p) != 8:
            raise RuntimeError("Requires 64-bit Windows Python")
        self.k = C.WinDLL("kernel32", use_last_error=True)
        self.k.OpenProcess.argtypes = [W.DWORD, W.BOOL, W.DWORD]
        self.k.OpenProcess.restype = W.HANDLE
        self.k.CloseHandle.argtypes = [W.HANDLE]
        self.k.CloseHandle.restype = W.BOOL
        self.k.ReadProcessMemory.argtypes = [W.HANDLE, C.c_void_p, C.c_void_p, C.c_size_t, C.POINTER(C.c_size_t)]
        self.k.ReadProcessMemory.restype = W.BOOL
        self.k.VirtualQueryEx.argtypes = [W.HANDLE, C.c_void_p, C.POINTER(MBI), C.c_size_t]
        self.k.VirtualQueryEx.restype = C.c_size_t
        self.k.QueryFullProcessImageNameW.argtypes = [W.HANDLE, W.DWORD, W.LPWSTR, C.POINTER(W.DWORD)]
        self.k.QueryFullProcessImageNameW.restype = W.BOOL
        self.k.GetProcessTimes.argtypes = [W.HANDLE] + [C.POINTER(W.FILETIME)] * 4
        self.k.GetProcessTimes.restype = W.BOOL
        self.handle = self.k.OpenProcess(0x0410, False, pid)  # QUERY_INFORMATION | VM_READ only
        if not self.handle:
            raise C.WinError(C.get_last_error())
        try:
            buf = C.create_unicode_buffer(32768)
            size = W.DWORD(len(buf))
            if not self.k.QueryFullProcessImageNameW(self.handle, 0, buf, C.byref(size)):
                raise C.WinError(C.get_last_error())
            self.path = buf.value
            if Path(self.path).name.lower() != "dingtalk.exe" or os.path.normcase(os.path.realpath(self.path)) != os.path.normcase(os.path.realpath(expected_exe)):
                raise ValueError("Process image does not match the specified DingTalk executable")
            times = [W.FILETIME() for _ in range(4)]
            if not self.k.GetProcessTimes(self.handle, *(C.byref(t) for t in times)):
                raise C.WinError(C.get_last_error())
            self.created_filetime = (times[0].dwHighDateTime << 32) | times[0].dwLowDateTime
            self.pid = pid
        except Exception:
            self.close()
            raise

    def read(self, address, size):
        buf = C.create_string_buffer(size)
        count = C.c_size_t()
        ok = self.k.ReadProcessMemory(self.handle, address, buf, size, C.byref(count))
        # A partial read must never be treated as a full snapshot.
        return buf.raw[:count.value], bool(ok and count.value == size)

    def regions(self):
        address = 0
        while address < 0x0000800000000000:
            info = MBI()
            got = self.k.VirtualQueryEx(self.handle, address, C.byref(info), C.sizeof(info))
            if not got:
                return
            base = info.BaseAddress or 0
            end = base + info.RegionSize
            if end <= address:
                raise RuntimeError("Non-progressing VirtualQueryEx")
            yield base, info.RegionSize, info.State, info.Protect, info.Type
            address = end

    def close(self):
        if self.handle:
            self.k.CloseHandle(self.handle)
            self.handle = None


def candidate_windows(data, needles, radius=32768):
    """Merge overlapping bounded windows around target-conversation markers."""
    intervals = []
    for needle in needles:
        pos = data.find(needle)
        while pos != -1:
            intervals.append((max(0, pos - radius), min(len(data), pos + len(needle) + radius)))
            pos = data.find(needle, pos + len(needle))
    last = None
    for start, end in sorted(intervals):
        if last is not None and start <= last[1] and max(last[1], end) - last[0] <= 131072:
            last[1] = max(last[1], end)
        else:
            if last is not None:
                yield tuple(last)
            last = [start, end]
    if last is not None:
        yield tuple(last)


def encoded_windows(data, needles):
    for lo, hi in candidate_windows(data, needles):
        yield lo, hi, "utf-8"
    wide = [n.decode("ascii").encode("utf-16-le") for n in needles]
    for lo, hi in candidate_windows(data, wide):
        for alignment in (0, 1):
            start = lo + alignment
            end = hi - (hi - start) % 2
            if end > start:
                yield start, end, "utf-16-le"


def capture(args, matcher_factory=EvidenceMatcher, summary_func=summarize):
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=False)
    matcher = matcher_factory(args.api)
    cids = {r.get("openConversationId") or r.get("conversationId") for rows in matcher.by_cipher.values() for r in rows}
    # Drop only the CID prefix for locating JSON-escaped '/' variants. Validation still requires the full exact CID.
    needles = [cid.split("/", 1)[-1].encode("ascii") for cid in cids if isinstance(cid, str) and len(cid) > 12]
    if hasattr(matcher, "locator_needles"):
        needles = matcher.locator_needles(needles)
    if not needles:
        raise ValueError("No usable API conversation markers")
    proc = ReadOnlyProcess(args.pid, args.exe)
    started = time.monotonic()
    report = {"started_utc": now(), "pid": args.pid, "process_path": proc.path,
              "process_created_filetime": proc.created_filetime, "api_source_sha256": matcher.api_sha256,
              "memory_access": "PROCESS_QUERY_INFORMATION | PROCESS_VM_READ", "bytes_read": 0,
              "reread_bytes": 0, "rereads_skipped_by_budget": 0,
              "regions_scanned": 0, "regions_skipped": 0, "partial_reads": 0, "candidate_windows": 0,
              "changed_objects_rejected": 0, "scan_completed": False,
              "limitations": ["Only committed readable private/mapped non-executable pages; UTF-8/UTF-16LE JSON only.",
                              "Bounded scan and currently resident objects only; absence is not proof of impossibility.",
                              "Object association and repeated byte reads do not prove a decryption function invocation."]}
    observations = []
    seen = set()
    budget = int(args.max_gib * 1024**3)
    chunk_size, overlap = 4 * 1024**2, 65536
    deadline = started + args.seconds
    try:
        with (out / "observations.jsonl").open("w", encoding="utf-8") as sink:
            for base, size, state, protect, kind in proc.regions():
                if time.monotonic() >= deadline or report["bytes_read"] >= budget:
                    report["stop_reason"] = "time_or_byte_budget"
                    break
                if state != 0x1000 or kind not in (0x20000, 0x40000) or protect & (0x100 | 0x01) or (protect & 0xff) not in (0x02, 0x04, 0x08):
                    report["regions_skipped"] += 1
                    continue
                report["regions_scanned"] += 1
                offset = 0
                while offset < size and time.monotonic() < deadline and report["bytes_read"] < budget:
                    count = min(chunk_size, size - offset, budget - report["bytes_read"])
                    data, complete = proc.read(base + offset, count)
                    report["bytes_read"] += len(data)
                    if not complete:
                        report["partial_reads"] += 1
                    for lo, hi, encoding in encoded_windows(data, needles):
                        if time.monotonic() >= deadline:
                            break
                        report["candidate_windows"] += 1
                        provenance = {"kind": "read_only_process_memory", "pid": args.pid,
                                      "process_created_filetime": proc.created_filetime,
                                      "captured_utc": now(), "window_address": hex(base + offset + lo),
                                      "window_read_complete": complete}
                        for row in matcher.carve(data[lo:hi], provenance, deadline=deadline, encoding=encoding):
                            p = row["provenance"]
                            address = base + offset + lo + p["object_offset_bytes"]
                            key = (address, p["raw_json_sha256"], row.get("api_message_id"),
                                   row.get("plaintext_sha256") or row.get("object_sha256"))
                            if key in seen:
                                continue
                            seen.add(key)
                            if time.monotonic() >= deadline or report["bytes_read"] + p["raw_json_bytes"] > budget:
                                report["rereads_skipped_by_budget"] += 1
                                break
                            raw_again, ok = proc.read(address, p["raw_json_bytes"])
                            report["bytes_read"] += len(raw_again)
                            report["reread_bytes"] += len(raw_again)
                            if not ok or digest(raw_again) != p["raw_json_sha256"]:
                                report["changed_objects_rejected"] += 1
                                continue
                            p["object_address"] = hex(address)
                            p["immediate_reread_equal"] = True
                            p["reread_utc"] = now()
                            observations.append(row)
                            sink.write(json.dumps(row, ensure_ascii=False) + "\n")
                            sink.flush()
                    if count <= overlap or offset + count >= size:
                        break
                    offset += count - overlap
            else:
                report["scan_completed"] = time.monotonic() < deadline and report["bytes_read"] < budget
                report["stop_reason"] = "address_space_enumerated" if report["scan_completed"] else "time_or_byte_budget"
    finally:
        proc.close()
        report.update(summary_func(observations))
        report["elapsed_seconds"] = round(time.monotonic() - started, 3)
        report["counters"] = dict(matcher.stats)
        report["finished_utc"] = now()
        (out / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return report


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--api", required=True)
    p.add_argument("--pid", type=int, required=True)
    p.add_argument("--exe", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--seconds", type=float, default=45)
    p.add_argument("--max-gib", type=float, default=3)
    args = p.parse_args()
    if not (0 < args.seconds <= 60 and 0 < args.max_gib <= 8):
        p.error("Use 0 < seconds <= 60 and 0 < max-gib <= 8")
    print(json.dumps(capture(args), ensure_ascii=False, indent=2))
