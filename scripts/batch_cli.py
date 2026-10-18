"""One-shot batch entrypoint with resumable fetch and optional resident client read."""
from contextlib import contextmanager
from datetime import datetime, timedelta
import argparse
import json
import os
from pathlib import Path
import sys

from message_pipeline import Cache, load_inputs, resolve_batch, run_cli
from dws_fetch import fetch_snapshot


@contextmanager
def output_lock(root):
    root.mkdir(parents=True, exist_ok=True)
    with (root / '.pipeline.lock').open('a+b') as stream:
        stream.seek(0, 2)
        if stream.tell() == 0:
            stream.write(b'0')
            stream.flush()
        stream.seek(0)
        try:
            if os.name == 'nt':
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise ValueError('Output directory is in use by another batch') from error
        try:
            yield
        finally:
            stream.seek(0)
            if os.name == 'nt':
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)


def parser():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input', '--raw-dir', action='append', default=[], help='JSON/JSONL snapshot or flat input directory; repeatable')
    p.add_argument('--out', required=True)
    p.add_argument('--scope', default='output-local', help='Account/workspace label; use a separate output for each account')
    p.add_argument('--server', choices=['auto', 'off', 'retry'], default='auto')
    p.add_argument('--known-policy-disabled', action='store_true', help='Persist the already verified CRYPTO_DISABLED result without a network retry')
    p.add_argument('--client', choices=['auto', 'off'], default='auto')
    p.add_argument('--local-crypto', choices=['auto','off'], default='auto', help='Use the verified Windows client cached key when server decryption is unavailable; --client off disables this too')
    p.add_argument('--client-index', action='append', default=[])
    p.add_argument('--decrypt-limit', type=int, default=0, help='0 means unlimited; does not limit fetching')
    p.add_argument('--conversation-id', action='append')
    p.add_argument('--start')
    p.add_argument('--end')
    p.add_argument('--days', type=int)
    p.add_argument('--kind', choices=['all', 'direct', 'group'])
    p.add_argument('--resume', action='store_true')
    return p


def target_conversations(rows):
    cids = set()
    for row in rows:
        cid = row.get('openConversationId') or row.get('conversationId')
        if isinstance(cid,str) and cid:
            cids.add(cid)
        quote = row.get('quotedMessage')
        if isinstance(quote,dict):
            qcid = quote.get('openConversationId') or quote.get('conversationId') or cid
            if isinstance(qcid,str) and qcid:
                cids.add(qcid)
    return cids


def execute(args):
    root = Path(args.out).resolve()
    if args.decrypt_limit < 0 or (args.days is not None and args.days <= 0):
        raise ValueError('Invalid negative limit or nonpositive days')
    if args.known_policy_disabled and args.server == 'retry':
        raise ValueError('Choose either known disabled policy or explicit server retry')
    if args.days is not None and (args.start or args.resume):
        raise ValueError('--days cannot be combined with --start or --resume')
    if args.input and (args.conversation_id or args.start or args.end or args.days or args.kind or args.resume):
        raise ValueError('Input snapshots cannot be combined with fetch/window/resume arguments')
    for path in args.input:
        resolved = Path(path).resolve()
        if resolved == root or resolved in root.parents or root in resolved.parents:
            raise ValueError('Keep input snapshots and the output directory separate')
    with output_lock(root):
        manifest = root / 'scope.json'
        if manifest.exists():
            if json.loads(manifest.read_text(encoding='utf-8')).get('scope') != args.scope:
                raise ValueError('Output belongs to another scope; use a separate output directory')
        else:
            manifest.write_text(json.dumps({'scope': args.scope}), encoding='utf-8')
        inputs, fetch = args.input, None
        if not inputs:
            start, end, kind = args.start, args.end, args.kind
            if args.resume:
                saved = json.loads((root / 'fetch' / 'fetch_manifest.json').read_text(encoding='utf-8'))
                kind = kind or saved['kind']
            else:
                end = end or datetime.now().isoformat(timespec='seconds')
                if not start:
                    start = (datetime.fromisoformat(end) - timedelta(days=args.days or 7)).isoformat(timespec='seconds')
            snapshot, fetch = fetch_snapshot(root / 'fetch', start, end,
                conversation_ids=args.conversation_id, kind=kind or 'all', resume=args.resume)
            inputs = [snapshot]
        else:
            load_inputs(inputs)
        if args.known_policy_disabled:
            cache = Cache(root / 'resolution_cache.sqlite3', args.scope)
            try:
                cache.set_disabled('CRYPTO_DISABLED')
            finally:
                cache.close()
        local = None
        if args.client == 'auto' and args.local_crypto == 'auto':
            from native_decryptor import NativeDecryptor
            rows, _ = load_inputs(inputs)
            target_cids = target_conversations(rows)
            local = NativeDecryptor(root/'tmpdec-local',run_cli,limit=args.decrypt_limit,target_cids=target_cids)
        try:
            report = resolve_batch(inputs, root, scope=args.scope, server=args.server,
                client_indexes=args.client_index, decrypt_limit=args.decrypt_limit, fetch_report=fetch,
                local_decryptor=local)
        finally:
            if local is not None:
                local.close()
        client_report = {'status': 'off' if args.client == 'off' else 'not_needed'}
        if args.client == 'auto' and report['counts'].get('encrypted_body_unresolved', 0):
            from client_bridge import capture_loaded
            client_report = capture_loaded(inputs, root)
            if client_report.get('index') and client_report.get('api_bound_messages',0) > 0:
                first = report
                report = resolve_batch(inputs, root, scope=args.scope, server='off',
                    client_indexes=[*args.client_index, client_report['index']], fetch_report=fetch)
                report['decrypt_calls'] = first['decrypt_calls']
                report['server_stop_reason'] = first['server_stop_reason']
                report['local_crypto'] = first['local_crypto']
        report['client'] = client_report
        report['output_directory'] = str(root)
        (root / 'summary.json').write_text(json.dumps(report, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
        return report


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        report = execute(args)
    except (OSError, ValueError, RuntimeError) as error:
        print(json.dumps({'status': 'error', 'error_type': type(error).__name__,
                          'hint': 'Check paths, scope, argument combinations and whether the output is already in use.'}))
        return 1
    print(json.dumps({k: report[k] for k in ('status', 'counts', 'unresolved_items',
        'decrypt_calls', 'server_stop_reason', 'local_crypto', 'client', 'output_directory')}, ensure_ascii=False))
    return 2 if report['status'] == 'partial' else 0


if __name__ == '__main__':
    sys.exit(main())
