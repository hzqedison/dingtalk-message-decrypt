"""Deterministic DingTalk message resolution. No model or model API dependency."""
from __future__ import annotations

import base64
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import subprocess
import time


def strict_json(value):
    def pairs(items):
        obj = {}
        for key, item in items:
            if key in obj:
                raise ValueError('Duplicate JSON key')
            obj[key] = item
        return obj
    def bad_constant(_):
        raise ValueError('Nonfinite JSON number')
    return json.loads(value, object_pairs_hook=pairs, parse_constant=bad_constant)


def sha(value):
    return hashlib.sha256(value.encode('utf-8') if isinstance(value, str) else value).hexdigest()


def unpack(value):
    for _ in range(4):
        if not isinstance(value, str) or not value.lstrip().startswith(('{', '[')):
            break
        try:
            value = strict_json(value)
        except ValueError:
            break
    return value


def cipher_of(value):
    if not isinstance(value, str):
        return None
    m = re.fullmatch(r'([A-Za-z0-9+/=\r\n\t ]+)\|\|(\d+)\|\|(\d+)\|\|(\d+)', value.strip())
    if not m:
        return None
    encoded = re.sub(r'[\r\n\t ]', '', m[1])
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except ValueError:
        return None
    if not decoded or base64.b64encode(decoded).decode('ascii') != encoded:
        return None
    return encoded + '||' + '||'.join(m.groups()[1:])


def plaintext(value):
    return (isinstance(value, str) and bool(value.strip()) and not cipher_of(value)
            and not re.match(r'^\d+_\d+_', value.strip())
            and not re.search(r'\|\|\d+\|\|\d+\|\|\d+\s*$', value)
            and not any(marker in value for marker in ('[加密消息', '[不可读消息]', '该消息被撤回', '该消息已撤回'))
            and not any(ord(c) < 32 and c not in '\n\r\t' or 0xd800 <= ord(c) <= 0xdfff for c in value))


def body_of(row):
    content = unpack(row.get('content'))
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        nested = unpack(content.get('textContent'))
        if isinstance(nested, dict) and isinstance(nested.get('text'), str):
            return nested['text']
        if isinstance(content.get('text'), str):
            return content['text']
    return row.get('text') if isinstance(row.get('text'), str) else None


def message_identity(row):
    """Canonical explicit crypto context; never infer an enterprise from the CID."""
    extension = unpack(row.get('extension', {}))
    if not isinstance(extension, dict):
        raise ValueError('invalid_message_crypto_metadata')
    identity = {}
    for name, aliases in (('oid', ('oid',)), ('corpId', ('corpId', 'corp_id', 'enterprise')),
                          ('safety_priority', ('safety_priority',))):
        values = [source[key] for source in (row, extension) for key in aliases if key in source]
        if not values:
            continue
        if any(isinstance(value, bool) or not isinstance(value, (str, int)) or not str(value).strip() for value in values):
            raise ValueError('invalid_message_crypto_metadata')
        normalized = {str(value) for value in values}
        if len(normalized) != 1:
            raise ValueError('conflicting_message_crypto_identity')
        identity[name] = normalized.pop()
    return identity


def identity_key(identity):
    return json.dumps(identity, sort_keys=True, separators=(',', ':'))


LOCAL_METADATA = ('enterprise', 'key_version', 'crypto_type', 'identity_source', 'client_dll_sha256',
                  'plaintext_validation', 'independent_body_comparison', 'identity_evidence')


def valid_local_result(result, identity):
    return (result.get('status') in ('decrypted_local', 'decrypted_local_cache')
            and plaintext(result.get('text')) and result.get('crypto_decryption_proven') is True
            and isinstance(result.get('enterprise'), str) and bool(result['enterprise'])
            and isinstance(result.get('identity_source'), str) and bool(result['identity_source'])
            and result.get('key_version') is not None
            and ('corpId' not in identity or identity['corpId'] == result['enterprise']))


def messages_of(payload):
    if isinstance(payload, list):
        for item in payload:
            yield from messages_of(item)
    elif isinstance(payload, dict):
        if payload.get('messageId') or payload.get('openMessageId'):
            yield payload
            return
        for key in ('messages', 'msgs', 'data', 'result', 'succeeded'):
            if key in payload:
                yield from messages_of(payload[key])


def load_inputs(paths):
    rows, sources = [], []
    for supplied in paths:
        path = Path(supplied)
        files = sorted(p for p in path.iterdir() if p.suffix in ('.json', '.jsonl')) if path.is_dir() else [path]
        for file in files:
            raw = file.read_bytes()
            payloads = [strict_json(line) for line in raw.decode('utf-8-sig').splitlines() if line.strip()] if file.suffix == '.jsonl' else [strict_json(raw)]
            sources.append({'path': str(file.resolve()), 'sha256': sha(raw)})
            for payload in payloads:
                rows.extend(messages_of(payload))
    return rows, sources


def run_cli(command, timeout=90, cwd=None):
    try:
        result = subprocess.run(command, capture_output=True, timeout=timeout, cwd=cwd)
        return result.returncode, result.stdout.decode('utf-8', errors='strict'), result.stderr.decode('utf-8', errors='strict')
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
        # Do not return exception output: it can contain unstructured CLI secrets.
        return -1, '', type(error).__name__


class Cache:
    def __init__(self, path, scope):
        self.db = sqlite3.connect(path)
        self.scope = scope
        self.blocked_legacy = set()
        self.db.execute('CREATE TABLE IF NOT EXISTS resolved(scope TEXT,cid TEXT,hash TEXT,text TEXT,PRIMARY KEY(scope,cid,hash))')
        self.db.execute('CREATE TABLE IF NOT EXISTS policy(scope TEXT PRIMARY KEY,reason TEXT,updated REAL)')
        self.db.execute('CREATE TABLE IF NOT EXISTS resolved_identity(scope TEXT,cid TEXT,hash TEXT,identity TEXT,result TEXT,PRIMARY KEY(scope,cid,hash,identity))')

    def get_result(self, cid, cipher, identity):
        row = self.db.execute('SELECT result FROM resolved_identity WHERE scope=? AND cid=? AND hash=? AND identity=?',
                              (self.scope, cid, sha(cipher), identity_key(identity))).fetchone()
        if not row:
            return None
        try:
            result = strict_json(row[0])
            if not isinstance(result, dict) or result.get('input_identity') != identity:
                return None
            if result.get('status') == 'decrypted_local' and valid_local_result(result, identity):
                return {**result, 'status': 'decrypted_local_cache', 'cache_hit': True}
            if result.get('status') == 'decrypted_full' and plaintext(result.get('text')):
                return {**result, 'status': 'decrypted_cache', 'cache_hit': True}
        except (ValueError, TypeError):
            pass
        return None

    def put_result(self, cid, cipher, identity, result):
        local = result.get('status') in ('decrypted_local', 'decrypted_local_cache')
        if (local and not valid_local_result(result, identity)) or (not local and
                (result.get('status') != 'decrypted_full' or not plaintext(result.get('text')))):
            raise ValueError('Invalid contextual decryption result')
        stored = {'status': 'decrypted_local' if local else 'decrypted_full', 'text': result['text'],
                  'crypto_decryption_proven': True, 'input_identity': identity,
                  'source_resolution_status': 'decrypted_local' if local else 'decrypted_full',
                  'decryption_source': 'local_ding' if local else 'server_full'}
        if local:
            stored.update({key: result[key] for key in LOCAL_METADATA if key in result})
        old = self.get_result(cid, cipher, identity)
        if old is not None and (old['text'] != stored['text'] or any(
                key in old and key in stored and old[key] != stored[key] for key in LOCAL_METADATA)):
            raise ValueError('Conflicting contextual cached result')
        self.db.execute('INSERT OR REPLACE INTO resolved_identity VALUES(?,?,?,?,?)',
                        (self.scope, cid, sha(cipher), identity_key(identity), json.dumps(stored)))
        self.db.commit()

    def get(self, cid, cipher):
        if (cid, sha(cipher)) in self.blocked_legacy:
            return None
        found = self.db.execute('SELECT text FROM resolved WHERE scope=? AND cid=? AND hash=?', (self.scope,cid,sha(cipher))).fetchone()
        return found[0] if found and plaintext(found[0]) else None

    def put(self, cid, cipher, text):
        if not plaintext(text):
            raise ValueError('Cannot cache an envelope, placeholder or invalid plaintext')
        old = self.get(cid,cipher)
        if old is not None and old != text:
            raise ValueError('Conflicting cached plaintext')
        self.db.execute('INSERT OR REPLACE INTO resolved VALUES(?,?,?,?)', (self.scope,cid,sha(cipher),text))
        self.db.commit()

    def disabled(self):
        row = self.db.execute('SELECT reason FROM policy WHERE scope=?', (self.scope,)).fetchone()
        return row[0] if row else None

    def set_disabled(self, reason):
        self.db.execute('INSERT OR REPLACE INTO policy VALUES(?,?,?)', (self.scope,reason,time.time()))
        self.db.commit()

    def clear_disabled(self):
        self.db.execute('DELETE FROM policy WHERE scope=?', (self.scope,))
        self.db.commit()

    def close(self):
        self.db.close()


class FullDecryptor:
    def __init__(self, cache, out, mode='auto', runner=run_cli, limit=0):
        self.cache, self.out, self.mode, self.runner, self.limit = cache, Path(out), mode, runner, limit
        self.out.mkdir(parents=True,exist_ok=True)
        self.calls = 0
        self.halted = None
        self.checked_version = False
        if mode == 'retry':
            cache.clear_disabled()

    def resolve(self, cid, cipher, identity=None):
        identity = identity or {}
        contextual = self.cache.get_result(cid, cipher, identity)
        if contextual is not None:
            return contextual
        cached = self.cache.get(cid,cipher) if not identity else None
        if cached is not None:
            return {'status':'decrypted_cache','text':cached,'crypto_decryption_proven':True}
        if self.mode == 'off':
            return {'status':'unresolved','reason':'server_disabled_by_argument'}
        reason = self.cache.disabled() or self.halted
        if reason:
            return {'status':'unresolved','reason':reason}
        if self.limit and self.calls >= self.limit:
            return {'status':'unresolved','reason':'decrypt_limit'}
        if not self.checked_version:
            rc, stdout, _ = self.runner(['dws','version'],timeout=30)
            match = re.search(r'\bv?(\d+)\.(\d+)\.(\d+)\b',stdout)
            if rc or not match or tuple(map(int,match.groups())) < (1,0,63):
                self.halted = 'unsupported_or_unknown_dws_version'
                return {'status':'unresolved','reason':self.halted}
            self.checked_version = True
        # One reusable relative filename: never a costly per-message tempfile cleanup.
        file = self.out/'cipher.txt'
        file.write_text(cipher,encoding='utf-8')
        self.calls += 1
        rc, stdout, stderr = self.runner(['dws','chat','crypto','decrypt','--layer','full','--file',file.name,'--format','json'],
                                         timeout=90,cwd=str(self.out.resolve()))
        try:
            payload = strict_json(stdout)
        except ValueError:
            payload = None
        if rc == 0 and isinstance(payload,dict) and payload.get('ok') is True and plaintext(payload.get('plaintext')):
            text = payload['plaintext']
            result = {'status':'decrypted_full','text':text,'crypto_decryption_proven':True}
            if identity:
                self.cache.put_result(cid, cipher, identity, result)
                result.update(input_identity=identity, decryption_source='server_full')
            else:
                self.cache.put(cid,cipher,text)
            return result
        # Successful text may legitimately discuss an error code. Inspect only failures.
        diagnostic = json.dumps({k: payload[k] for k in ('error','code','reason','message') if k in payload}) if isinstance(payload,dict) else stdout
        if (not isinstance(payload,dict) or payload.get('ok') is not True) and (
                'CRYPTO_DISABLED' in diagnostic or 'crypto disabled by switch' in diagnostic.lower()
                or 'CRYPTO_DISABLED' in stderr or 'crypto disabled by switch' in stderr.lower()):
            self.cache.set_disabled('CRYPTO_DISABLED')
            return {'status':'unresolved','reason':'CRYPTO_DISABLED'}
        # Unknown/auth/transport failures stop the run; no blind batch retries.
        self.halted = ('intermediate_envelope' if isinstance(payload,dict)
                       and re.match(r'^\d+_\d+_',str(payload.get('plaintext','')).strip()) else 'decrypt_failed')
        return {'status':'unresolved','reason':self.halted}


def load_client_index(paths):
    index = defaultdict(list)
    for path in paths:
        for line in Path(path).read_text(encoding='utf-8').splitlines():
            if not line.strip():
                continue
            row = strict_json(line)
            if (row.get('evidence_type') != 'native_message_double_read' or not plaintext(row.get('text'))
                    or sha(row['text']) != row.get('text_sha256') or not row.get('api_message_id')
                    or not row.get('api_conversation_id') or not row.get('cipher_sha256')
                    or row.get('recall_metadata_checked') is not True or row.get('recalled') is not False):
                continue
            index[(row['api_conversation_id'],row['api_message_id'],row['cipher_sha256'])].append(row)
    return index


def migrate_local_results(path, cache, current):
    """Recover provenance only from matching prior records, never from legacy text alone."""
    migrated = 0
    if not path.exists():
        return migrated
    candidates = defaultdict(list)
    for line in path.read_text(encoding='utf-8').splitlines():
        try:
            record = strict_json(line)
            row, result = record['original'], record['resolution']['body']
            if result.get('status') not in ('decrypted_local', 'decrypted_local_cache'):
                continue
            cid = row.get('openConversationId') or row.get('conversationId')
            mid = str(row.get('openMessageId') or row.get('messageId') or '')
            cipher = cipher_of(body_of(row))
            if not cipher or not isinstance(cid, str) or not mid:
                continue
            identity = message_identity(row)
            active = current.get((cid, mid))
            if (active is None or cipher_of(body_of(active)) != cipher or message_identity(active) != identity
                    or result.get('cipher_sha256') != sha(cipher)):
                continue
            candidates[(cid, cipher, identity_key(identity))].append((identity, result))
        except (ValueError, TypeError, KeyError, AttributeError):
            continue
    for (cid, cipher, _), entries in candidates.items():
        old = cache.get(cid, cipher)
        cache.blocked_legacy.add((cid, sha(cipher)))
        identity, result = entries[0]
        fingerprints = {json.dumps({key: item.get(key) for key in ('text', *LOCAL_METADATA)}, sort_keys=True)
                        for _, item in entries}
        if len(fingerprints) != 1 or not valid_local_result(result, identity):
            continue
        if cache.get_result(cid, cipher, identity) is not None:
            continue
        if old != result['text']:
            continue
        try:
            cache.put_result(cid, cipher, identity, result)
            migrated += 1
        except ValueError:
            continue
    return migrated


def resolve_batch(input_paths, out_dir, scope='output-local', server='auto', client_indexes=(), runner=run_cli,
                  decrypt_limit=0, fetch_report=None, local_decryptor=None):
    out = Path(out_dir)
    out.mkdir(parents=True,exist_ok=True)
    manifest = out/'resolution_manifest.json'
    previous_manifest = manifest.exists()
    if manifest.exists() and json.loads(manifest.read_text(encoding='utf-8'))['scope'] != scope:
        raise ValueError('Output belongs to a different scope; use a separate output directory')
    manifest.write_text(json.dumps({'scope':scope,'schema_version':4}),encoding='utf-8')
    rows, sources = load_inputs(input_paths)
    grouped = defaultdict(list)
    unidentified = 0
    for row in rows:
        cid = row.get('openConversationId') or row.get('conversationId')
        mid = row.get('openMessageId') or row.get('messageId')
        if not isinstance(cid,str) or not mid:
            unidentified += 1
            continue
        grouped[(cid,str(mid))].append(row)
    # Any differing version of a body is withheld pending an explicit version rule.
    unique, conflicts = {}, []
    for key, variants in grouped.items():
        signatures = {json.dumps({'body':body_of(v),'quote':v.get('quotedMessage'),
                      'time':v.get('createTime'),'sender':v.get('sender'),
                      'message_oid':{'oid':v['oid']} if 'oid' in v else {},
                      'message_corp':{k:v[k] for k in ('corpId','corp_id','enterprise','safety_priority') if k in v},
                      'crypto_extension':{k:unpack(v.get('extension',{}))[k] for k in ('oid','safety_priority','corpId','corp_id','enterprise') if k in unpack(v.get('extension',{}))}
                      if isinstance(unpack(v.get('extension',{})),dict) else 'invalid'},sort_keys=True,ensure_ascii=False) for v in variants}
        if len(signatures)>1:
            conflicts.append({'conversation_id':key[0],'message_id':key[1],'reason':'duplicate_variants'})
        else:
            unique[key]=variants[0]
    client = load_client_index(client_indexes)
    memo = {}
    cache = Cache(out/'resolution_cache.sqlite3',scope)
    migrated_local = migrate_local_results(out/'resolved.jsonl', cache, unique) if previous_manifest else 0
    decryptor = FullDecryptor(cache,out/'tmpdec',server,runner,decrypt_limit)

    def resolve(row, cid, mid):
        value=body_of(row)
        cipher=cipher_of(value)
        if not cipher:
            if plaintext(value):
                return {'status':'original_plaintext','text':value,'crypto_decryption_proven':False}
            return {'status':'unresolved','reason':'placeholder_requires_raw_content' if isinstance(value,str) and '[加密消息' in value else
                    'nontext_content' if value is None else 'invalid_text_or_envelope'}
        try:
            identity = message_identity(row)
        except ValueError as error:
            return {'status':'unresolved','reason':str(error),'cipher_sha256':sha(cipher)}
        key=(cid,mid,sha(cipher))
        evidence=client.get(key,[])
        if evidence:
            texts={r['text'] for r in evidence}
            if len(texts)!=1:
                return {'status':'unresolved','reason':'conflicting_client_evidence','cipher_sha256':sha(cipher)}
            return {'status':'client_observed','text':next(iter(texts)),'cipher_sha256':sha(cipher),
                    'crypto_decryption_proven':False,'evidence_sources':sorted({r.get('source_capture','') for r in evidence})}
        cache_key=(cid,cipher,identity_key(identity))
        if cache_key not in memo:
            memo[cache_key]=decryptor.resolve(cid,cipher,identity)
            if memo[cache_key]['status']=='unresolved' and local_decryptor is not None:
                local = local_decryptor.resolve(row,cid,mid,cipher)
                if valid_local_result(local, identity):
                    cache.put_result(cid,cipher,identity,local)
                    memo[cache_key]={**local,'input_identity':identity,'decryption_source':'local_ding',
                                     'source_resolution_status':'decrypted_local'}
                else:
                    memo[cache_key]={**memo[cache_key],'local_reason':local.get('reason','invalid_local_result_or_identity')}
                    if local.get('failure_stage'):
                        memo[cache_key]['local_failure_stage'] = local['failure_stage']
        return {**memo[cache_key],'cipher_sha256':sha(cipher)}

    counts=Counter(input_rows=len(rows),unique_messages=len(unique),duplicate_rows=sum(len(v)-1 for v in grouped.values()),
                   conflicting_messages=len(conflicts),unidentified_rows=unidentified)
    resolved, readable, unresolved = [], [], list(conflicts)
    try:
        body_results={key:resolve(row,*key) for key,row in unique.items()}
        for (cid,mid),row in unique.items():
            result=body_results[(cid,mid)]
            counts['body_'+result['status']]+=1
            if cipher_of(body_of(row)):
                counts['encrypted_bodies']+=1
                if result['status']=='unresolved':
                    counts['encrypted_body_unresolved']+=1
            quote=row.get('quotedMessage')
            quote_result=None
            if isinstance(quote,dict) and quote:
                qid=str(quote.get('openMessageId') or quote.get('messageId') or '')
                qcid=quote.get('openConversationId') or quote.get('conversationId') or cid
                valid_qcid = isinstance(qcid,str) and bool(qcid) and all(
                    quote.get(key) is None or isinstance(quote[key],str) for key in ('openConversationId','conversationId'))
                known=unique.get((qcid,qid)) if valid_qcid else None
                if not valid_qcid:
                    quote_result={'status':'unresolved','reason':'invalid_quote_conversation_identity'}
                elif known is not None and body_of(known)==body_of(quote):
                    try:
                        qi, ki = message_identity(quote), message_identity(known)
                        if any(key in ki and ki[key] != value for key,value in qi.items()):
                            quote_result={'status':'unresolved','reason':'conflicting_quote_crypto_identity'}
                        elif all(ki.get(key) == value for key,value in qi.items()):
                            quote_result={**body_results[(qcid,qid)],'resolved_via':'same_message_id_and_body'}
                        else:
                            quote_result=resolve(quote,qcid,qid)
                    except ValueError:
                        quote_result={'status':'unresolved','reason':'conflicting_quote_crypto_identity'}
                elif qid:
                    quote_result=resolve(quote,qcid,qid)
                else:
                    quote_result={'status':'unresolved','reason':'missing_quote_identity'}
                counts['quote_'+quote_result['status']]+=1
                if quote_result['status']=='unresolved':
                    unresolved.append({'conversation_id':cid,'message_id':mid,'field':'quotedMessage',**quote_result})
            resolved.append({'original':row,'resolution':{'body':result,'quoted_message':quote_result}})
            if 'text' in result:
                readable.append({'conversation_id':cid,'message_id':mid,'session':row.get('conversationTitle') or cid,
                                 'time':row.get('createTime'),'sender':row.get('sender'),
                                 'text':result['text'],'source':result['status'],
                                 **{key:result[key] for key in (*LOCAL_METADATA,'input_identity','decryption_source',
                                                              'source_resolution_status','cache_hit') if key in result},
                                 'crypto_decryption_proven':result.get('crypto_decryption_proven',False)})
            elif result.get('reason')!='nontext_content':
                unresolved.append({'conversation_id':cid,'message_id':mid,'field':'body',**result})
        counts['readable_messages']=len(readable)
        incomplete_fetch=fetch_report is not None and not fetch_report.get('complete',False)
        report={'schema_version':4,'scope':scope,'counts':dict(counts),'input_sources':sources,
                'decrypt_calls':decryptor.calls,'server_stop_reason':cache.disabled() or decryptor.halted,
                'migrated_local_cache_entries':migrated_local,
                'local_crypto':local_decryptor.summary() if local_decryptor is not None else {'status':'off'},
                'fetch':fetch_report,'input_fetch_completeness':'unknown' if fetch_report is None else 'complete' if not incomplete_fetch else 'partial',
                'resolution_complete_for_supplied_records':not unresolved and not unidentified,
                'status':'partial' if unresolved or unidentified or incomplete_fetch else 'complete_for_supplied_records',
                'unresolved_items':len(unresolved),'limitations':['Client-observed text is not standalone cryptographic decryption.',
                'Imported snapshots have unknown pagination completeness unless a fetch report is supplied.',
                'Structured nontext content stays in resolved.jsonl; it is not invented as a text body.']}
        for name,data in [('resolved.jsonl',resolved),('messages.jsonl',readable),('unresolved.jsonl',unresolved)]:
            (out/name).write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in data),encoding='utf-8')
        (out/'summary.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        return report
    finally:
        cache.close()
