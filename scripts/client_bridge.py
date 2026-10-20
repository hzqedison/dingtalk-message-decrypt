"""Optional Windows client fallback; no UI input, process writes, hooks, or keys."""
from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid

from message_pipeline import body_of, cipher_of, load_inputs, plaintext, sha
from client_compatibility import ClientCompatibilityError
from client_layouts import select_binary_layout


def discover_client():
    if os.name != 'nt':
        return None, 'windows_client_required'
    command = r'''$items = @(foreach ($p in Get-Process -Name DingTalk -ErrorAction SilentlyContinue) {
      try { $m = @($p.Modules | Where-Object ModuleName -eq 'MainFrame.dll');
        if ($m.Count -eq 1) { [pscustomobject]@{pid=$p.Id;exe=$p.Path;dll=$m[0].FileName;module_base=$m[0].BaseAddress.ToInt64()} }
      } catch {} }); ConvertTo-Json -InputObject $items -Compress'''
    try:
        result = subprocess.run(['powershell','-NoProfile','-NonInteractive','-Command',command],
                                capture_output=True,timeout=30,creationflags=subprocess.CREATE_NO_WINDOW)
        found = json.loads(result.stdout.decode('utf-8-sig')) if result.returncode == 0 else []
    except (OSError,ValueError,subprocess.TimeoutExpired):
        return None, 'client_discovery_failed'
    if len(found) != 1:
        return None, 'client_not_running' if not found else 'ambiguous_client_processes'
    return found[0], None


def capture_loaded(input_paths, out_dir):
    target, error = discover_client()
    if error:
        return {'status':'unavailable','reason':error,'index':None}
    # Reject an unknown adapter before even the optional resident JSON scan.
    try:
        select_binary_layout(Path(target['dll']).read_bytes(), 'typed_messages')
    except ClientCompatibilityError as error:
        return {'status':'unavailable','reason':error.reason,'index':None,
                'client_compatibility':error.diagnostic}
    except OSError:
        return {'status':'unavailable','reason':'client_dll_unreadable','index':None}
    rows, _ = load_inputs(input_paths)
    root=Path(out_dir)/('client-'+datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8])
    root.mkdir(parents=True,exist_ok=False)
    api=root/'api.json'
    api.write_text(json.dumps({'messages':rows},ensure_ascii=False),encoding='utf-8')
    by_id={(m.get('openConversationId') or m.get('conversationId'),str(m.get('openMessageId') or m.get('messageId'))):m for m in rows}
    runtime=Path(__file__).resolve().parent/'client_runtime'
    common=['--api',str(api.resolve()),'--pid',str(target['pid']),'--exe',target['exe'],'--seconds','45','--max-gib','3']
    def call(name,args):
        result=subprocess.run([sys.executable,str(runtime/name),*args],capture_output=True,timeout=75)
        (root/(name+'.stdout.log')).write_bytes(result.stdout)
        (root/(name+'.stderr.log')).write_bytes(result.stderr)
        return result.returncode
    anchors=root/'json_objects'
    native=root/'native_objects'
    try:
        # JSON acquisition is optional evidence for linking native IDs to API IDs.
        code=call('capture_message_evidence.py',common+['--out',str(anchors.resolve())])
        anchor_args=['--anchors',str((anchors/'observations.jsonl').resolve())] if code == 0 else []
        code=call('capture_typed_messages.py',common+['--profile','im_chat','--dll',target['dll'],
                    '--module-base',str(target['module_base']),'--out',str(native.resolve()),*anchor_args])
        if code:
            result={'status':'unavailable','reason':'unsupported_client_or_capture_failed','index':None,'diagnostics':str(root.resolve())}
            (root/'summary.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
            return result
    except (OSError,subprocess.TimeoutExpired) as error:
        return {'status':'unavailable','reason':type(error).__name__,'index':None,'diagnostics':str(root.resolve())}
    index, supplemental, excluded = [], [], Counter()
    for line in (native/'readable_messages.jsonl').read_text(encoding='utf-8').splitlines():
        item=json.loads(line)
        ext=item.get('extension_selected',{})
        if str(ext.get('recallMessageTime','0')).strip() not in ('','0'):
            excluded['recall_marked']+=1
            continue
        cid=ext.get('openConversationId')
        if not cid or not plaintext(item.get('text')) or sha(item['text']) != item['text_sha256']:
            excluded['invalid_body_or_identity']+=1
            continue
        supplemental.append(item)
        api_id=item.get('api_message_id')
        original=by_id.get((cid,api_id))
        cipher=cipher_of(body_of(original)) if original else None
        if not cipher or item.get('api_time_matches_to_second') is not True:
            excluded['no_verified_api_binding']+=1
            continue
        index.append({'evidence_type':'native_message_double_read','api_message_id':api_id,
                      'api_conversation_id':cid,'cipher_sha256':sha(cipher),'text':item['text'],
                      'text_sha256':item['text_sha256'],'native_message_id':item['native_message_id'],
                      'created_at_ms':item['created_at_ms'],'recall_metadata_checked':True,'recalled':False,
                      'source_capture':str(native.resolve()),'source_observations_sha256':sha((native/'observations.jsonl').read_bytes()),
                      'crypto_decryption_proven':False})
    index_path=root/'client_index.jsonl'
    index_path.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in index),encoding='utf-8')
    (root/'supplemental_native_messages.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in supplemental),encoding='utf-8')
    result={'status':'captured','index':str(index_path.resolve()),'api_bound_messages':len(index),
            'native_readable_messages':len(supplemental),'excluded':dict(excluded),
            'supplemental_messages':str((root/'supplemental_native_messages.jsonl').resolve()),
            'limitations':['Only resident client objects; no automatic history loading.',
                           'Native messages without an exact API binding are separate, never timestamp-backfilled.']}
    (root/'summary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return result
