# Sanitized migration example; configure paths, scope and window before use.
# Import shared checks from this same skill installation, never a stale local copy.
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / 'scripts'))
"""Fetch-only native collection retry 3 for Oct 28 and Oct 27."""
import importlib.util, json, shutil, subprocess, sys
from pathlib import Path
from caller_checks import mode_config, mode_args, originals, read_rows, encrypted, validate_result

BASE=Path(__file__).resolve().parent
SOURCE=BASE/'daily_collect.py'
SKILL=Path(__file__).resolve().parents[2]/'scripts'/'dws_decrypt.py'
PYTHON=Path(sys.executable)
SCOPE='dws-auth-REDACTED'
POLICY=BASE/'cache/private/dws-read-policy.sqlite3'

def run(day, prior_day, out_day):
    out=BASE/'cache'/f'heartbeat-{out_day}-full'; prior=BASE/'cache'/f'heartbeat-20261027-midday/discovery/conversations.json'
    if out.exists() and not (out/'discovery/conversations.json').exists(): raise RuntimeError(f'output exists without reusable discovery: {out}')
    out.mkdir(parents=True,exist_ok=True); (out/'discovery').mkdir(exist_ok=True)
    spec=importlib.util.spec_from_file_location(f'collector_{day}', SOURCE); m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    m.BASE,m.OUT,m.DISC,m.PRIOR=BASE,out,out/'discovery',prior
    m.POLICY,m.START,m.END,m.SCOPE=POLICY,f'2026-10-{day} 00:00:00',f'2026-10-{day} 23:59:59',SCOPE
    # First pass fetches raw only; no bulk crypto or client observation.
    m.PYTHON,m.SKILL=PYTHON,SKILL
    try:
        m.main(client='off', local_crypto='off', pipeline_dir=out/'raw-fetch')
    except SystemExit as e:
        if e.code not in (0,2): raise
    rawpipe=out/'raw-fetch'; summary=rawpipe/'summary.json'
    if not summary.exists(): raise RuntimeError('fetch-only pipeline produced no summary')
    sm=json.loads(summary.read_text(encoding='utf-8')); fetch=json.loads((rawpipe/'fetch/fetch_report.json').read_text(encoding='utf-8'))
    resolved=rawpipe/'resolved.jsonl'
    rows=[json.loads(x) for x in resolved.read_text(encoding='utf-8').splitlines() if x.strip()]
    originals(rows)  # Reject empty or malformed raw-fetch output.
    if fetch.get('complete') is not True: raise RuntimeError('raw fetch incomplete')
    candidates=[]
    for r in rows:
        o=r.get('original') or {}; b=o.get('content') or o.get('text')
        q=o.get('quotedMessage') or {}; qb=q.get('content') or q.get('text')
        if encrypted(b): candidates.append(('body',r))
        if encrypted(qb) and (q.get('messageId') or q.get('openMessageId')): candidates.append(('quote',r))
    if not candidates: raise RuntimeError(f'no real encrypted body+quote candidates in raw; {len(rows)} records')
    # Preserve fetch evidence, and conduct isolated smoke on the chosen source record.
    smoke=out/'smoke'; smoke.mkdir()
    sample=smoke/'sample.jsonl'; sample.write_text(json.dumps((candidates[0][1].get('original') or {}),ensure_ascii=False)+'\n',encoding='utf-8')
    p=subprocess.run([str(PYTHON),str(SKILL),'--input',str(sample),'--out',str(smoke/'result'),'--scope',SCOPE,*mode_args(mode_config())],cwd=BASE,capture_output=True,text=True,encoding='utf-8',errors='replace')
    (smoke/'stdout.txt').write_text(p.stdout,encoding='utf-8');(smoke/'stderr.txt').write_text(p.stderr,encoding='utf-8')
    validate_result(smoke/'result', p.returncode, [candidates[0][1]['original']], candidates[0][0])
    shutil.copytree(rawpipe/'fetch',out/'pipeline/fetch')
    report={'day':day,'rawFetchOnly':True,'fetchComplete':fetch.get('complete'),'conversationCount':fetch.get('conversation_count'),'rawMessageCount':fetch.get('raw_message_count'),'policySkips':fetch.get('policy_cached_skips'),'smokeExit':p.returncode,'smokeKinds':[candidates[0][0]]}
    (out/'retry3-status.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps(report,ensure_ascii=False))

if __name__=='__main__':
    run('28','27','20261029')
