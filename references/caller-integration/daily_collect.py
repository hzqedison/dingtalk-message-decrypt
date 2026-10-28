# Sanitized migration example; configure paths, scope and window before use.
# Import shared checks from this same skill installation, never a stale local copy.
import sys
from pathlib import Path as _Path
sys.path.insert(0, str(_Path(__file__).resolve().parents[2] / 'scripts'))
"""Read-only native discovery and unified DWS collection for 2026-10-24 noon."""
import datetime as dt, hashlib, json, subprocess, time
from pathlib import Path
from caller_checks import mode_config, mode_args

BASE=Path(__file__).resolve().parent
OUT=BASE/'cache'/'heartbeat-20261024-midday'; DISC=OUT/'discovery'
SKILL=Path(__file__).resolve().parents[2]/'scripts'/'dws_decrypt.py'
PYTHON=Path(sys.executable)
POLICY=BASE/'cache'/'private'/'dws-read-policy.sqlite3'
PRIOR=BASE/'cache'/'heartbeat-20261024-full'/'discovery'/'conversations.json'
START='2026-10-24 00:00:00'; END='2026-10-24 12:00:00'
SCOPE='dws-auth-REDACTED'

def save(p,v):
 p.parent.mkdir(parents=True,exist_ok=True); p.write_text(json.dumps(v,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
def invoke(args,label,timeout=3700):
 attempts=[]
 for n in range(1,4):
  cmd=['dws',*args,'--format','json']
  try:
   p=subprocess.run(cmd,cwd=BASE,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
   try:v=json.loads(p.stdout);src='stdout'
   except json.JSONDecodeError:
    try:v=json.loads(p.stderr);src='stderr'
    except json.JSONDecodeError:v=None;src=None
   save(DISC/'raw'/f'{label}-{n}.json',{'label':label,'attempt':n,'exitCode':p.returncode,'command':cmd,'stdout':p.stdout,'stderr':p.stderr,'jsonSource':src})
   attempts.append({'attempt':n,'exitCode':p.returncode,'jsonSource':src})
   if p.returncode==0 and isinstance(v,dict):return v,attempts
   e=v.get('error',{}) if isinstance(v,dict) else {}; msg=' '.join(str(e.get(k,'')) for k in ('reason','server_error_code','message'))+p.stdout+p.stderr; low=msg.lower()
   denied='1001' in msg or '该群为保密群，无法获取消息记录' in msg or any(s in low for s in ('permission denied','forbidden','无权限','权限不足'))
   transient=any(s in low for s in ('timeout','temporarily','temporary','unavailable','connection reset','internal server','try again','429','502','503','504'))
   if denied or not transient or n==3:return None,attempts
  except subprocess.TimeoutExpired:
   attempts.append({'attempt':n,'timeout':True}); save(DISC/'raw'/f'{label}-{n}.json',{'label':label,'attempt':n,'timeout':True})
   if n==3:return None,attempts
  time.sleep(120)
 return None,attempts
def conv_rows(r):
 d=r.get('data') if isinstance(r,dict) else None; out=[]
 if isinstance(d,dict):
  if isinstance(d.get('conversations'),list):out+=d['conversations']
  for b in d.get('succeeded',[]) if isinstance(d.get('succeeded'),list) else []:
   if isinstance(b,dict) and isinstance(b.get('conversations'),list):out+=b['conversations']
 if isinstance(r,dict) and isinstance(r.get('conversations'),list):out+=r['conversations']
 return out
def mentions_flat(r):
 d=r.get('result',r); out=[]
 for b in d.get('conversationMessagesList',[]) if isinstance(d,dict) else []:
  if not isinstance(b,dict):continue
  cid=b.get('openConversationId') or b.get('conversationId')
  for m in b.get('messages',[]) if isinstance(b.get('messages'),list) else []:
   if isinstance(m,dict):
    x=dict(m);x.setdefault('openConversationId',cid);x.setdefault('conversationTitle',b.get('title') or b.get('conversationTitle') or '')
    if 'singleChat' not in x and 'singleChat' in b:x['singleChat']=b['singleChat']
    out.append(x)
 return out
def reader_command(rows, pipeline, mode):
 cmd=[str(PYTHON),str(SKILL),"--out",str(pipeline),"--scope",SCOPE,*mode_args(mode),"--start",START,"--end",END,"--read-policy-store",str(POLICY)]
 for row in rows:cmd += ["--conversation-id",row["conversationId"]]
 return cmd

def main(*, client="auto", local_crypto="auto", pipeline_dir=None):
 mode=mode_config(client,local_crypto)
 pipeline=Path(pipeline_dir) if pipeline_dir is not None else OUT/"pipeline"
 OUT.mkdir(parents=True,exist_ok=True);DISC.mkdir(parents=True,exist_ok=True)
 # Record authenticated profile binding, without retaining credentials.
 p=subprocess.run(['dws','auth','status','--format','json'],cwd=BASE,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=60); a=json.loads(p.stdout)
 if p.returncode or not a.get('authenticated') or not a.get('refresh_token_valid'):raise RuntimeError('auth status invalid')
 ident={'corp_id':a.get('corp_id'),'user_id':a.get('user_id')}; digest=hashlib.sha256(json.dumps(ident,sort_keys=True,separators=(',',':')).encode()).hexdigest()
 if 'dws-auth-'+digest!=SCOPE:raise RuntimeError('authenticated scope mismatch')
 save(OUT/'auth-profile-binding.json',{'authenticated':True,'refresh_token_valid':True,'profile_sha256':digest,'scope':SCOPE})
 # @me is intentionally first and must exhaust its source.
 at,aa=invoke(['chat','message','list-mentions','--start',START,'--end',END,'--limit','50','--cursor','0','--page-all','--page-limit','500','--page-delay','100'],'at-me')
 if at is None:save(DISC/'at-me-failure.json',aa);raise RuntimeError('@me discovery failed')
 save(DISC/'at-me.json',at); mentions=mentions_flat(at); ap=at.get('paging',{})
 if ap.get('hasMore') is True or ap.get('sourceExhausted') is False:raise RuntimeError('@me pages incomplete')
 full,fa=invoke(['chat','+conversation-list','--page-all','--limit','100','--page-limit','500','--page-delay','100'],'conversation-list')
 if full is None or full.get('complete') is not True or full.get('truncated') is True:save(DISC/'conversation-list-failure.json',{'attempts':fa,'response':full});raise RuntimeError('conversation-list incomplete')
 save(DISC/'conversation-list.json',full)
 base=['chat','+recent-conversations','--start',START,'--end',END,'--limit','100','--page-limit','500','--page-delay','100','--total-timeout','3600']; pages=[];cursor=None
 for i in range(1,501):
  r,ra=invoke(base+(['--cursor',cursor] if cursor else []),f'recent-page-{i}')
  if r is None or r.get('ok') is False:save(DISC/f'recent-page-{i}-failure.json',{'attempts':ra,'response':r});raise RuntimeError(f'recent page {i} failed')
  save(DISC/f'recent-page-{i}.json',r);pages.append(r);pg=(r.get('meta') or {}).get('pagination') or {}
  if pg.get('endpoint_exhausted') is True:break
  nxt=pg.get('next_token')
  if not nxt or nxt==cursor:raise RuntimeError(f'recent cursor stalled at {i}')
  cursor=nxt
 else:raise RuntimeError('recent-conversations paging safety limit')
 recent={}
 for pg in pages:
  for row in conv_rows(pg):
   cid=row.get('conversationId') or row.get('openConversationId')
   if cid:recent[cid]=row
 merged={}
 def add(row,source):
  cid=row.get('openConversationId') or row.get('conversationId')
  if not cid:return
  x=merged.setdefault(cid,{'conversationId':cid,'name':'','type':'unknown','sources':[]})
  x['name']=row.get('conversationName') or row.get('name') or row.get('conversationTitle') or x['name']
  typ=row.get('type')
  if typ in ('direct','group'):x['type']=typ
  elif row.get('singleChat') is True:x['type']='direct'
  elif row.get('singleChat') is False and x['type']=='unknown':x['type']='group'
  if source not in x['sources']:x['sources'].append(source)
 for row in full.get('conversations',[]):add(row,'complete-conversation-list')
 for row in recent.values():add(row,'recent-conversations')
 for row in mentions:add(row,'at-me')
 prior=json.loads(PRIOR.read_text(encoding='utf-8')) if PRIOR.exists() else []
 for row in prior:add(row,'prior-20261023-full-day-index')
 rows=sorted(merged.values(),key=lambda x:x['conversationId'])
 save(DISC/'recent-conversations-complete.json',{'pages':len(pages),'conversations':list(recent.values()),'endpoint_exhausted':True})
 save(DISC/'conversations.json',rows);save(DISC/'at-me-in-window.json',mentions)
 save(DISC/'discovery-summary.json',{'range':{'timezone':'Asia/Shanghai','startInclusive':START,'endInclusive':END,'semantics':'[start,end]'},'fullConversationList':{'complete':full.get('complete'),'pagesFetched':full.get('pagesFetched'),'count':len(full.get('conversations',[])),'truncated':full.get('truncated')},'recentConversations':{'pagesFetched':len(pages),'count':len(recent),'endpointExhausted':True},'atMe':{'sourceExhausted':ap.get('sourceExhausted'),'hasMore':ap.get('hasMore'),'pages':ap.get('pages'),'rows':len(mentions)},'priorIndex':{'path':str(PRIOR.relative_to(BASE)),'rows':len(prior)},'unionUniqueCIDs':len(rows),'priorityClassCounts':{'direct':sum(r['type']=='direct' for r in rows),'group':sum(r['type']=='group' for r in rows),'unknown':sum(r['type']=='unknown' for r in rows)}})
 # Prioritize high-signal sources by invocation order; unified reader still receives every CID.
 order={'direct':0,'group':1,'unknown':2}; rows.sort(key=lambda x:(order[x['type']],x['conversationId']))
 if not rows:raise RuntimeError("no conversations; refusing unscoped reader invocation")
 cmd=reader_command(rows,pipeline,mode)
 report={}
 for run in range(1,4):
  started=dt.datetime.now().astimezone().isoformat(timespec='seconds'); p=subprocess.run(cmd+(['--resume'] if run>1 else []),cwd=BASE,capture_output=True,text=True,encoding='utf-8',errors='replace')
  (OUT/f'pipeline-run-{run}.stdout.txt').write_text(p.stdout,encoding='utf-8');(OUT/f'pipeline-run-{run}.stderr.txt').write_text(p.stderr,encoding='utf-8')
  save(OUT/f'pipeline-run-{run}.json',{'run':run,'started':started,'ended':dt.datetime.now().astimezone().isoformat(timespec='seconds'),'exitCode':p.returncode,'mode':mode,'knownPolicyDisabled':True,'conversationCount':len(rows),'range':{'timezone':'Asia/Shanghai','startInclusive':START,'endInclusive':END}})
  try:report=json.loads((pipeline/'fetch'/'fetch_report.json').read_text(encoding='utf-8'))
  except (OSError,json.JSONDecodeError):break
  transient=[e for e in report.get('errors',[]) if e.get('reason') in ('command_failed','runner_TimeoutExpired')]
  if p.returncode!=2 or not transient or run==3:break
  time.sleep(120)
 summary=json.loads((pipeline/'summary.json').read_text(encoding='utf-8')) if (pipeline/'summary.json').exists() else None
 count=(summary.get('counts') or {}).get('input_rows') if isinstance(summary,dict) else None
 valid_input=type(count) is int and count>0
 save(OUT/'collection-summary.json',{'discovery':json.loads((DISC/'discovery-summary.json').read_text(encoding='utf-8')),'exitCode':p.returncode,'fetchReport':report,'pipelineSummary':summary,'callerInputValidation':'nonempty' if valid_input else 'missing_or_zero','businessComplete':False})
 if not valid_input:raise RuntimeError('input_rows missing or zero; not a completed collection')
 print(json.dumps({'output':str(OUT),'scope':SCOPE,'discovered':len(rows),'mentions':len(mentions),'exitCode':p.returncode,'fetchComplete':report.get('complete'),'messageCount':report.get('message_count'),'policySkips':report.get('policy_cached_skips')},ensure_ascii=False))
 raise SystemExit(p.returncode)
if __name__=='__main__':main()
