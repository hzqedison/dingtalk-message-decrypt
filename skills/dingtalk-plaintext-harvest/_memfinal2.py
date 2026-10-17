"""本地内存明文提取器 v4 —— 兼容两种内存结构，最大化覆盖率

结构 A（完整消息 JSON，带时间）：
  "content":{"textContent":{"text":"<b64>\\n||2||1||N"}},"conversationId":"...",
  "createdAt":<ms>,"extension":{"origin_text":"<明文>","openConversationId":"cidXX==",...},
  "messageId":<num>,...,"sourceNick":"<发送人>"

结构 B（搜索/话题索引，无时间但有群ID和消息ID）：
  {"interaction":"{...sourceMsgId:27448721518719,topicId:27457311453311}",
   "oid":"30767088","openConversationId":"cidXX==","origin_text":"<明文>",
   "sendMsgUUID":"...","topicSourceCid":"78145014778","topicSourceMsgId":...}

策略：对每个 origin_text，在 ±900 字节窗口内取**最近**的 openConversationId / createdAt /
sourceNick / sourceMsgId / 密文信封，两种结构的字段都能吃到。
用法：python _memfinal2.py
产物：mem_plain2.json（累积）
"""
import ctypes, re, sys, io, json, os, subprocess, time, datetime, argparse
from ctypes import wintypes

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
PAGE_READABLE = {0x02, 0x04, 0x06, 0x20, 0x40, 0x80}
MEM_COMMIT = 0x1000
BASE = os.path.dirname(os.path.abspath(__file__))
STORE = os.path.join(BASE, 'mem_plain2.json')
B64 = set(b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
SKIP = set(b' \t\r\n\\n')

ap = argparse.ArgumentParser()
ap.add_argument('--full', action='store_true', help='打印全部群的明文')
args = ap.parse_args()


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', ctypes.c_uint32), ('__pad1', ctypes.c_uint32),
                ('RegionSize', ctypes.c_size_t), ('State', ctypes.c_uint32),
                ('Protect', ctypes.c_uint32), ('Type', ctypes.c_uint32)]


k32 = ctypes.windll.kernel32
OP = k32.OpenProcess
OP.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
OP.restype = wintypes.HANDLE
RPM = k32.ReadProcessMemory
RPM.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t,
                ctypes.POINTER(ctypes.c_size_t)]
VQE = k32.VirtualQueryEx
VQE.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]

RX_ORIGIN = re.compile(rb'"origin_text\\?":\\?"((?:[^"\\]|\\.)*?)\\?"')
RX_REPLY = re.compile(rb'"replyContent\\?":\\?"((?:[^"\\]|\\.)*?)\\?"')
RX_ENV = re.compile(rb'\|\|(\d+)\|\|(\d+)\|\|(\d+)')
RX_TS = re.compile(rb'"createdAt\\?":\\?"?(\d{10,13})')
RX_OCID = re.compile(rb'"openConversationId\\?":\\?"(cid[A-Za-z0-9+/=]*)\\?"')
RX_MID = re.compile(rb'"messageId\\?":\\?"?(\d{6,})')
RX_NICK = re.compile(rb'"sourceNick\\?":\\?"((?:[^"\\]|\\.)*?)\\?"')
RX_SRCMSG = re.compile(rb'"sourceMsgId\\?":\\?"?(\d{6,})')
RX_TOPIC = re.compile(rb'"topicId\\?":\\?"?(\d{6,})')
RX_SENDERID = re.compile(rb'"senderId\\?":\\?"?(\d{6,})')
RX_UID = re.compile(rb'"uid\\?":\\?"?(\d{6,})')


def unesc(s):
    for _ in range(3):
        if '\\u' not in s and '\\n' not in s and '\\"' not in s:
            break
        try:
            s2 = json.loads('"' + s + '"')
        except Exception:
            break
        if s2 == s:
            break
        s = s2
    return s


def back_collect(raw, pos, limit=2500):
    """从 pos 往前收集 base64。
    关键：内存里 JSON 字符串的折行是字面 \\n（反斜杠+字母n），而 n 本身是合法
    base64 字符，必须把 \\n 作为整体跳过，否则每条密文都会混入假字符。"""
    out = bytearray()
    i = pos - 1
    n = 0
    while i >= 0 and n < limit:
        c = raw[i]
        if c in B64:
            if c == 0x6e and i > 0 and raw[i - 1] == 0x5c:
                i -= 2
                continue
            out.append(c); n += 1; i -= 1
        elif c in (0x0a, 0x0d, 0x09, 0x20, 0x5c):
            i -= 1
        else:
            break
    out.reverse()
    return bytes(out)


def nearest(rx, seg, anchor):
    """取 seg 中距 anchor 最近的匹配"""
    best = None
    bd = 1e9
    for m in rx.finditer(seg):
        d = min(abs(m.start() - anchor), abs(m.end() - anchor))
        if d < bd:
            bd = d; best = m
    return best


out = subprocess.run(['powershell', '-NoProfile', '-Command',
                      "Get-CimInstance Win32_Process -Filter \"Name='DingTalk.exe'\" | "
                      "Sort-Object WorkingSetSize -Descending | "
                      "Select-Object -First 1 -ExpandProperty ProcessId"],
                     capture_output=True, text=True, timeout=30).stdout.strip()
PID = int(out.split()[0]) if out.split() else 23400
print('DingTalk.exe PID =', PID)
h = OP(0x0410, False, PID)
if not h:
    print('OpenProcess 失败'); sys.exit(1)

recs = {}
addr = 0
mbi = MBI()
total = 0
t0 = time.time()
while True:
    if VQE(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
        break
    base = mbi.BaseAddress or 0
    size = mbi.RegionSize or 0
    if size <= 0:
        break
    if size > 128 * 1024 * 1024:
        addr = base + size; continue
    if mbi.State == MEM_COMMIT and mbi.Protect in PAGE_READABLE:
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        if RPM(h, ctypes.c_void_p(base), buf, size, ctypes.byref(read)) and read.value:
            n = read.value; total += n
            raw = buf.raw[:n]
            for om in RX_ORIGIN.finditer(raw):
                a, b = om.span()
                try:
                    text = unesc(om.group(1).decode('utf-8', 'ignore')).strip()
                except Exception:
                    continue
                if len(text) < 2:
                    continue
                lo = max(0, a - 900); hi = min(n, b + 900)
                seg = raw[lo:hi]
                anchor = a - lo
                # 密文指纹（有则用，无则用文本哈希）
                em = nearest(RX_ENV, seg, anchor)
                b64key = None
                if em:
                    b64 = back_collect(raw, lo + em.start())
                    if len(b64) >= 24:
                        b64key = b64[-24:].decode('ascii', 'ignore') + '|' + \
                            em.group(3).decode()
                key = b64key or ('T:' + text[:50])
                r = recs.setdefault(key, {'text': text, 'hits': 0})
                r['hits'] += 1
                if b64key:
                    r['cipher'] = b64key
                m = nearest(RX_TS, seg, anchor)
                if m:
                    r['ts'] = m.group(1).decode()
                m = nearest(RX_OCID, seg, anchor)
                if m:
                    r['ocid'] = m.group(1).decode()
                m = nearest(RX_MID, seg, anchor)
                if m:
                    r['mid'] = m.group(1).decode()
                m = nearest(RX_NICK, seg, anchor)
                if m:
                    r['nick'] = unesc(m.group(1).decode('utf-8', 'ignore'))
                m = nearest(RX_SRCMSG, seg, anchor)
                if m:
                    r['srcmsg'] = m.group(1).decode()
                m = nearest(RX_TOPIC, seg, anchor)
                if m:
                    r['topic'] = m.group(1).decode()
    addr = base + size
k32.CloseHandle(h)

# 合并历史
hist = {}
if os.path.exists(STORE):
    try:
        hist = json.load(open(STORE, encoding='utf-8'))
    except Exception:
        hist = {}
allr = {}
for r in hist.get('records', []):
    allr[r.get('key') or ('T:' + r['text'][:50])] = r
for k, r in recs.items():
    if k in allr:
        for f in ('ts', 'ocid', 'mid', 'nick', 'srcmsg', 'topic', 'cipher'):
            if f in r and f not in allr[k]:
                allr[k][f] = r[f]
        allr[k]['hits'] = allr[k].get('hits', 1) + r['hits']
    else:
        r['key'] = k
        allr[k] = r

json.dump({'records': list(allr.values()),
           'updated': time.strftime('%Y-%m-%d %H:%M:%S'),
           'scans': hist.get('scans', 0) + 1},
          open(STORE, 'w', encoding='utf-8'), ensure_ascii=False, indent=1)

print('扫描 %.1f MB | 耗时 %.0fs' % (total / 1048576.0, time.time() - t0))
print('本轮唯一 %d | 累计 %d | 扫描 %d 次' % (len(recs), len(allr), hist.get('scans', 0) + 1))
for f, name in (('ts', 'createdAt'), ('ocid', 'openConversationId'),
                ('nick', 'sourceNick'), ('srcmsg', 'sourceMsgId')):
    print('  带 %-20s %d' % (name, sum(1 for r in allr.values() if r.get(f))))

bygrp = {}
for r in allr.values():
    bygrp.setdefault(r.get('ocid') or '(未知群)', []).append(r)
print()
print('=== 按群分布 ===')
for g, rs in sorted(bygrp.items(), key=lambda x: -len(x[1])):
    tss = [r['ts'] for r in rs if r.get('ts')]
    def ts2str(ms):
        try:
            return datetime.datetime.fromtimestamp(int(ms) / 1000.0).strftime('%Y-%m-%d %H:%M')
        except Exception:
            return '?'
    span = '%s ~ %s' % (ts2str(min(tss)), ts2str(max(tss))) if tss else '无时间'
    print('  %-36s %3d 条  %s' % (g, len(rs), span))

if args.full:
    print()
    print('=== 全部明文 ===')
    for g, rs in sorted(bygrp.items(), key=lambda x: -len(x[1])):
        print('--- %s (%d) ---' % (g, len(rs)))
        for r in sorted(rs, key=lambda x: x.get('ts') or '0'):
            print('   [%s] %s' % (r.get('ts') or '?', r['text'][:110].replace('\n', ' / ')))
print()
print('已保存 ->', STORE)
