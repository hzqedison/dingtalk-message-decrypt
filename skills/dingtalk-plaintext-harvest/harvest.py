"""钉钉群明文抓取器（被动监听版）

不控制钉钉窗口、不自动滚动。你正常在钉钉里浏览群消息，脚本在后台持续
扫描进程内存，把客户端解密显示出的明文抓下来累积。

用法：
  python harvest.py                        # 后台监听 5 分钟
  python harvest.py --seconds 600          # 自定义监听时长
  python harvest.py --mark AbCdEf          # 只抓某个群（填群 cid 特征片段，可留空=抓所有）
  python harvest.py --name "项目沟通群"     # 报告标题里的群名

工作方式：启动后你不用管它，正常在钉钉里翻看群消息（想抓哪段就滚到哪段），
脚本会把看到的内容自动抓下来。时间到自动生成分类清单。
"""
import ctypes, re, sys, io, json, os, subprocess, time, argparse, datetime
from ctypes import wintypes

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
BASE = os.path.dirname(os.path.abspath(__file__))

ap = argparse.ArgumentParser()
ap.add_argument('--mark', default='', help='群 cid 特征片段；留空=不做群过滤（抓当前客户端里所有可见明文）')
ap.add_argument('--name', default='钉钉群', help='群名（用于报告标题）')
ap.add_argument('--seconds', type=int, default=300, help='监听时长（秒）')
args = ap.parse_args()
GROUP_MARK = args.mark.encode() if args.mark else None   # None = 不过滤群

# ---------- Win32 ----------
u32 = ctypes.WinDLL('user32', use_last_error=True)
k32 = ctypes.WinDLL('kernel32', use_last_error=True)
u32.SetForegroundWindow.argtypes = [wintypes.HWND]
u32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
u32.SetCursorPos.argtypes = [ctypes.c_int, ctypes.c_int]
u32.mouse_event.argtypes = [wintypes.DWORD]*4 + [ctypes.POINTER(ctypes.c_ulong)]
u32.IsWindowVisible.argtypes = [wintypes.HWND]
u32.EnumWindows.argtypes = [ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM), wintypes.LPARAM]
u32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
u32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]

PAGE_READABLE = {0x02, 0x04, 0x06, 0x20, 0x40, 0x80}
MEM_COMMIT = 0x1000
BS, QO = 0x5c, 0x22
WHEEL = 0x0800


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', ctypes.c_uint32), ('__p', ctypes.c_uint32),
                ('RegionSize', ctypes.c_size_t), ('State', ctypes.c_uint32),
                ('Protect', ctypes.c_uint32), ('Type', ctypes.c_uint32)]


OP = k32.OpenProcess; OP.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]; OP.restype = wintypes.HANDLE
RPM = k32.ReadProcessMemory
RPM.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
VQE = k32.VirtualQueryEx
VQE.argtypes = [wintypes.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]


def unlayer(raw):
    out = bytearray(); i = 0; n = len(raw)
    while i < n:
        c = raw[i]
        if c == BS and i + 1 < n:
            d = raw[i + 1]
            if d == BS:
                out.append(BS); i += 2
            elif d == QO:
                out.append(QO); i += 2
            else:
                out.append(BS); out.append(d); i += 2
        else:
            out.append(c); i += 1
    return bytes(out)


def unesc(s):
    for _ in range(6):
        if '\\' not in s:
            break
        try:
            s = json.loads('"' + s + '"')
        except Exception:
            break
    return s


def read_str(buf, i):
    n = len(buf); j = i + 1
    while j < n:
        c = buf[j]
        if c == BS:
            j += 2; continue
        if c == QO:
            return buf[i + 1:j], j + 1
        if c == 0x0a:
            return None, j
        j += 1
    return None, n


def dec(b):
    try:
        return unesc(b.decode('utf-8', 'ignore'))
    except Exception:
        return None


def has_zh(t):
    return any('一' <= c <= '鿿' for c in t)


def find_ding_window():
    # 纯 Win32：枚举钉钉进程窗口，不检查可见性（可能被最小化），取最大的
    ding_pids = {pid for pid, _ in _ding_pids()}
    res = []
    def cb(hwnd, lp):
        pid = wintypes.DWORD()
        u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value not in ding_pids:
            return True
        r = wintypes.RECT()
        u32.GetWindowRect(hwnd, ctypes.byref(r))
        w, h = r.right - r.left, r.bottom - r.top
        if w > 500 and h > 500:
            res.append((hwnd, r, w * h))
        return True
    u32.EnumWindows(ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)(cb), 0)
    if not res:
        return None
    hwnd, r, _ = max(res, key=lambda x: x[2])
    # 窗口可能被最小化，先恢复
    u32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    u32.ShowWindow(hwnd, 9)          # SW_RESTORE
    time.sleep(0.6)
    u32.GetWindowRect(hwnd, ctypes.byref(r))
    return (hwnd, r, 0)


def _proc_name(h):
    buf = ctypes.create_unicode_buffer(300)
    k32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    n = wintypes.DWORD(300)
    if k32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(n)):
        return buf.value
    return ''


def _ding_pids():
    """纯 Win32：枚举所有 DingTalk.exe 进程"""
    psapi = ctypes.WinDLL('psapi', use_last_error=True)
    arr = (wintypes.DWORD * 4096)()
    need = wintypes.DWORD()
    if not psapi.EnumProcesses(arr, ctypes.sizeof(arr), ctypes.byref(need)):
        return []
    out = []
    for i in range(need.value // 4):
        pid = arr[i]
        if not pid:
            continue
        h = OP(0x0410, False, pid)   # QUERY_INFORMATION|VM_READ
        if h:
            nm = _proc_name(h)
            if 'dingtalk.exe' in nm.lower():
                # 拿内存占用
                class PMC(ctypes.Structure):
                    _fields_ = [('cb', wintypes.DWORD), ('PageFaultCount', wintypes.DWORD),
                                ('PeakWorkingSetSize', ctypes.c_size_t), ('WorkingSetSize', ctypes.c_size_t),
                                ('QuotaPeakPagedPoolUsage', ctypes.c_size_t), ('QuotaPagedPoolUsage', ctypes.c_size_t),
                                ('QuotaPeakNonPagedPoolUsage', ctypes.c_size_t), ('QuotaNonPagedPoolUsage', ctypes.c_size_t),
                                ('PagefileUsage', ctypes.c_size_t), ('PeakPagefileUsage', ctypes.c_size_t)]
                pmc = PMC(); pmc.cb = ctypes.sizeof(PMC)
                ws = 0
                psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(PMC), wintypes.DWORD]
                if psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
                    ws = pmc.WorkingSetSize
                out.append((pid, ws))
            k32.CloseHandle(h)
    return out


def main_pid():
    ps = _ding_pids()
    return max(ps, key=lambda x: x[1])[0] if ps else None


def grab_content_text():
    """抓主进程里所有 content.text（附近有本群标记）"""
    res = {}
    pid = main_pid()
    if not pid:
        return res
    h = OP(0x0410, False, pid)
    if not h:
        return res
    KEY = b'"text":"'
    addr = 0; mbi = MBI()
    while True:
        if VQE(h, ctypes.c_void_p(addr), ctypes.byref(mbi), ctypes.sizeof(mbi)) == 0:
            break
        base = mbi.BaseAddress or 0; size = mbi.RegionSize or 0
        if size <= 0:
            break
        if size > 128 * 1024 * 1024:
            addr = base + size; continue
        if mbi.State == MEM_COMMIT and mbi.Protect in PAGE_READABLE:
            buf = ctypes.create_string_buffer(size); read = ctypes.c_size_t(0)
            if RPM(h, ctypes.c_void_p(base), buf, size, ctypes.byref(read)) and read.value:
                raw = buf.raw[:read.value]
                if GROUP_MARK is None or GROUP_MARK in raw:
                    inner = unlayer(raw); p = 0
                    while True:
                        i = inner.find(KEY, p)
                        if i < 0:
                            break
                        v, _ = read_str(inner, i + len(KEY) - 1)
                        p = i + len(KEY)
                        if not v or len(v) < 3 or len(v) > 3000:
                            continue
                        s = dec(v)
                        if not s or not has_zh(s):
                            continue
                        s = s.strip()
                        if '||2||' in s or s.startswith('1_1_') or re.match(r'^[A-Za-z0-9+/=\s]+$', s):
                            continue
                        lo = max(0, i - 4000); hi = min(len(inner), i + 4000)
                        if GROUP_MARK is None or GROUP_MARK in inner[lo:hi]:
                            res[s[:40]] = s
        addr = base + size
    k32.CloseHandle(h)
    return res


def clean(t):
    out = []
    for c in t:
        if ('一' <= c <= '鿿') or (c.isascii() and (c.isalnum() or c in ' .,;:!?()[]@#%&*+-/<>="\'')):
            out.append(c)
        else:
            break
    return ''.join(out).strip()


def norm(t):
    return re.sub(r'[^0-9A-Za-z一-鿿]', '', t).lower()


# ---------- 主流程（被动监听，不控制窗口）----------
print('[%s] 启动（被动监听模式，不控制钉钉窗口）' % datetime.datetime.now().strftime('%H:%M:%S'), flush=True)
pid = main_pid()
if not pid:
    print('未检测到钉钉进程，请先打开钉钉'); sys.exit(1)
print('钉钉进程 PID=%d。请正常在群里浏览消息，脚本后台静默抓取 %d 秒。'
      % (pid, args.seconds), flush=True)
print('（想抓哪段历史，就在钉钉里滚到那段让它显示出来即可）', flush=True)

found = {}
t0 = time.time()
last_n = -1
idle = 0
while time.time() - t0 < args.seconds:
    for k, v in grab_content_text().items():
        if k not in found:
            found[k] = v
    if len(found) != last_n:
        print('  已抓 %d 条（+%d）' % (len(found), len(found) - last_n), flush=True)
        last_n = len(found)
    time.sleep(1.5)

MF = os.path.join(BASE, '_memfinal2.py')
if not os.path.exists(MF):
    print('（未找到 _memfinal2.py，跳过 origin_text 补抓，仅用显示层结果）', flush=True)
else:
    print('监听结束，补抓 origin_text 层...', flush=True)
    try:
        subprocess.run([sys.executable, MF], capture_output=True, timeout=180)
        mp = os.path.join(BASE, 'mem_plain2.json')
        if os.path.exists(mp):
            d = json.load(open(mp, encoding='utf-8'))
            for r in d.get('records', []):
                if not args.mark or args.mark in (r.get('ocid') or ''):
                    t = r.get('text', '').strip()
                    if t:
                        found.setdefault(t[:40], t)
    except Exception as e:
        print('origin_text 补抓跳过:', e)

# 清理 + 去重
final = {}
for v in found.values():
    t = clean(v)
    if len(t) >= 4:
        k = norm(t)
        if len(k) >= 4 and k not in final:
            final[k] = t

TOPICS = [
    ('费用/token/计费/限流', ['限流', 'token', '积分', '计费', '扣费', '账单', '成本', '定价', '价格',
                    '便宜', '贵', '元', '充值', '额度', 'quota', '重置', '续费', '免费', '榨干', '限额']),
    ('模型效果与降智', ['降智', '抽象', '模型', 'Claude', 'GPT', 'gemini', 'Gemini', 'glm', 'deepseek',
                  'DeepSeek', 'flash', '生图', '文本能力', '回答', '答案', '理解']),
    ('功能开发与修复', ['fix', 'feat', '修复', '新增', '支持', '优化', 'perf', 'refactor', 'release',
                  '端点', '桥接', '适配', '回调', '轮询', '缓存']),
    ('代理与网络', ['代理', '线路', '延迟', 'IP', '翻墙', '香港', '美国', '节点', '网络', '公网', '加速']),
    ('团队与账号权限', ['账号', '社媒组', '权限', '同事', '加几个', 'plus', '个人号', '封号', '被封', '离职']),
    ('工具与使用技巧', ['codex', 'Codex', 'CLI', 'app', '教程', '用法', '命令', '仓库', '爬虫', '汉化']),
]
buckets = {n: [] for n, _ in TOPICS}
buckets['其他/闲聊'] = []
for t in final.values():
    for name, kws in TOPICS:
        if any(k in t for k in kws):
            buckets[name].append(t)
            break
    else:
        buckets['其他/闲聊'].append(t)

ts = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
out = os.path.join(BASE, '群明文_%s_%s.md' % (args.name, ts))
L = ['# %s · 群明文抓取（%s）' % (args.name, datetime.datetime.now().strftime('%Y-%m-%d %H:%M')), '',
     '> 被动监听抓取：不控制钉钉窗口，静默读显示层明文 content.text → 合并 origin_text → 去重分类。',
     '> 共 **%d** 条唯一明文（含回复/引用，故可能超过消息总数）。' % len(final), '',
     '| 主题 | 条数 |', '|---|---|']
for name in [n for n, _ in TOPICS] + ['其他/闲聊']:
    L.append('| %s | %d |' % (name, len(buckets[name])))
L.append('')
for name in [n for n, _ in TOPICS] + ['其他/闲聊']:
    its = buckets[name]
    if not its:
        continue
    L.append('## %s（%d）' % (name, len(its)))
    L.append('')
    for t in sorted(its, key=lambda x: -len(x)):
        L.append('- %s' % t.replace('\n', ' / ').strip())
    L.append('')
open(out, 'w', encoding='utf-8').write('\n'.join(L) + '\n')
print()
print('=' * 50)
print('完成：%d 条唯一明文' % len(final))
for name in [n for n, _ in TOPICS] + ['其他/闲聊']:
    print('  %-16s %d' % (name, len(buckets[name])))
print('已生成 ->', out)
