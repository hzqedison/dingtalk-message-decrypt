#!/usr/bin/env python3
# Historical archive only. Use ../dws_decrypt.py; old success-rate claims below were withdrawn.
# -*- coding: utf-8 -*-
"""
钉钉消息读取 + 三方密文解密（自包含工具）  v2

背景
----
企业钉钉开启「三方加密」后，dws 的高层命令（+chat-messages / +at-me）
会把读不到的消息替换成占位符 "[加密消息，无法解码]"。
原因不是技术做不到，而是列表接口的内置解密被服务端策略禁用
（返回 reason=policy_disabled, decryptAllowedCount=0）。

正确做法：
  1. 用底层 `dws chat message list` 拿 content 字段（密文原文，形如 "xxx...||2||1||228"）
  2. 用 `dws chat crypto decrypt --layer full` 逐条解密（本地 SafeChat 层 + 服务端 DING 层，
     **双层链路，只有它能拿到明文**）；失败再降级 `--layer safechat`（只能解单层消息）
实测：近 92 天 172,819 条消息 / 39,351 条密文，还原率 100%。

v2 修正（2026-10-09，来自一次 3 个月全量实测）
----------------------------------------------
1. crypto decrypt 的 --file **必须是相对路径**，传绝对路径会被 dws 拒绝
   （报错 "must be a relative path within the current directory"）。
   → 统一用 cwd=tmp_dir + 文件名的相对写法。
2. ~~主解密层改 `--layer safechat`：同样 100% 成功，但 6.61 QPS vs full 的 4.16（快 59%）。~~
   **该结论已于 2026-10-16 被推翻，见 v3。**
   `--layer ding` 实测 30/30 全失败，不要用。
3. 拉取**不能传 --max-items**（任何非零值都会截断；600 曾让 10 个会话缺一个半月）。
   改为 `--direction newer` + `--time <下界>` 手动翻页，天然落在时间窗内。
4. 分页游标是 `nextPage['time']`（nextPage 本身是个 dict），直接传整个 dict 会返回 0 条。
5. **群聊正文也会加密**（旧版 SKILL.md 说「群聊正文 100% 明文」是错的，
   那是从单日样本得出的结论）。本工具默认也处理群聊。

v3 修正（2026-10-16，企业侧 DING 解密策略被关闭）
---------------------------------------------------
1. **`--layer full` 是唯一能出明文的层**。它在服务端执行 DING 层解密；
   `--layer safechat` 只跑本地层，对双层消息只会返回 `1_1_<hex>` 信封，**永远不是明文**。
   → LAYER_CHAIN 已改为 ('full', 'safechat')。
2. **必须识别 `1_1_<hex>` 信封并判为失败**（旧版没识别，把信封当明文写进了语料）。
   判定：`^\\d+_\\d+_[0-9a-f]+$`；长度恒等于原密文 `||2||1||N` 的 N。
   出现信封 = 服务端 DING 层没跑成，几乎总是策略关闭（见下）。
3. 服务端关闭时 `full` 层直接报 `CRYPTO_DISABLED / crypto disabled by switch`（业务级错误，
   非权限问题）。**这是企业侧策略开关，客户端无解，只能找管理员开通。**
4. 已排除的因素（别重复踩）：
   - 升级 dws 无用（v1.0.63 与 v1.0.64 行为完全一致，v1.0.64 无解密相关修复）
   - 清空 ~/.dws/safechat/keystore 重新拉密钥无用（输出逐字节相同）
   - 登录态/token 正常，与账号权限无关
5. 一条命令自检（判断"策略关了"还是"环境坏了"）：
   dws chat crypto decrypt --layer full --file <密文> -f raw
   报 CRYPTO_DISABLED → 找管理员；返回 1_1_ → 同上；返回可读中文 → 环境正常。

用法
----
  python dws_decrypt.py --days 92 --out ./out                  # 近 92 天单聊
  python dws_decrypt.py --days 92 --out ./out --kind all       # 单聊 + 群聊（推荐）
  python dws_decrypt.py --days 92 --out ./out --limit 200      # 先试跑 200 条
  python dws_decrypt.py --resume --out ./out                   # 断点续跑

产出
----
  out/conversations.json   会话列表
  out/raw/*.jsonl          每个会话的逐页原始结果（含 content 密文），可断点续跑
  out/decrypted.jsonl      解密成功的明文（追加写，可反复续跑）
  out/messages.jsonl       合并后的完整明文语料（明文 + 解密结果）

依赖
----
  dws CLI >= v1.0.63（v1.0.62 的 safechat 本地层会 cgo 崩溃，必须先 dws upgrade）
  仅用 Python 标准库
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import queue
import re
import subprocess
import threading
import time
from collections import Counter

ENC = '加密消息，无法解码'
CIPHER_RE = re.compile(r'^[A-Za-z0-9+/=\s]+\|\|\d+(\|\|\d+)*$')
SKIP_SESSIONS = ['钉钉文档自动化助手', 'AI听记助手', 'OA审批助手', '员工关怀', '差旅助手']

# 主层 full（唯一能出明文的双层链路），降级 safechat（只能解单层）；
# ding 实测不可用。full 依赖服务端 DING 解密策略，企业侧关闭时会报 CRYPTO_DISABLED。
LAYER_CHAIN = ('full', 'safechat')
FETCH_WORKERS = 8      # 拉取并发（服务端对会话列表/消息列表较敏感）
DEC_WORKERS = 16       # 解密并发（16 封顶，32 无提升）


def run(cmd, timeout=120, cwd=None):
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=timeout, cwd=cwd)
    except Exception as e:
        return -1, '', str(e)
    return p.returncode, (p.stdout or b'').decode('utf-8', 'ignore'), \
        (p.stderr or b'').decode('utf-8', 'ignore')


def jout(s):
    try:
        return json.loads(s)
    except Exception:
        return None


ENVELOPE_RE = re.compile(r'^\d+_\d+_[0-9a-f]+$')


def is_envelope(txt):
    """True 表示这是未完成的信封（形如 1_1_<hex>），不是明文。

    服务端 DING 解密策略被企业关闭时，本地 SafeChat 层只能剥掉第一层，
    返回的就是这种信封；它的长度恒等于原密文 ||2||1||N 的 N。
    v2 没识别它，直接当明文写进了语料 —— v3 起必须判为失败。
    """
    if not txt:
        return False
    s = txt.strip()
    return len(s) > 8 and bool(ENVELOPE_RE.match(s))


def msgs_of(j):
    if not j:
        return []
    if isinstance(j.get('messages'), list):
        return j['messages']
    for k in ('data', 'result'):
        v = j.get(k) or {}
        if isinstance(v, dict) and isinstance(v.get('messages'), list):
            return v['messages']
    return []


def cursor_of(j):
    """分页游标。nextPage 是个 dict，要取里面的 time（踩过坑：传整个 dict 会返回 0 条）"""
    if not j:
        return None
    np = j.get('nextPage')
    if isinstance(np, dict):
        if np.get('time'):
            return np['time']
        if np.get('nextCursor'):
            return str(np['nextCursor'])
    r = j.get('result') or {}
    if isinstance(r, dict) and r.get('nextCursor'):
        return str(r['nextCursor'])
    return None


def check_version():
    rc, out, _ = run(['dws', 'version'])
    m = re.search(r'v(\d+)\.(\d+)\.(\d+)', out)
    if not m:
        print('[warn] 无法解析 dws 版本，请确认已安装 dws')
        return
    ver = tuple(int(x) for x in m.groups())
    if ver < (1, 0, 63):
        print('[ERROR] dws %s 过低：v1.0.62 的 safechat 本地层会崩溃，'
              '必须先执行 dws upgrade 升到 v1.0.63+' % '.'.join(m.groups()))
        raise SystemExit(1)
    print('[ok] dws v%s' % '.'.join(m.groups()))


# ---------------- 会话清单 ----------------
def fetch_conversations(start_s, end_s, out_dir, max_rounds=6):
    """+recent-conversations 带 --cursor 续页。

    实测该接口单轮常常跑不完（endpoint_exhausted=false、中途分页超时），
    必须续 cursor 多轮；否则会话清单是残缺的（曾少 42 个会话）。
    """
    print('[1/4] 拉取会话列表 %s ~ %s' % (start_s, end_s))
    convs = {}
    cursor = None
    for rnd in range(max_rounds):
        cmd = ['dws', 'chat', '+recent-conversations',
               '--start', start_s, '--end', end_s,
               '--limit', '100', '--page-limit', '500', '--page-delay', '100',
               '--total-timeout', '480', '--format', 'json', '--timeout', '120']
        if cursor:
            cmd += ['--cursor', cursor]
        rc, so, se = run(cmd, timeout=560)
        j = jout(so)
        if not j:
            print('      第%d轮无有效返回，停止（%s）' % (rnd + 1, se[:120]))
            break
        n = 0
        for blk in (j.get('data', {}).get('succeeded') or []):
            for c in (blk.get('conversations') or []):
                cid = c.get('conversationId')
                if cid and cid not in convs:
                    convs[cid] = c
                    n += 1
        pag = (j.get('meta', {}).get('pagination') or {})
        exhausted = pag.get('endpoint_exhausted')
        cursor = pag.get('next_token')
        print('      第%d轮 +%d，累计 %d，exhausted=%s' % (rnd + 1, n, len(convs), exhausted))
        if exhausted or not cursor or n == 0:
            break
    lst = list(convs.values())
    json.dump(lst, open(os.path.join(out_dir, 'conversations.json'), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    cnt = Counter(c.get('type') for c in lst)
    print('      会话 %d 个 %s' % (len(lst), dict(cnt)))
    return lst


# ---------------- 逐会话拉取（手动分页，无 --max-items） ----------------
def fetch_conv(cid, outfile, state, lo, hi, sleep=0.12, max_pages=2000):
    """返回 (msg_count, pages, stop_reason)。页级追加写，可中断续跑。"""
    cursor = state.get('cursor') or lo
    pages, total = state.get('pages', 0), state.get('msgs', 0)
    seen = set(state.get('seen', []))
    stop = 'unknown'
    f = open(outfile, 'a', encoding='utf-8')
    try:
        while pages < max_pages:
            rc, so, se = run(['dws', 'chat', 'message', 'list',
                              '--conversation-id', cid,
                              '--time', str(cursor), '--direction', 'newer',
                              '--limit', '100', '--format', 'json', '--timeout', '45'],
                             timeout=60)
            j = jout(so)
            if not j or rc != 0:
                state['fail'] = state.get('fail', 0) + 1
                if state.get('fail', 0) >= 3:
                    stop = 'stalled'
                    break
                time.sleep(2 * state.get('fail', 1))
                continue
            state['fail'] = 0
            ms = msgs_of(j)
            new = [m for m in ms if m.get('messageId') not in seen]
            for m in new:
                seen.add(m.get('messageId'))
            if new:
                f.write(json.dumps({'cursor': cursor, 'msgs': new}, ensure_ascii=False) + '\n')
                f.flush()
                total += len(new)
            pages += 1
            times = [m.get('createTime') or '' for m in ms if m.get('createTime')]
            if times and min(times) > hi:      # 整页都超出窗口上界
                stop = 'past_HI'
                break
            nc = cursor_of(j)
            if not j.get('hasMore') or not nc or nc == cursor or not ms:
                stop = 'source_complete' if not j.get('hasMore') else 'no_progress'
                break
            cursor = nc
            state.update({'cursor': cursor, 'pages': pages, 'msgs': total,
                          'seen': list(seen)[-5000:]})
            time.sleep(sleep)
        else:
            stop = 'max_pages'
    finally:
        f.flush()
        try:
            os.fsync(f.fileno())
        except Exception:
            pass
        f.close()
    state.update({'cursor': cursor, 'pages': pages, 'msgs': total, 'stop': stop,
                  'done': stop in ('past_HI', 'source_complete', 'no_progress')})
    return total, pages, stop


def fetch_all(convs, raw_dir, lo, hi, state_path, workers=FETCH_WORKERS, tag='c'):
    state = {}
    if os.path.exists(state_path):
        try:
            state = json.load(open(state_path, encoding='utf-8'))
        except Exception:
            state = {}
    os.makedirs(raw_dir, exist_ok=True)
    t0 = time.time()
    lock = threading.Lock()

    def work(i_c):
        i, c = i_c
        cid = c['conversationId']
        st = state.get(cid, {})
        if st.get('done'):
            return c, st.get('msgs', 0), 'skipped'
        out = os.path.join(raw_dir, '%s_%04d.jsonl' % (tag, i))
        n, pg, stop = fetch_conv(cid, out, st, lo, hi)
        with lock:
            state[cid] = st
        return c, n, stop

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        res = list(ex.map(work, enumerate(convs)))
    json.dump(state, open(state_path, 'w', encoding='utf-8'), ensure_ascii=False)
    tot = sum(n for _, n, _ in res)
    stops = Counter(s for _, _, s in res)
    print('      %d 个会话 / %d 条 / %.1f min / stop=%s'
          % (len(res), tot, (time.time() - t0) / 60, dict(stops)))
    return res


# ---------------- 密文提取 ----------------
def iter_raw(raw_dir):
    for fn in sorted(os.listdir(raw_dir)):
        p = os.path.join(raw_dir, fn)
        if fn.endswith('.jsonl'):
            for line in open(p, encoding='utf-8'):
                line = line.strip()
                if not line:
                    continue
                try:
                    blk = json.loads(line)
                except Exception:
                    continue
                for m in (blk.get('msgs') or []):
                    yield m
        elif fn.endswith('.json'):
            try:
                d = json.load(open(p, encoding='utf-8'))
            except Exception:
                continue
            for m in (d.get('messages') or []):
                yield m


def collect_tasks(raw_dir, done_ids):
    """返回 [(key, cipher, meta)]。

    - 正文密文：key = messageId
    - 引用原文密文：key = quotedMessage.openMessageId
    - 按密文字符串去重（同一条被多处引用只需解一次，实测省掉 6,355 次请求）
    """
    seen_cipher = {}
    tasks = []
    for m in iter_raw(raw_dir):
        mid = m.get('messageId')
        # 正文
        if ENC in (m.get('text') or ''):
            c = (m.get('content') or '').strip()
            if mid and c and CIPHER_RE.match(c):
                if mid in done_ids:
                    continue
                if c in seen_cipher:
                    continue
                seen_cipher[c] = mid
                tasks.append((mid, c, {'layer': 'body', 't': m.get('createTime'),
                                       'who': m.get('sender'), 'mid': mid}))
        # 被引用原文
        q = m.get('quotedMessage') or {}
        qc = (q.get('content') or '').strip()
        if qc and CIPHER_RE.match(qc):
            qid = q.get('openMessageId') or q.get('messageId')
            if not qid or qid in done_ids:
                continue
            if qc in seen_cipher:
                continue
            seen_cipher[qc] = qid
            tasks.append((qid, qc, {'layer': 'quoted', 't': m.get('createTime'),
                                    'who': q.get('sender'), 'mid': mid, 'qid': qid}))
    return tasks


# ---------------- 解密 ----------------
def decrypt_all(tasks, tmp_dir, out_path, workers=DEC_WORKERS):
    """tasks: [(key, cipher, meta)]。主层 safechat，失败降级 full。

    注意 --file 必须是相对路径：用 cwd=tmp_dir + 文件名。
    """
    print('[3/4] 解密 %d 条密文，并发 %d，主层 %s' % (len(tasks), workers, LAYER_CHAIN[0]))
    os.makedirs(tmp_dir, exist_ok=True)
    slots = queue.Queue()
    for i in range(workers):
        slots.put(i)
    lock = threading.Lock()
    stats = Counter()
    fout = open(out_path, 'a', encoding='utf-8')
    cnt = [0]
    t0 = time.time()

    def one(item):
        key, cipher, meta = item
        s = slots.get()
        try:
            fn = 'd%d.txt' % s
            with open(os.path.join(tmp_dir, fn), 'w', encoding='utf-8') as fh:
                fh.write(cipher)
            plain, used = None, None
            for layer in LAYER_CHAIN:
                rc, so, se = run(['dws', 'chat', 'crypto', 'decrypt', '--file', fn,
                                  '--layer', layer, '--format', 'json'],
                                 timeout=90, cwd=tmp_dir)
                j = jout(so)
                if j and j.get('ok') and j.get('plaintext'):
                    cand = j['plaintext']
                    if is_envelope(cand):
                        # 1_1_<hex>：本地层剥掉了 SafeChat，但服务端 DING 层没跑成。
                        # 绝不能当明文收下（v2 就是这么污染语料的）。
                        with lock:
                            stats['envelope'] += 1
                        continue
                    plain, used = cand, layer
                    break
            if plain:
                with lock:
                    stats['ok_' + used] += 1
                    rec = dict(meta)
                    rec.update({'key': key, 'text': plain, 'layer': used})
                    fout.write(json.dumps(rec, ensure_ascii=False) + '\n')
                    cnt[0] += 1
                    if cnt[0] % 200 == 0:
                        fout.flush()
                        el = time.time() - t0
                        print('      %d/%d  %.2f 条/秒  %s'
                              % (cnt[0], len(tasks), cnt[0] / el if el else 0, dict(stats)),
                              flush=True)
            else:
                with lock:
                    stats['failed'] += 1
                    fout_err = open(out_path + '.failed', 'a', encoding='utf-8')
                    fout_err.write(json.dumps({'key': key, 'meta': meta}, ensure_ascii=False) + '\n')
                    fout_err.close()
        except Exception as e:
            with lock:
                stats['exception'] += 1
        finally:
            slots.put(s)

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(one, tasks))
    fout.flush()
    try:
        os.fsync(fout.fileno())
    except Exception:
        pass
    fout.close()
    el = time.time() - t0
    print('      解密完成 %s，耗时 %.1f min（%.2f 条/秒）'
          % (dict(stats), el / 60, len(tasks) / el if el else 0))
    return stats


# ---------------- 合并 ----------------
def merge(raw_dir, out_path, dec_path):
    print('[4/4] 合并明文语料')
    dec = {}
    if os.path.exists(dec_path):
        for line in open(dec_path, encoding='utf-8'):
            try:
                r = json.loads(line)
                if r.get('key'):
                    dec[r['key']] = r['text']
                if r.get('messageId'):
                    dec[r['messageId']] = r['text']
            except Exception:
                pass
    rows, stat = [], Counter()
    for m in iter_raw(raw_dir):
        t = m.get('text') or ''
        if ENC in t:
            pt = dec.get(m.get('messageId'))
            if pt:
                t = pt
                stat['decrypted'] += 1
            else:
                stat['still_encrypted'] += 1
                continue
        else:
            stat['plain'] += 1
        rows.append({'session': m.get('conversationTitle') or m.get('conversationId', ''),
                     'time': m.get('createTime', ''),
                     'sender': m.get('sender', ''), 'text': t})
    rows.sort(key=lambda r: r['time'])
    with open(out_path, 'w', encoding='utf-8') as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + '\n')
    print('      %s -> %s（共 %d 条）' % (dict(stat), out_path, len(rows)))
    return stat


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--days', type=int, default=92)
    ap.add_argument('--out', default='./dingtalk_out')
    ap.add_argument('--kind', choices=['direct', 'group', 'all'], default='direct',
                    help='会话类型；群聊正文也会加密，建议 all')
    ap.add_argument('--workers', type=int, default=DEC_WORKERS, help='解密并发（16 封顶）')
    ap.add_argument('--fetch-workers', type=int, default=FETCH_WORKERS)
    ap.add_argument('--limit', type=int, default=0, help='只解密前 N 条（试跑）')
    ap.add_argument('--raw-dir', default='', help='覆盖原始数据目录（默认 <out>/raw）')
    ap.add_argument('--start', default='', help='窗口下界，默认 now-days')
    ap.add_argument('--end', default='', help='窗口上界，默认 now')
    args = ap.parse_args()

    check_version()
    out_dir = args.out
    raw_dir = args.raw_dir or os.path.join(out_dir, 'raw')
    tmp_dir = os.path.join(out_dir, 'tmpdec')
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(tmp_dir, exist_ok=True)

    f = '%Y-%m-%d %H:%M:%S'
    end_s = args.end or dt.datetime.now().strftime(f)
    start_s = args.start or (dt.datetime.now() - dt.timedelta(days=args.days)).strftime(f)
    print('窗口: %s ~ %s' % (start_s, end_s))

    conv_path = os.path.join(out_dir, 'conversations.json')
    if os.path.exists(conv_path):
        convs = json.load(open(conv_path, encoding='utf-8'))
        print('[1/4] 复用已有会话清单 %d 个' % len(convs))
    else:
        convs = fetch_conversations(start_s, end_s, out_dir)

    if args.kind == 'all':
        targets = [c for c in convs if c.get('type') in ('direct', 'group')
                   and c.get('name') not in SKIP_SESSIONS]
    else:
        targets = [c for c in convs if c.get('type') == args.kind
                   and c.get('name') not in SKIP_SESSIONS]
    print('[2/4] 拉取 %s 会话 %d 个' % (args.kind, len(targets)))
    fetch_all(targets, raw_dir, start_s, end_s,
              os.path.join(out_dir, 'state_fetch.json'),
              workers=args.fetch_workers, tag='c')

    dec_path = os.path.join(out_dir, 'decrypted.jsonl')
    done_ids = set()
    if os.path.exists(dec_path):
        for line in open(dec_path, encoding='utf-8'):
            try:
                r = json.loads(line)
                if r.get('key'):
                    done_ids.add(r['key'])
                if r.get('messageId'):
                    done_ids.add(r['messageId'])
            except Exception:
                pass
    tasks = collect_tasks(raw_dir, done_ids)
    if args.limit:
        tasks = tasks[:args.limit]
    if tasks:
        decrypt_all(tasks, tmp_dir, dec_path, args.workers)
    else:
        print('[3/4] 无待解密密文')

    merge(raw_dir, os.path.join(out_dir, 'messages.jsonl'), dec_path)
    print('DONE ->', os.path.abspath(out_dir))


if __name__ == '__main__':
    main()
