#!/usr/bin/env python3
"""
钉钉消息读取 + 三方密文解密（自包含工具）

背景
----
企业钉钉开启「三方加密」后，dws 的高层命令（+chat-messages / +at-me）
会把读不到的消息替换成占位符 "[加密消息，无法解码]"。
原因不是技术做不到，而是列表接口的内置解密被服务端策略禁用
（返回 reason=policy_disabled, decryptAllowedCount=0）。

正确做法：
  1. 用底层 `dws chat message list` 拿到 content 字段（密文原文，形如 "xxx...||2||1||228"）
  2. 用 `dws chat crypto decrypt --layer full` 逐条解密（SafeChat 本地层 + Ding 服务端层）
实测成功率 99.93%。

用法
----
  python dws_decrypt.py --days 92 --out ./out               # 近 92 天全部单聊
  python dws_decrypt.py --days 92 --out ./out --workers 32  # 提高并发
  python dws_decrypt.py --days 92 --out ./out --limit 200   # 只处理前 200 条（试跑）
  python dws_decrypt.py --resume --out ./out                # 断点续跑

产出
----
  out/conversations.json   会话列表
  out/raw/NNN.json         每个会话的原始拉取结果（含 content 密文）
  out/decrypted.jsonl      解密成功的明文（可反复追加，支持断点续跑）
  out/messages.jsonl       合并后的完整明文语料（明文 + 解密结果）

依赖
----
  dws CLI >= v1.0.63（v1.0.62 的 safechat 本地层会 cgo 崩溃，必须先 dws upgrade）
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import re
import subprocess
import threading
from collections import Counter

ENC = '加密消息，无法解码'
SKIP_SESSIONS = ['钉钉文档自动化助手', 'AI听记助手', 'OA审批助手', '员工关怀', '差旅助手']


def run(cmd, timeout=240):
    p = subprocess.run(cmd, capture_output=True, timeout=timeout)
    return (p.stdout or b'').decode('utf-8', 'ignore')


def check_version():
    out = run(['dws', 'version'])
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


def fetch_conversations(days, out_dir):
    end = dt.datetime.now()
    start = end - dt.timedelta(days=days)
    f = '%Y-%m-%d %H:%M:%S'
    print('[1/4] 拉取会话列表 %s ~ %s' % (start.strftime(f), end.strftime(f)))
    cmd = ['dws', 'chat', '+recent-conversations',
           '--start', start.strftime(f), '--end', end.strftime(f),
           '--limit', '100', '--page-limit', '500', '--page-delay', '100',
           '--format', 'json']
    raw = run(cmd, timeout=900)
    d = json.loads(raw)
    convs = d['data']['succeeded'][0]['conversations']
    json.dump(convs, open(os.path.join(out_dir, 'conversations.json'), 'w', encoding='utf-8'),
              ensure_ascii=False, indent=1)
    directs = [c for c in convs if c.get('type') == 'direct'
               and c.get('name') not in SKIP_SESSIONS]
    groups = [c for c in convs if c.get('type') == 'group']
    print('      会话 %d 个（单聊 %d / 群聊 %d）' % (len(convs), len(directs), len(groups)))
    return directs, end.strftime(f)


def fetch_one(item, raw_dir, end_time, max_items):
    idx, c = item
    out = os.path.join(raw_dir, 'dm_%03d.json' % idx)
    if os.path.exists(out):
        try:
            if len(json.load(open(out, encoding='utf-8')).get('messages') or []) > 0:
                return idx, c['name'], 'skip'
        except Exception:
            pass
    cmd = ['dws', 'chat', 'message', 'list',
           '--conversation-id', c['conversationId'],
           '--time', end_time, '--direction', 'older',
           '--page-all', '--page-limit', '200', '--max-items', str(max_items),
           '--format', 'json']
    try:
        raw = run(cmd, timeout=300)
        open(out, 'w', encoding='utf-8').write(raw)
        return idx, c['name'], 'ok'
    except Exception as e:
        open(out, 'w', encoding='utf-8').write(json.dumps({'error': str(e)}, ensure_ascii=False))
        return idx, c['name'], 'FAIL'


def fetch_all(directs, raw_dir, end_time, workers, max_items):
    print('[2/4] 拉取单聊消息（含密文 content），并发 %d' % workers)
    with cf.ThreadPoolExecutor(max_workers=max(1, workers // 2) or 1) as ex:
        for idx, name, st in ex.map(lambda it: fetch_one(it, raw_dir, end_time, max_items),
                                    enumerate(directs)):
            print('      %d %s %s' % (idx, name, st), flush=True)


def collect_tasks(raw_dir, name_by_idx, done):
    tasks = []
    for idx, name in name_by_idx.items():
        p = os.path.join(raw_dir, 'dm_%03d.json' % idx)
        if not os.path.exists(p):
            continue
        try:
            d = json.load(open(p, encoding='utf-8'))
        except Exception:
            continue
        for m in d.get('messages') or []:
            if ENC not in (m.get('text') or ''):
                continue
            if m.get('messageId') in done:
                continue
            c = m.get('content') or ''
            if not c or '||' not in c:
                continue
            tasks.append((idx, name, m))
    return tasks


def decrypt_all(tasks, tmp_dir, workers, out_path):
    print('[3/4] 解密 %d 条密文，并发 %d（实测瓶颈在服务端限速约 5 条/秒，加并发收益有限）'
          % (len(tasks), workers))
    lock = threading.Lock()
    stats = Counter()
    fout = open(out_path, 'a', encoding='utf-8')
    cnt = [0]

    def work(item):
        i, (idx, name, m) = item
        tmp = os.path.join(tmp_dir, 'in_%d.txt' % i)
        try:
            with open(tmp, 'w', encoding='utf-8') as f:
                f.write(m.get('content') or '')
            out = run(['dws', 'chat', 'crypto', 'decrypt', '--file', tmp,
                       '--layer', 'full', '--format', 'json'], timeout=120)
        except Exception:
            out = ''
        plain = None
        try:
            j = json.loads(out)
            v = j.get('plaintext')
            if isinstance(v, str) and v.strip() and '加密' not in v:
                plain = v
            else:
                with lock:
                    stats['fail_' + str((j.get('error') or {}).get('message', 'no_plaintext'))[:50]] += 1
        except Exception:
            with lock:
                stats['unparsable'] += 1
        if plain:
            with lock:
                stats['success'] += 1
                fout.write(json.dumps({
                    'session': name, 'time': m.get('createTime', ''),
                    'sender': m.get('sender', ''), 'messageId': m.get('messageId', ''),
                    'text': plain,
                }, ensure_ascii=False) + '\n')
                cnt[0] += 1
                if cnt[0] % 100 == 0:
                    fout.flush()
                    print('      %d %s' % (cnt[0], dict(stats)), flush=True)

    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        list(ex.map(work, enumerate(tasks)))
    fout.close()
    print('      解密完成', dict(stats))
    return stats


def merge(raw_dir, name_by_idx, dec_path, out_path):
    print('[4/4] 合并明文语料')
    dec = {}
    if os.path.exists(dec_path):
        for line in open(dec_path, encoding='utf-8'):
            try:
                r = json.loads(line)
                dec[r['messageId']] = r['text']
            except Exception:
                pass
    rows = []
    stat = Counter()
    for idx, name in name_by_idx.items():
        p = os.path.join(raw_dir, 'dm_%03d.json' % idx)
        if not os.path.exists(p):
            continue
        try:
            d = json.load(open(p, encoding='utf-8'))
        except Exception:
            continue
        for m in d.get('messages') or []:
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
            rows.append({'session': name, 'time': m.get('createTime', ''),
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
    ap.add_argument('--workers', type=int, default=16)
    ap.add_argument('--max-items', type=int, default=600, help='每个会话最多拉取条数')
    ap.add_argument('--limit', type=int, default=0, help='只解密前 N 条（试跑）')
    ap.add_argument('--resume', action='store_true', help='跳过已有原始文件的会话')
    ap.add_argument('--skip-fetch', action='store_true', help='已有原始数据，直接解密')
    ap.add_argument('--raw-dir', default='', help='覆盖原始数据目录（默认 <out>/raw）')
    args = ap.parse_args()

    check_version()
    out_dir = args.out
    raw_dir = args.raw_dir or os.path.join(out_dir, 'raw')
    tmp_dir = os.path.join(out_dir, 'tmpdec')
    os.makedirs(raw_dir, exist_ok=True)
    os.makedirs(tmp_dir, exist_ok=True)

    if args.skip_fetch:
        convs = json.load(open(os.path.join(out_dir, 'conversations.json'), encoding='utf-8'))
        directs = [c for c in convs if c.get('type') == 'direct']
        end_time = dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    else:
        directs, end_time = fetch_conversations(args.days, out_dir)
        fetch_all(directs, raw_dir, end_time, args.workers, args.max_items)

    name_by_idx = {i: c['name'] for i, c in enumerate(directs)}
    dec_path = os.path.join(out_dir, 'decrypted.jsonl')
    done = set()
    if os.path.exists(dec_path):
        for line in open(dec_path, encoding='utf-8'):
            try:
                done.add(json.loads(line)['messageId'])
            except Exception:
                pass
    tasks = collect_tasks(raw_dir, name_by_idx, done)
    if args.limit:
        tasks = tasks[:args.limit]
    if tasks:
        decrypt_all(tasks, tmp_dir, args.workers, dec_path)
    else:
        print('[3/4] 无待解密密文')

    merge(raw_dir, name_by_idx, dec_path, os.path.join(out_dir, 'messages.jsonl'))
    print('DONE ->', os.path.abspath(out_dir))


if __name__ == '__main__':
    main()
