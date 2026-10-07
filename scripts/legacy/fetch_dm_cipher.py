"""【历史脚本 · 已被 scripts/dws_decrypt.py 取代，仅作参考】

批量拉取单聊消息的「密文原文」（content 字段），为逐条解密做准备。

为什么需要它：高级命令 `dws chat +chat-messages` 会把读不到的消息替换成
占位符 `[加密消息，无法解码]`，拿不到密文；只有底层命令
`dws chat message list` 才会返回 content 字段。

依赖：
  - rc3m.json：由 `dws chat +recent-conversations` 导出的会话列表
  - dws CLI >= v1.0.63

用法：
  export DWS_ME="你的钉钉昵称"          # 必填：用于排除自己（可能不止一个账号）
  export DWS_START="2026-10-07 00:00:00"  # 可选：拉取起点，默认今天 0 点
  python fetch_dm_cipher.py

产出：
  dm_cipher_meta.json   会话索引（idx / 昵称 / conversationId）
  dm_cipher/dm_NNN.json 每个会话的原始返回（含 content 密文）
"""
import json, os, subprocess, concurrent.futures as cf

ME = os.environ.get('DWS_ME', '')
START_TIME = os.environ.get('DWS_START', '2026-10-07 00:00:00')
if not ME:
    print('提示：未设置 DWS_ME，自己的账号不会被排除（可能混入自己发出的消息）')

d = json.load(open('rc3m.json', encoding='utf-8'))
cs = d['data']['succeeded'][0]['conversations']
directs = [c for c in cs if c['type'] == 'direct']

# 机器人 / 助手账号不计入
SKIP = ['钉钉文档自动化助手', 'AI听记助手', 'OA审批助手', '员工关怀', '差旅助手']
# 你自己的账号昵称（可能有多个），用逗号分隔传入
SKIP += [x for x in os.environ.get('DWS_SKIP_ME', '').split(',') if x]
if ME:
    SKIP.append(ME)

targets = [c for c in directs if c['name'] not in SKIP]

os.makedirs('dm_cipher', exist_ok=True)
meta = [{'idx': i, 'name': c['name'], 'cid': c['conversationId']} for i, c in enumerate(targets)]
json.dump(meta, open('dm_cipher_meta.json', 'w', encoding='utf-8'), ensure_ascii=False, indent=1)
print('targets', len(targets), flush=True)


def fetch(item):
    idx, c = item
    out = 'dm_cipher/dm_%03d.json' % idx
    if os.path.exists(out):
        try:
            if len(json.load(open(out, encoding='utf-8')).get('messages') or []) > 0:
                return idx, c['name'], 'skip'
        except Exception:
            pass
    cmd = ['dws', 'chat', 'message', 'list',
           '--conversation-id', c['conversationId'],
           '--time', START_TIME, '--direction', 'older',
           '--page-all', '--page-limit', '200', '--max-items', '600',
           '--format', 'json']
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=240)
        open(out, 'wb').write(p.stdout)
        return idx, c['name'], 'ok'
    except Exception as e:
        open(out, 'w', encoding='utf-8').write(json.dumps({'error': str(e)}, ensure_ascii=False))
        return idx, c['name'], 'FAIL'


with cf.ThreadPoolExecutor(max_workers=6) as ex:
    for idx, name, st in ex.map(fetch, enumerate(targets)):
        print(idx, name, st, flush=True)
print('DONE')
