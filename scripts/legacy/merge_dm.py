"""【历史脚本 · 已被 scripts/dws_decrypt.py 取代，仅作参考】

合并「原始可读消息」+「解密结果」→ 完整单聊语料，并按关键词粗筛出疑似待办信号分片。

这是「钉钉待办清单」那次分析的中间步骤，保留下来供参考：
它演示了如何判断哪些消息是待办信号（关键词命中 + 剔除群发文本）。

依赖：
  - dm_cipher_meta.json / dm_cipher/*.json   fetch_dm_cipher.py 的产物
  - dm_decrypted.jsonl                       解密结果（每行含 messageId / text）

用法：
  export DWS_ME="你的钉钉昵称"   # 必填：过滤掉自己发出的消息
  python merge_dm.py

产出：
  slices2/dm_1..N.txt   按待办信号切分的分片文本
"""
import json, os, re
from collections import Counter

ENC = '加密消息，无法解码'
ME = os.environ.get('DWS_ME', '')
if not ME:
    print('提示：未设置 DWS_ME，自己发出的消息不会被过滤')

meta = json.load(open('dm_cipher_meta.json', encoding='utf-8'))
names = {m['idx']: m['name'] for m in meta}

# 1. 解密结果索引: messageId -> plaintext
dec = {}
if os.path.exists('dm_decrypted.jsonl'):
    for line in open('dm_decrypted.jsonl', encoding='utf-8'):
        try:
            r = json.loads(line)
        except Exception:
            continue
        dec[r['messageId']] = r['text']
print('解密结果', len(dec))

allmsgs = []
stat = Counter()
for idx, name in names.items():
    p = 'dm_cipher/dm_%03d.json' % idx
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
        allmsgs.append((m.get('createTime', ''), name, m.get('sender', ''), t))

print('消息统计', dict(stat))
print('可用于分析的条数', len(allmsgs))

# 2. 清洗
def clean(s):
    s = re.sub(r'\s+', ' ', s.replace('\n', ' '))
    s = re.sub(r'\[图片消息\]\([^)]*\)', '[图]', s)
    s = re.sub(r'\[加密消息，无法解码\]', '[加密]', s)
    return s.strip()

# 3. 群发检测（同一文本出现在 >=4 个会话视为群发通知）
cnt = Counter(clean(m[3])[:60] for m in allmsgs)
broadcast = {k for k, v in cnt.items() if v >= 4 and len(k) > 10}

KW = ['帮', '麻烦', '辛苦', '请', '跟进', '确认', '处理', '看一下', '看看', '安排', '提供', '输出',
      '支持', '对接', '排查', '修复', '推进', '同步', '反馈', '补充', '评估', '上线', '排期', '方案',
      '评审', '需要你', '记得', '别忘', '截止', '明天', '下周', '本周', '拉个', '问一', '改一', '加一',
      '配一', '发我', '给我', '整理', '统计', '梳理', '优化', '测试', '验证', '推动', '协调', '准备',
      '负责', '认领', '沟通', '开会', '碰', '对齐', '催', '提醒', '待办', 'todo', '搞定', '查一', '查下',
      '看下', '解决', '完善', '能不能', '是否可以', '加下', '改下', '确认下', '跟进下', '同步下', '对一下',
      '交接', '部署', '提测', '验收', '走查', '发一下', '发个', '约个', '安排下', '吗', '？', '?', '一下',
      '要不', '建议', '帮忙', '需要', '希望', '尽快', '决定', '审批', '签字', '回复', '回一下', '回我', '答复']

out = []
seen = set()
for tm, name, sender, t in allmsgs:
    if ME and sender == ME:
        continue
    c = clean(t)
    if not c or c[:60] in broadcast:
        continue
    if not any(k in c for k in KW):
        continue
    key = (name, c[:80])
    if key in seen:
        continue
    seen.add(key)
    if len(c) > 240:
        c = c[:240] + '…'
    out.append((tm, name, c))

out.sort()
print('待办信号条数', len(out))
os.makedirs('slices2', exist_ok=True)
N = 8
step = (len(out) + N - 1) // N
for k in range(N):
    part = out[k * step:(k + 1) * step]
    lines = ['[%s] %s: %s' % a for a in part]
    open('slices2/dm_%d.txt' % (k + 1), 'w', encoding='utf-8').write('\n'.join(lines))
    print(k + 1, len(part))
