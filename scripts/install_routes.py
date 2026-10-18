"""Add a small, reversible decrypt-skill route to explicitly selected skill files."""
import argparse
import os
from pathlib import Path

START = '<!-- DINGTALK_DECRYPT_ROUTE_START -->'
END = '<!-- DINGTALK_DECRYPT_ROUTE_END -->'


def install(path, decrypt_skill):
    path, decrypt_skill = Path(path).resolve(), Path(decrypt_skill).resolve()
    text = path.read_text(encoding='utf-8-sig')
    if not decrypt_skill.is_file():
        raise ValueError('Decrypt skill is not installed')
    try:
        target = os.path.relpath(decrypt_skill, path.parent).replace('\\', '/')
    except ValueError:  # Windows skills may live on a different volume.
        target = decrypt_skill.as_posix()
    block = f'''{START}
## 加密聊天记录的读取路由

读取/整理聊天记录或结果出现加密占位符时，先加载 [dingtalk-message-decrypt]({target})。
密文需要底层 `content`，优先执行该技能的批处理脚本，避免逐消息调用模型或在命令间猜测重试。
此读取场景使用该技能的分页和解密路径，优先于下文通用消息读取路由；其他能力沿用原路由。
服务端 `CRYPTO_DISABLED` 应缓存并停止重复请求，继续技能默认的本地独立解密后端；它不要求目标消息当前显示。客户端正文观察仅作额外补充。按真实来源报告结果与缺口，不能宣称全部历史可读。
{END}'''
    if START in text:
        before, rest = text.split(START, 1)
        _, after = rest.split(END, 1)
        updated = before + block + after
    else:
        if not text.startswith('---\n'):
            raise ValueError('Expected YAML frontmatter')
        pos = text.find('\n---\n', 4)
        if pos < 0:
            raise ValueError('Missing frontmatter terminator')
        pos += len('\n---\n')
        updated = text[:pos] + '\n' + block + '\n' + text[pos:]
    if updated == text:
        return 'unchanged'
    backup = path.with_name(path.name + '.before-decrypt-route.bak')
    if not backup.exists():
        backup.write_bytes(path.read_bytes())
    path.write_text(updated, encoding='utf-8', newline='\n')
    return 'updated'


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--skill-file', action='append', required=True)
    p.add_argument('--decrypt-skill', default=str(Path.home()/'.agents/skills/dingtalk-message-decrypt/SKILL.md'))
    args = p.parse_args()
    seen = set()
    for supplied in args.skill_file:
        path = Path(supplied).resolve()
        if path not in seen:
            print(f'{install(path,args.decrypt_skill)}: {path}')
            seen.add(path)
