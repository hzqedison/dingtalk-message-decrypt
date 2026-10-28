# 一个仓库维护读取与调用校验

读取相关代码的唯一维护源是 `hzqedison/dingtalk-message-decrypt`：客户端适配、统一读取入口、调用校验、接入示例和合成测试都在此仓库。更新后运行 `sync_to_agents.sh`，以下模块和示例随技能一起部署；无需再从其他仓库获取这次修复。

## 给 DELL / 其他设备 Agent

先保留现有未提交修改，核对实际技能部署。阅读本文，使用此仓库的调用校验模块，将下列示例中的改动移植到现有调用脚本。保留现场路径、账号 scope、策略库和排程；不要直接用脱敏示例覆盖业务脚本。

| 原调用脚本 | 本仓库迁移示例 | 修复 |
| --- | --- | --- |
| `collect_2026_10_24_midday_readonly.py` | [daily_collect.py](daily_collect.py) | 显式模式参数、同源日志、正确输出目录、零输入停止 |
| `collect_retry3_full_readonly.py` | [fetch_only.py](fetch_only.py) | 取消全局 subprocess 拦截，不删除 auto，核验真实小样 |
| `continue_retry3_1028.py` | [continue_saved.py](continue_saved.py) | 导入无采集副作用、精确父消息绑定、提取 original、新输出目录、小样失败停止 |

三个示例是历史脚本的脱敏迁移参考，保留历史日期以方便对照；不会被安装或同步脚本执行。不要直接运行示例。它们的导入路径适用于仓库和已部署技能内的当前目录；移植到业务项目时，改为下面的技能路径加载方式。

通用校验只在 [scripts/caller_checks.py](../../scripts/caller_checks.py) 维护。业务项目不要再复制一份该模块，否则以后更新技能仍可能使用旧校验。明确加载当前技能目录：

```python
from pathlib import Path
import sys

skill = Path.home() / '.codex' / 'skills' / 'dingtalk-message-decrypt'
sys.path.insert(0, str(skill / 'scripts'))
from caller_checks import mode_config, mode_args, originals, write_rows, validate_result

mode = mode_config(client='auto', local_crypto='auto')
# cmd 中使用 *mode_args(mode)，日志直接保存同一个 mode。
# 只抓原始数据时使用 mode_config(client='off', local_crypto='off')。
```

长驻 Python 进程在更新后应重新启动本次调用，使已加载的模块不会停留在旧版本。scope 仍由调用方按已认证账号核对；本模块不替代认证核验。

## 验收约定

`validate_result(result_dir, returncode, expected, kind)` 的 `expected` 是实际送入读取器的原始记录列表。`kind='body'` 或 `'quote'` 表示严格本地解密小样：

- 退出码必须为 0，输入必须为一条，输出原始记录必须与输入相同；引用以整个父消息原始记录绑定，不能只比较引用 ID。
- 必须有明确的完成字段、零未解决项及空 `local_crypto.stop_reason`；缺失字段会失败，不补成 0。
- 目标结果必须为 `decrypted_local`、`crypto_decryption_proven=true`，且通过统一读取器的可读文本检查。缓存或客户端观察不算本轮小样解密。
- 无 `kind` 时验证整个所提供输入的非零数量、完整状态及原始记录集合，不代表时间窗、分页、附件或业务流程全部完成。
- 这些是调用契约校验，不是对不可信外来结果的签名验证，也不提供独立可信明文对照。

续跑示例先在新目录验证正文和引用，再将 `original` 写入独立 `original-input.jsonl`。不会重新使用旧 `resolution` 作为新恢复证据。若本次只授权小样，不要执行示例中的后续批量步骤。

## 只运行合成测试

在仓库根目录，用现有 Python：

```text
python -B -m unittest discover -s tests -p test_caller_checks.py -v
python -B -m unittest discover -s tests -v
```

调用层测试默认禁止真实 subprocess，全部数据为合成，所有写入位于临时目录。测试成功不等于 DELL 业务脚本已部署，也不等于实际消息已恢复。

`AI` 私有仓库此前的 `codex/dell-caller-guards-20261029` 仅保留历史交接快照；后续读取能力修复以本仓库为准。账号配置、消息、缓存、凭据、日报和定时任务仍由各设备本地业务项目管理，不属于公开技能源代码。
