# 批处理行为与边界

## 输入、输出、恢复

入口 `scripts/dws_decrypt.py` 支持重复的 `--input`（原始 JSON/JSONL 或平面目录）；不传输入则用当前已认证 dws 账号读取。
脚本不选择账号，也不读取/保存 token。`--scope` 是调用方设置的账号工作区标签，不是认证凭据；账号切换后使用不同输出目录和 scope。

首次读取指定 `--conversation-id`（可重复）、`--start`、`--end`，或以 `--days` 指定相对窗口。
不指定会话时扫描活跃会话；默认 7 天、`--kind all`，近 7 天会话接口可能返回 0，不能据此断言没有历史消息。
恢复用同一个 `--out`、`--scope` 和 `--resume`，沿用固定时间窗；不要同时传 `--days`。
原始响应、页检查点先落盘，停滞或异常保留 partial。未指定完整时间范围时不要声称覆盖全部历史。

读取会话使用 `+recent-conversations` 的 cursor 到 `endpoint_exhausted`；正文用 `chat message list` 的 `--direction newer` 与时间下界，继续 `nextPage.time`，不传 `--max-items`。
成功翻页和正文可读是两个维度。导入快照若没有分页报告，读取完整性标记 unknown。

| 文件 | 用途 |
|---|---|
| `summary.json` | 数量、状态、读取完整性、停止原因、客户端补充结果；模型先只读它 |
| `messages.jsonl` | 仅可读正文，保留来源；按任务需要再分析 |
| `resolved.jsonl` | 每条原始记录与独立解析结果，引用不覆盖当前正文 |
| `unresolved.jsonl` | 仍未解决的正文、引用或冲突 |
| `fetch/raw/` | 原始分页响应；恢复时验证 |
| `resolution_cache.sqlite3` | 按 scope + CID + 完整密文哈希 + 显式企业身份隔离的解密结果与来源；另保留旧 full 缓存及策略停止状态 |
| `client-*/` | 本轮只读证据、补充正文与 API 身份索引 |

退出码：0=提供记录中无未解决文本项（仍检查输入范围）；2=有可用产物的 partial；1=参数/输入/执行错误。
空内容或非文本结构保留在原始记录中，不虚构正文。`unresolved_items` 按字段统计，不能当作未读消息条数。
同 ID 不同正文/时间/引用/发送者/显式企业身份版本拒绝自动覆盖；同 CID、同密文且显式企业身份一致的确定解密结果可以回填多个 ID，但客户端观察仅匹配确切 ID。引用自身的显式身份与对应正文冲突时拒绝复用，也不能用父消息企业替代引用企业。

本地缓存使用独立的 `resolved_identity` 表，保留企业、key 版本、算法类型、身份依据、客户端版本摘要和原始来源。后端提供的 `identity_evidence` 也原样保留，包括证据时点和历史归属稳定性限制。命中后 `source=decrypted_local_cache`、`source_resolution_status=decrypted_local`；`cache_hit=true` 表示本轮未重新执行密码运算。`messages.jsonl` 和 `resolved.jsonl` 都保留这些来源字段。此处只缓存正文与非秘密元数据，不保存 key。

旧 `resolved` 表继续支持无显式身份的 full 缓存；输入出现显式 oid/corpId 时不会使用旧身份不明条目。升级时，同一 scope 的旧 `resolved.jsonl` 正文记录可补回本地来源，但须与当前输入 CID、MID、完整密文、显式身份及保存的密文哈希匹配，并与旧缓存正文完全一致；来源或正文冲突不迁移。只有旧 `decrypted_cache` 标记而没有本地来源记录时，不能倒推出企业或解密来源。迁移条数见 `summary.migrated_local_cache_entries`。复制工作区验证时保留 `scope.json`、`resolution_manifest.json`、`resolution_cache.sqlite3` 和 `resolved.jsonl`，输入原始快照须位于输出目录之外。

## 服务端与客户端

`--server auto` 复用本目录缓存，对未命中内容只走 `full`。首次必要时检查 dws >=1.0.63。
`CRYPTO_DISABLED` 持久化后整批及后续运行停止服务端重试。已知策略关闭时用 `--known-policy-disabled` 种入事实，无需再探测。
`--server off` 禁止本轮服务端调用（仍可读合法缓存）；只有确认策略恢复后才用 `--server retry` 清除该停止状态。
未知失败停止本轮，不循环猜命令。中间信封、占位符、非法 UTF-8 不进入正文缓存。
不把 `safechat` 中间信封当明文，不采用 `ding`、清空 keystore、升级来重试策略关闭或申请虚构 scope。

`--client auto --local-crypto auto`（默认）先使用本地DING后端：dws `safechat`仅去掉外层，解析type/version后用确定匹配的客户端缓存key解包、AES-CBC解密；严格验证填充和UTF-8。该路径读取所选企业/版本的包装key，在Python内存中处理，不写key文件、不调用目标函数、不操作界面。`CRYPTO_DISABLED`只熔断服务端，不能关闭这个后端。

身份来源：消息extension.oid或顶层oid优先，按客户端组织映射；消息另有显式corpId时须与映射一致。无oid但有显式corpId时按该企业选择版本key；两者均缺失时读取`chat conversation-info`，要求成功且返回openConversationId精确一致，群会话可使用该corpId并保留查询时间/响应摘要。单聊等未提供企业字段时，脚本对本批正文及引用的目标CID只扫描一次原生Conversation对象（40秒/3GiB上限）；完整扫描后按同一对象的external CID、internal CID及组织字段建立候选，要求双读稳定、所有候选一致、原生开关开/关的组织选择一致。身份来源为`native_conversation_candidate_consensus`，并不宣称已复现原生服务缓存选择。扫描失败本轮不反复重试，单CID元数据请求失败负缓存。

不同企业不试解。缺候选、身份分歧、未知身份、缺版本key继续未解决。会话当前企业是候选归属依据，不等于逐条历史归属已独立验证；消息显式oid不能被它覆盖。引用只用自己的身份或精确同ID正文结果，不继承父消息oid。扫描摘要见`local_crypto.native_conversation_provider`，完整来源证据随正文、引用及本地缓存保留。

`--local-crypto off`关闭此后端，`--client off`同时关闭本地解密及对象补充。`--decrypt-limit`分别限制服务端调用和本地SafeChat调用次数，0不限制；不影响分页。`summary.local_crypto`分别列SafeChat调用、会话元数据请求、停止原因及身份来源。

本地后端失败后，`--client auto`仅在仍有正文密文未解决时尝试读取已加载消息对象；对象补充不会读取key或操作界面。纯离线`--server off --client off`不会调用dws或客户端。
前提是 Python 可导入 `pefile`（本地密码运算另需PyCryptodome），且唯一主进程使用已验证 DLL（9.0.2.261015001，SHA-256 `23bf21eec6a50c69388089e7ddeb22b573439c36f4c9be4c396d719a3f375d77`）。未知版本拒绝读取，不猜偏移。
两次独立扫描各限定 45 秒/3 GiB；不写内存转储，仅保存通过会话与结构验证的对象。每个正文/身份/扩展字段双读一致，已撤回标记排除。
客户端可能没有目标消息驻留，此时记录 0，保留原始快照和此前成果；不把扫描成功当作解密成功。

正文来源：`original_plaintext`、`decrypted_full`、`decrypted_local`、`decrypted_cache`、`decrypted_local_cache`、`client_observed`。本轮本地密码运算数与本地缓存命中数分开统计，缓存保留原始身份依据，不证明当前账号权限、当前会话归属或编辑/撤回状态仍未变化。
后者是客户端已加载正文的观察，不证明独立解密算法成功。仅完整密文 + 原生 ID/CID 的同对象关联并通过 API 时间校验才回填 API 记录；只有相近时间的对象绝不回填。
没有 API 强绑定的正文单独保存 `supplemental_native_messages.jsonl`，不可与 `messages.jsonl` 数量直接相加。
`--client-index` 仅导入本地受信任的采集索引；哈希用于一致性校验，不是对任意外来文件的真实性认证。离线证据反映采集时状态，不保证后来没有编辑/撤回。

## 跨设备排查

先核对实际技能路径、运行脚本的 Python 解释器、dws 版本、客户端版本/DLL 哈希及当前账号。客户端与 dws 是否为同一账号需独立核验，企业身份匹配不能替代账号核验。不自动切账号。

本地后端在读取客户端和调用 SafeChat 前检查 `Crypto.Cipher.AES` 与 `pefile` 能否导入。失败时 `local_crypto.stop_reason=local_dependency_unavailable`，同批不继续客户端扫描，保留已有明文和缓存结果。`local_crypto.dependencies` 说明失败模块及其 `install_command`，`python_executable` 指向实际运行环境。依赖可用性只在本地后端实际需要执行时检查；纯离线缓存重放无需这些依赖。

`Crypto` 来自 `pycryptodome`，不是 `crypto`；`pycryptodomex` 的模块名是 `Cryptodome`，也不满足当前代码。PowerShell 中使用报告给出的解释器绝对路径，例如：

```powershell
& '<实际 Python.exe 路径>' -m pip install pycryptodome pefile
& '<实际 Python.exe 路径>' -c "import sys, pefile, Crypto; from Crypto.Cipher import AES; print(sys.executable); print(Crypto.__version__)"
```

导入不可用可能是未安装，也可能是安装损坏；报告不输出底层异常正文。修复后用同一原始输入、相同账号 scope 和独立诊断输出目录复测；不清空 keystore，不重试已关闭的 full 策略。依赖修复成功本身不证明消息已解密。

诊断顺序为：依赖 → 客户端/企业身份 → SafeChat → 信封验证 → 密钥读取及解包 → 正文解密及校验。

| 字段或结果 | 能说明什么 |
| --- | --- |
| `safechat_calls` | 尝试调用次数，不是成功次数 |
| `safechat_intermediate_failed` | 外层调用返回失败，尚未成功取得信封 |
| `key_provider.requests > 0` | 本批至少进入过一次密钥读取请求；多条批次不能归到每一条消息 |
| `cached_key_count=0` | 当前 provider 没有成功缓存密钥，不能据此推断客户端缺密钥 |
| `local_failure_stage=enterprise_identity` | 企业身份解析过程中失败 |
| `local_failure_stage=safechat_input` / `safechat_call` | 输入准备或外层调用/响应解析过程中失败 |
| `local_failure_stage=envelope_validation` | 外层返回的内容没有通过信封校验 |
| `local_failure_stage=key_lookup_or_unwrap` | 密钥读取、稳定性检查或解包阶段失败，尚不能单独认定缺密钥 |
| `local_failure_stage=body_decryption_or_validation` | 正文解密或文本校验阶段失败 |

阶段字段位于 `unresolved.jsonl` 及 `resolved.jsonl` 的解析结果，不包含密钥、异常原文或额外正文。旧 `local_identity_key_or_payload_validation_failed` 保留兼容，同时增加阶段字段。服务端 `reason` 与本地 `local_reason` 分开解读；`server_disabled_by_argument` 不代表本地失败原因。

部署版本核验：执行 `python <skill>/scripts/deployment_info.py`。安装/同步生成的 `deployment.json` 包含 `source_commit`、`source_dirty` 和文件 SHA-256；脚本检查当前文件是否与记录一致。没有记录时返回 `provenance_unavailable`；源码没有 Git 时提交号和修改状态为 null，不能宣称最新。`source_dirty=true` 表示提交号不足以标识全部部署内容。该记录只用于本地追溯，不是签名，也不会自动查询远端版本。

## 目前的验证结论（2026-10-18）

已在研究版本验证目标群两段历史，共 30 条未标记撤回的已加载正文；其中 11 条可与原 API 密文强绑定。
打包后的脚本能独立完成客户端扫描，但最新现场驻留对象中目标群命中为 0，不能据此声称打包版本已端到端恢复这些 30 条。
273 条 API 快照离线回放可保留全部原字段；126 条原始明文、133 条密文、14 条空正文。引用另外统计。
早期“全部解密/100%”结果曾混入 `1_1_<hex>` 中间信封，撤回该成功率结论。
现已完成独立算法及真实样本验证：11条不同原始密文全部解出与已保存客户端正文逐字节一致的内容；其中1条用户核对过。生产入口对该确认样本也成功。160项离线回归测试通过。本地后端不依赖目标消息当前驻留；仍依赖已登录客户端、匹配key和身份。任意客户端版本、会话企业变更后的历史归属、缺失历史key及无正文缓存的冷启动离线能力未验证。

生产整批验证：273条输入，133条密文正文全部本地解密，29条密文引用解决，可读正文259条；14条空正文及1条空引用保持未解决。0次full、133次SafeChat、1次会话身份查询，没有触发对象扫描。11条独立样本对账全部一致，其余结果通过严格密码格式和文本校验，不表述为逐条人工核验。

单聊生产验证：2026-10-16至18日快照28条，两个会话中16条密文正文及4条密文引用恢复，加11条原始明文共27条可读正文；1条空内容保留。0次full、16次SafeChat、2次官方会话元数据查询和1次原生身份扫描，没有自动滚屏或正文扫描。这批结果通过严格密码格式和文本校验，尚未逐条人工核验。

历史单聊扩大验证：三个会话1456条快照，1174条密文正文与77条密文引用全部恢复，共1419条可读正文。37条空正文、2条空引用保留，逐项核验39个未解决字段均为原始空串，剩余密文为0。记录日期最早2024-10-08、最晚2026-10-06，不代表窗口完整。full调用0、SafeChat调用1174、会话元数据3次、原生身份扫描1次，未触发正文观察补充。

该历史批次随后用部署版纯离线重放：1419条正文、77条本地引用及1251个本地结果身份依据全部一致；39个未解决字段不变，退出2，源文件哈希不变。禁用外部进程执行，未重新解密或读取客户端。

缓存升级离线验证：复制原批次身份清单、缓存与解析结果到新私有目录，在禁止外部进程调用的条件下运行 `--server off --client off`。成功迁移133条本地缓存；259条可读正文按顺序、CID、MID及完整正文逐条相同，133条正文和29条引用均保留本地来源、企业、版本和身份依据。原批次文件哈希未变，15个原有未解决字段保持不变。此验证证明已保存结果可重放，不表示离线获得了新消息或可绕过缺失key。

后续静态分析确认了客户端内置历史查询服务及解密管理器，但历史查询服务当前未监听，另一个已监听的 MCP 入口未证明具有该能力；不能自动替换生产读取路径。维护者需要继续此项研究时读 [client-paths.md](client-paths.md)，普通批处理无需加载这些逆向细节。
