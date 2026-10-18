# 客户端批量路径的核验状态

2026-10-18，Windows 9.0.2.261015001；仅适用于 SHA-256
`23bf21eec6a50c69388089e7ddeb22b573439c36f4c9be4c396d719a3f375d77` 的 MainFrame.dll。
此文供维护者定位实现证据和剩余能力；产品脚本已集成纯Python本地密码运算与定向只读key提供器，没有集成以下内置 MCP 或内部C++函数调用。

## 两套不同的本机 MCP

| 路径 | 已核验内容 | 当前限制 |
|---|---|---|
| `dingtalk::mcp` / `nest::McpServer` | `query_messages(cid,count,cursor)`，count 默认20、上限100，cursor为毫秒时间字符串；通过消息服务调用历史读取 | 固定127.0.0.1:8090，登录成功路径受 `general/enable_mcp_server` 灰度开关控制；本轮未监听；未发现普通设置入口 |
| `biz::mcp::MCPHandler` / HTTP `/mcp` | 端口/PID写在 `%APPDATA%/DingTalk/mcp_port`；本轮为8440；确认注册3项会议工具及动态会议工具入口 | 无Authorization的initialize被拒绝；未证明其registry包含query_messages；动态工具清单未穷尽 |

不能将8090的工具名直接套给8440。没有修改灰度值、伪造身份或启动服务器。没有读取认证令牌尝试未证明的聊天能力。

`query_messages` 的静态历史调用链：RVA `0x62114C0 → 0x6210AE0 → IDTMessageService::ListMessage → 0x396D120 GetHistoryMessage`。回调从 mj 文本模型+0x38取正文；工具自身不解密，服务是否提供目标明文尚未运行验证。
下一页游标取最后消息时间，空列表返回 `"0"`；若未来验证可用，必须避免把空列表的0重新当成取最新消息请求。内部CID与API外部CID不是同一标识，仍须严格绑定。

## 内部解密管理器

已确定单例槽RVA `0x9D70CD8` 与getter `0x59AAF40`。核心入口 `0x59A04D0` 依赖初始化状态、企业/身份字符串、两层处理顺序、输出和错误对象，并非裸char指针函数。
`0x59A2200` 按企业与密文版本查缓存；缺版本走客户端 `getKeyByCorpId` 请求。缓存命中有本地继续处理分支，但不证明整条链离线。低层 `0x59A5530` 首参是解包后key字符串，返回整数错误码0成功，不能把其签名与完整入口混用。

本轮只读运行核验：管理器存在且已初始化，缓存目录6项；只读取91字节元数据，双读一致，未读密钥值或调用目标函数。数量不能证明目标企业/历史版本可用，也不构成任何解密成功。

后续目录核验读取1675字节，6个企业条目各有一个version=1记录，hasKeys/hasVersion/hasKey均为真。只读企业标识、版本及存在标志，未读包装key字段。按旧模型地址补读消息oid失败（模型已重用），已拒绝使用旧地址；已保存的、与完整原始密文关联的消息JSON中可恢复目标消息oid，需再按客户端组织映射确认corpId，不能取当前登录主企业替代。

随后完成目标消息oid→corp→version定向匹配：只读正确缓存项，在脚本内存中解包，真实密文解密成功；11条不同消息均与独立保存正文逐字节一致。官方conversation-info取得的目标群corpId也与此映射一致。单条验证读取1341字节，不写密钥、不调用目标函数；证据保存在研究目录private内，不随技能部署。

现在的未证部分是其他客户端版本、缺失历史key和会话企业变更时的历史语义；单聊缺oid的当前原生会话候选路径已单独验证。不要因找到RVA就主动试调，也不能用当前不监听推导客户端“不可能解密”。

## 纯Python编解码器与生产后端

`scripts/ding_codec.py` 已实现两个纯函数，由`native_decryptor.py`接入生产批量入口：

- `decrypt_envelope(text, key, expected_version=...)`：文本格式为`type_version_hex(IV||ciphertext)`；type 1/2分别要求16/32字节key，IV为解码后前16字节，执行AES-CBC。显式核对版本；返回bytes，不猜测文本编码。
- `unwrap_cached_key(wrapped, material, crypto_type=...)`：显式传入36字节包装材料；MD5的小写hexdigest前16个ASCII字符同时作包装AES-128的key与IV。两次Base64之间执行CBC解包，最后核对正文key长度。包装始终AES-128，不随正文type变成AES-256。

依赖PyCryptodome（`Crypto.Cipher.AES`），仅调用密码运算时导入。codec自身没有进程访问、网络请求、持久化或DLL加载。`client_runtime/ding_key_provider.py`验证文件SHA、现场代码与进程身份，精确查目标企业/版本并双读；其它企业key不被读取。调用方有oid时按它映射，缺oid的群可用严格匹配CID的官方corpId，保留来源、查询时点与历史稳定性未知的标记。

采用严格Base64、分组长度及PKCS#7校验，比原生只按末字节截断更严格。CBC不提供真实性验证，填充通过不等于正确明文；仍须与独立可信正文逐字节比对。

验证：112项完整回归通过，其中包含11项codec测试与22项key提供器测试。旧23917个中间信封全部符合解析格式，均为type1/version1；这仍不是23917条解密成功。真实生产快照273条中：126原始明文、133本地解密正文、29加密引用解密，共259可读正文；14空正文与1空引用保留未解决。独立保存的11条正文在生产输出中全部一致。只查询一次目标群企业，SafeChat调用133次，服务端full调用0，客户端正文扫描无需进行。

原始静态证据为`native-crypto-format-20261018/简报.md`、`native-cache-layout-20261018/简报.md`与`native-conversation-fallback-20261018/简报.md`；本文记录的DLL哈希限定同样适用。API会话corpId不能视为已证明与原生orgId回退在全部历史场景等价；不是逐条人工核验了133条。

原始证据保存在维护者本机研究工作区的
`native-history-audit-20261018/`、`native-mcp-transport-20261018/`、
`native-mcp-v2-registry-20261018/`、`native-crypto-context-20261018/`、`native-crypto-format-20261018/`。
这些路径是研究证据索引，不是技能运行依赖。

## 单聊原生会话身份回退

`client_runtime/conversation_identity.py` 定向匹配本批外部CID。已验证mj::object::Conversation vtable RVA `0x6DF44C8`，内部CID字符串在对象+0x70，extension树在+0x150，优先组织数值在+0x3B0。同一对象extension.openConversationId必须精确匹配；全部候选双读稳定并且内部CID/组织一致，才发布结果。根据已审计的`0x3524F90`分别计算开关开启和关闭两条路径，要求返回同一正组织ID；不猜开关、不逐企业试解。

该证据来源明确为`native_conversation_candidate_consensus`，不等同于已经选中当前原生服务缓存对象，也不能代替每条历史消息自己的oid。生产近期单聊验证16条密文正文及4条引用恢复，仍未逐条人工核验。原始静态证据见研究目录`native-conversation-identity-20261018/简报.md`；运行证据见`private/direct-local-production-20261018/summary.json`。
