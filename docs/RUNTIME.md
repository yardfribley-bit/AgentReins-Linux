# Runtime 首版：告警、证据与执行前审批

公开入口 `/runtime`，沿用 T000014 Grok 三页原型：告警台、告警详情、规则与情报。Dify 工作台 `/dify` 保留。

## 范围与边界

- S01：有工作负载归属的敏感路径读取权限访问；不采集凭据正文，打开不等于已读取内容。
- S04：同一工作负载/任务中下载输出路径与后续成功执行匹配，标记 candidate。下载命令的输出参数不当作执行；普通 shell 启动不触发。
- S05：仅对配置了非空 allowedNetworks 的工作负载检查 IP/CIDR/可选端口。未配置不启用；不将连接尝试写成数据外传。
- S02/S03：语义网关按路由绑定 agent，传感器把容器名映射到同一 agent。不受信输入（工具结果、检索、文档、上传、网页等来源类别，不解析提示词）之后的高风险工具调用先产生 S03 语义段；同一 agent 上参数实体与主机事件精确一致时，升级同一条告警。S02 只在该连接还落在已配置 allowedNetworks 之外时另开一条。名称仍是“可疑模型到命令执行链”和“工具后的非白名单外联”，不断言提示注入。只有时间邻近、缺少 agent、或 agent 不一致，都不关联。Dify API bridge 只作旁路，不触发这两条规则。同一 Dify 实例里的多个应用仍无法按容器拆开。
- S08：已登记工作负载对敏感或持久化路径的写入。只告警，不阻断、不回滚。证据保留写入前后 SHA-256 和大小（能读到文件时），不保留正文。
- P01：独立的执行前审批策略，覆盖 REA analyze 和固定命令实验入口。不冒充 S04 危险行为已发生。没有审批或服务不可用则不执行。
- 未接入工具不受审批保护；不提供主机层杀进程/断网。WebLens 仅支持人工导入可追溯候选，不自动查 FOFA、不自动启用策略。内核阻断保持关闭。

## 身份与数据

来源凭证、操作凭证独立，公开 API 只读。审批角色由服务器决定，不能在请求中伪造操作人。网页凭证仅保存在内存，刷新即清除。来源凭证属于可信采集器边界；不防御被完全控制的 root 主机伪造证据。

容器归属使用明确登记的容器名模式与容器 ID；主机父进程匹配包含启动时刻和 boot ID。短命进程可能无法获得 startTicks，此字段保持 null；父进程身份可以确认时展示依据，不能获取则不纳入保护对象。PID/cgroup 关联存在系统竞态，不承诺零漏采。

独立每 10 秒心跳，35 秒过期；记录断连区间、audit lost、消费端过期/队列丢弃。文件覆盖仅限实际审计 watch。模型层为 not_connected / gateway_unbound / gateway_bound / linked：路由已加载但 5 分钟内没有语义事件时是 gateway_bound，有语义事件才是 linked。工具层为 rea_only / semantic_linked；若该来源在 5 分钟内有已主机确认的 S02/S03，覆盖视图标为 host_linked。心跳在线不等于全部事件都采到。

事件默认保留 72 小时/20000 条；演练可在 runtime 的 config.json 提高 `maxEvents`（1000–2000000）和 `maxEventsPerSource`（100–2000000）。这两项由 runtime 服务读取，写在 sensor.json 里不会生效。告警快照与审阅 30 天/最多约 2000 条非 pending 告警。单来源待审批总队列有界；SQLite 页硬限制 256MiB，不包含 WAL。应另配磁盘监控与 WAL checkpoint。待审批不自动丢弃；错误时不发许可。原始 host.jsonl 沿用既有轮转。

## 审批状态

pending → approved → executing → succeeded/failed；或 pending → denied/cancelled/expired。
许可绑定工具、参数、任务和工作负载哈希；同 requestKey 改参数返回 409；领取只有一次。进程在执行中失联超过 180 秒标 interrupted，不自动重放。拒绝/取消不能撤销已经发生的动作。执行结果同步失败保持未知，不伪装成功。

人工处置携带 revision，旧版本返回 409。审阅保存操作身份、理由、证据哈希、快照版本和结果。加白仅 S01/S05 的来源/工作负载/具体路径或目的 IP/端口，期限一小时，不绕过 P01。

## 部署

- 云端 `/opt/agentreins-runtime`：server.py、engine.py、index.html、style.css、app.js；服务独立低权限用户，loopback 18920。
- `/etc/agentreins-runtime/config.json`：database、operatorToken、operatorName、sources `{sourceId:token}`，权限 640，服务组可读；不要提交凭证。
- 源端 sensor.py、gate_client.py、lab.py，以及 agents_config.py、semantic_extract.py、chain_detect.py、redact.py。`/etc/agentreins-runtime/sensor.json` 权限 600：url、token、containerPatterns、policies、agentsFile；按需设置 proxies。样例见 `config/sensor.json.example`。
- 语义网关读 `/etc/agentreins/agents.yaml`（`AGENTREINS_AGENTS`）。样例 `config/agents.yaml.example` 使用 RFC 5737 文档地址，部署时换成该主机的网桥网段，不要把真实地址提交回仓库。每个 agent 的模型 base URL 指向自己的网关端口，或指向带 `/a/<agentId>` 前缀的路径。`peerAllowlist` 为空表示放行，演练必须写上 plugin_daemon 或 PentAGI 容器所在网段。
- runtime 留存写在 `/etc/agentreins-runtime/config.json`，样例 `config/runtime.config.json.example`。演练建议 `maxEvents` 200000、`maxEventsPerSource` 80000，并加大 audit backlog。主机之间对时。
- `deploy/agentreins-runtime*.service` 和 nginx-runtime.conf.example 提供服务样例。网关、host-stream、audit-bridge 的单元把 `PYTHONPATH` 和 `AGENTREINS_RUNTIME` 指到 `/opt/agentreins-runtime`。
- audit_bridge.py 归一化 agentreins_sensitive 读取，以及 agentreins_persist 写入。`python3 runtime/watch_scope.py --apply` 只为已经存在的路径安装 watch：读取 `-p r -k agentreins_sensitive`，写入 `-p wa -k agentreins_persist`。静态 `deploy/60-agentreins.rules` 不写入可能不存在的路径。不要全局审计所有 read，也不要打开内核阻断。
- REA 执行器依赖 gate_client.py 和 sensor.json，升级必须同时部署；一旦启用，REA analyze 每次需要审批，可能超过上游工具调用超时，请核对 Dify 配置。

## 验证

`PYTHONPATH=. python3 tests/runtime/test_runtime.py`：20 项，含 HTTP 角色隔离、实参绑定、单次领取、拒绝/过期、重启、候选关联、正常 shell、下载输出误判与乱序反例。

实机验收脚本 `runtime/lab.py` 仅执行固定、无害的本机步骤，读取假 .env、访问 loopback HTTP、下载执行写标记脚本。不是客户业务攻击。示例告警来自实机，但应标为受控实验，不用于声称检出率。正常对照、丢失/过期、拒绝/放行应一并检查。生产误报率/检出率尚未测量。

## 2026-10-20 验收整改（runtime-1.1-review）

- 采集使用 `LogPump`，待发批次最多 100 条，满后停止读日志。只在服务端返回逐条 ACK 后原子更新 cursor；断网不前进，重启从已确认游标重放，事件 ID 去重。服务端逐条拒绝坏事件并返回索引/理由，其余继续入库。日志轮转/过期/解析失败作为覆盖缺口记录，不承诺磁盘文件被外部删除后仍能补采。旧版已经丢失的数据不能补造或恢复。
- 覆盖区分 auditLost、sensorLoss、总 drop 和 degraded，保留未知值。损失计数是累计值，历史累计损失未被清除时持续提示缺口，不将其解释为每秒丢失率。匿名只显示汇总和降级来源数量；实际主机/路径/容器/参数/覆盖明细需操作身份。
- S05 同来源/工作负载/目的/端口 5 分钟聚合，记录 count、firstSeen、lastSeen、有界样本。旧版开放 S05 可用 `runtime/migrate_review.py` 非破坏性整理；旧 ID 保留，可跳转聚合记录。
- `command_parse.py` 支持 curl -o/-oPATH/--output=/-O、wget 默认文件名与输出参数、shell 重定向和相对路径。相对路径必须有真实 cwd；没有 cwd 时保持未知，不假定根目录。netlink 执行事件可参与 candidate 关联，不能据此断言下载成功。
- S01 默认 12 类路径模式，可在服务端 `sensitivePaths` 配置。实际 Linux audit 只覆盖已存在并成功安装的路径；`watch_scope.py` 输出安装类别和缺失类别，缺失不能冒充已覆盖。后续新增凭据文件需重新审阅安装 watch。
- S03 规范化空白并扩展 wget|sh、下载命令替换、nc -e 模式。本节记录的是当时的缺口：主机适配器尚未产生已贯通任务身份的 model/tool 事件。2026-10-21 演练准备改为由语义网关路由绑定接入，见文末。
- P01 非敏感 env 参数完整可见；清洗后会隐藏/截断的参数拒绝审批，使用预配置凭据引用代替。每来源待审批上限 30。来源凭证不能处置，操作身份从配置的 `operators:{name:token}` 映射取得。旧 operatorToken 仅作升级兼容，建议迁移具名凭证。错误凭证每连接来源 60 秒内超过 15 次返回 429；合法凭证不受错误计数阻塞。
- 匿名详情返回 403；匿名搜索不接受主机/路径关键字查询，避免计数侧信道。脱敏投影只允许规则/级别/状态/次数/时间/匿名 ID。列表和详情查询是 SQLite 只读事务，过期由后台任务及写路径处理。
- WebLens 映射可通过 `intelligenceMappings` 配置并记录依据，未知组件不再一律映射 S02/S05。人工采纳保存资产关联和理由，规则卡片展示建议；不会自动启用阻断或更改实际采集范围。

回归：20 项原有测试 + `test_review_fixes.py` 10 项 + `test_public_api.py` 5 项。Grok SP01 在 Linux 重放 3000 条，唯一送达 3000 条、spoolDropped=0。Grok 用例复测采用新版明细鉴权，并给相对路径样例明确 cwd；原始用例保留。A08 是已声明的生产接入缺口；原脚本 A16 用无条件 False 判失败，用新增可配置映射/人工采纳 HTTP 用例验证替代，不能将原脚本宣称全部通过。

## 后续修正：近期覆盖与下载路径（2026-10-21）

降级判定改为最近 15 分钟损失增量与当前背压，窗口可配置 `lossWindowSeconds`（60–3600 秒）。历史累计值保留在 historicalLoss/drop，不因近期恢复而清空。增量存入 SQLite，重启仍可判断窗口；新接入已有损失的来源首次按当前观察到的损失记录，窗口过去且不再增长后恢复。未知 audit 计数仍为未知。

curl/wget 显式输出参数与远端默认文件名优先于 shell stdout 重定向，`curl -o /tmp/a URL > /dev/null` 不会改记为 /dev/null；`-o-` 明确输出 stdout，不当作落地文件。无输出选项的 curl 才使用 stdout 重定向作为路径。

宿主 netlink EXEC 在捕获时尝试补采 `/proc/<pid>/cwd`，读前后核对进程启动时刻，失败保持 null；runtime 继续优先使用 audit 的 cwd。短命进程和并发 chdir 仍有竞态，缺失工作目录时不猜测相对路径。

## 演练准备：S02/S03、S08 与只读导出（2026-10-21）

本节替换上文把生产 S02/S03 列为后续能力的说法。规则 ID 不变。模式仍是 alert，内核阻断保持关闭，不回滚文件。

### 语义到主机

网关按 `agents.yaml` 绑定路由：路径前缀 `/a/<agentId>`，或每个 agent 独占监听端口。语义事件的工作负载是 `gateway:<agentId>`，主机事件的工作负载仍是容器名。关联键是 agentId，不跨来源、不靠容器 ID 单独关联。chainId 取该链第一条 requestId；后续请求若回传 tool_call_id，则并入同一条链。网关进程内的这条对照在重启后清空。响应字节原样转发，不改写模型输出。

不受信只看来源类别：role 为 tool，或 source 属于 tool_result、retrieval、knowledge、document、upload、web、file、url，或内容块类型为 file、input_file、document、image_url。system、developer、assistant，以及没有来源标记的 user，视为受信。未知角色的置信度为 unknown，传感器不入库，因此不触发。

高风险工具包括名称含 terminal、shell、code_interpreter、bash、powershell、code_exec、command、exec 的调用，敏感或持久化路径，以及 curl、wget、已有危险命令模式或较长的 shell 命令。非白名单 URL 只在该工具事件带有非空 allowedNetworks 时计入高风险。

主机匹配要求路径相等、URL 主机名等于目的地址、主机实体（可带端口）一致，或命令规范化后互为足够长的子串。只比较第一个 token 不算关联。主机事件必须落在工具调用之后 120 秒内；向前查找不受信片段的窗口是 3600 秒。这两段时间只是约束。置信度使用 observed、correlated、inferred、unknown；触发边记为 correlated。inferred 不作为触发条件。S03 语义段先告警，主机段把同一条告警的 phase 从 semantic 升为 host_confirmed，并写入 hostConfirmedAt。级别不因此提高。S02 是另一条告警，phase 直接为 host_confirmed。

语义事件入库前截断到 8 KiB。网关不再写完整提示词：MODEL_REQUEST 只保留角色、计数和最多 512 字的摘录；TOOL_CALL 保留清洗后的参数，截断到 4 KiB，控制台仍能按工具参数做候选关联。

### 写入证据与 S08

audit 键 `agentreins_persist` 进入规则引擎，access 记为 write。传感器对普通文件、不跟随符号链接、不超过 1 MiB 的对象计算 SHA-256，并带上进程内缓存的前一次哈希。S08 要求 pid 大于 0，且路径命中敏感路径或持久化路径（环境文件、authorized_keys、shell 启动文件、cron、systemd、ld.so.preload、git hooks、github workflows、passwd、group、sudoers）。S08 不能加白，加白仍只有 S01 和 S05。

`scripts/upperdir_changes.py` 只读列出容器 overlay upperdir。`--docker` 用 `docker inspect` 找 UpperDir；不是 overlay2 时退回 `docker diff`。`--upper` 与 `--lower` 供没有 docker 的核对使用。白名单删除记 `.wh.` 名字和 0:0 字符设备。符号链接不跟随。大于 8 MiB 的文件只记大小。输出始终写明 volume 和 bind mount 不在覆盖范围内，这类变更的置信度是 correlated。演练前后各做一次快照，再用 `--baseline` 与 `--after` 做 diff。

### 只读时间窗导出

```bash
PYTHONPATH=. python3 scripts/export_timeline.py \
  --db /var/lib/agentreins-runtime/runtime.sqlite \
  --since 2026-10-24T00:00:00+00:00 \
  --until 2026-10-24T23:59:59+00:00 \
  --out /tmp/drill-export
```

数据库以 `mode=ro` 和 `query_only` 打开。可重复 `--db` 合并多台主机，可用 `--chain-id`、`--agent-id` 过滤。产物为 events、alerts、reviews、coverage、timeline 的 JSONL，events、alerts、coverage 的 CSV，以及 timeline.md。每条 JSONL 带 `prev` 和 `self`，`self` 是上一条哈希加本条规范 JSON 的 SHA-256。`SHA256SUMS` 覆盖导出目录里的其他文件。导出前会按 runtime 的 `clean` 遮盖命令行中的口令、`--api-key`、`--with-token`、`mysql -p`（不含单独的 `-p`）、`aws_secret_access_key`、`*_API_KEY`、常见令牌前缀和 Bearer。遮盖停在引号之前，避免把 shell 引用吃掉。

host-stream 与 audit 的 argv 现用 `shlex.join` 保留引号，因此 `bash -c 'curl URL > /tmp/a'` 里的重定向仍能被命令解析看到。`bash -lc`、curl `-o-`、`-sSLo`、wget `-qO` 等已知漏记仍然存在，本次不改 S04 规则。

### 延迟

语义段的延迟看告警 `createdAt` 与工具事件 `time` 的差，目标 P50 ≤ 5 秒、P95 ≤ 15 秒。主机确认看 `hostConfirmedAt` 与主机事件时间，端到端目标 P50 ≤ 10 秒、P95 ≤ 30 秒。自动化测试只约束合成事件的关联结果，实机分位数留到演练当天按上述字段统计。

### 部署步骤

1. 把 `runtime/` 下的 server、engine、sensor、agents_config、semantic_extract、chain_detect、redact、command_parse、watch_scope 和页面文件放到 `/opt/agentreins-runtime`。
2. 把 `collector/semantic_gateway.py`、`audit_bridge.py`、`agentreins_host_stream.py` 放到 `/opt/agentreins/`，更新对应 systemd 单元后重启这三项服务。不要改内核策略开关。
3. 复制 `config/agents.yaml.example` 为 `/etc/agentreins/agents.yaml`，把文档网段换成该主机上 plugin_daemon 或 PentAGI 容器的网桥网段，并写上 container pattern。
4. 在 `gateway.env` 设置 `AGENTREINS_AGENTS`、`AGENTREINS_UPSTREAM`、`AGENTREINS_RUNTIME`。把每个 agent 的 OpenAI base URL 指到它的网关端口或 `/a/<id>/v1`。
5. sensor.json 增加 `agentsFile` 和与 agents.yaml 一致的 `containerPatterns`。runtime 的 config.json 提高 `maxEvents` 与 `maxEventsPerSource`。
6. 以 root 预览并安装 watch：`python3 /opt/agentreins-runtime/watch_scope.py --config /etc/agentreins-runtime/sensor.json`，确认类别后再加 `--apply`。
7. 演练前用 `scripts/upperdir_changes.py --docker --name <container> --phase before --out <dir>` 做快照，结束后用 after 与 diff。导出用上面的 export 命令，在观察机上对只读拷贝或本机数据库执行。
8. 本地核对可跑 `PYTHONPATH=. python3 scripts/replay_s02s03.py <目录>`。它只使用占位标记和文档地址，不连接真实模型。

### 验证

`PYTHONPATH=. python3 -m unittest tests.runtime.test_s02s03 tests.runtime.test_runtime tests.runtime.test_review_fixes tests.runtime.test_next_iteration tests.runtime.test_public_api tests.policy.test_compiler tests.test_console_observation tests.test_history_retention`

覆盖 V1–V6、F1–F4、S08 哈希、导出哈希链、upperdir 的 whiteout 删除，以及既有运行时用例。控制台列表会显示 phase、confidence、agentId、chainId；匿名公开投影的字段范围保持不变。
