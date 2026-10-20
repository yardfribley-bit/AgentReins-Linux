# Runtime 首版：告警、证据与执行前审批

公开入口 `/runtime`，沿用 T000014 Grok 三页原型：告警台、告警详情、规则与情报。Dify 工作台 `/dify` 保留。

## 范围与边界

- S01：有工作负载归属的敏感路径读取权限访问；不采集凭据正文，打开不等于已读取内容。
- S04：同一工作负载/任务中下载输出路径与后续成功执行匹配，标记 candidate。下载命令的输出参数不当作执行；普通 shell 启动不触发。
- S05：仅对配置了非空 allowedNetworks 的工作负载检查 IP/CIDR/可选端口。未配置不启用；不将连接尝试写成数据外传。
- S02/S03：规则实现支持带任务身份的工具/模型事件；当前主机适配器尚未贯通模型/工具身份，因此不能宣称全 Dify 已覆盖。S03 名称为“可疑模型到命令执行链”，不直接断言提示注入。
- P01：独立的执行前审批策略，覆盖 REA analyze 和固定命令实验入口。不冒充 S04 危险行为已发生。没有审批或服务不可用则不执行。
- 未接入工具不受审批保护；不提供主机层杀进程/断网。WebLens 仅支持人工导入可追溯候选，不自动查 FOFA、不自动启用策略。

## 身份与数据

来源凭证、操作凭证独立，公开 API 只读。审批角色由服务器决定，不能在请求中伪造操作人。网页凭证仅保存在内存，刷新即清除。来源凭证属于可信采集器边界；不防御被完全控制的 root 主机伪造证据。

容器归属使用明确登记的容器名模式与容器 ID；主机父进程匹配包含启动时刻和 boot ID。短命进程可能无法获得 startTicks，此字段保持 null；父进程身份可以确认时展示依据，不能获取则不纳入保护对象。PID/cgroup 关联存在系统竞态，不承诺零漏采。

独立每 10 秒心跳，35 秒过期；记录断连区间、audit lost、消费端过期/队列丢弃。文件覆盖仅限实际审计 watch，模型显示网关存在但未贯通身份。心跳在线不等于全部事件都采到。

事件保留 72 小时/20000 条；告警快照与审阅 30 天/最多约 2000 条非 pending 告警。单来源待审批总队列有界；SQLite 页硬限制 256MiB，不包含 WAL。应另配磁盘监控与 WAL checkpoint。待审批不自动丢弃；错误时不发许可。原始 host.jsonl 沿用既有轮转。

## 审批状态

pending → approved → executing → succeeded/failed；或 pending → denied/cancelled/expired。
许可绑定工具、参数、任务和工作负载哈希；同 requestKey 改参数返回 409；领取只有一次。进程在执行中失联超过 180 秒标 interrupted，不自动重放。拒绝/取消不能撤销已经发生的动作。执行结果同步失败保持未知，不伪装成功。

人工处置携带 revision，旧版本返回 409。审阅保存操作身份、理由、证据哈希、快照版本和结果。加白仅 S01/S05 的来源/工作负载/具体路径或目的 IP/端口，期限一小时，不绕过 P01。

## 部署

- 云端 `/opt/agentreins-runtime`：server.py、engine.py、index.html、style.css、app.js；服务独立低权限用户，loopback 18920。
- `/etc/agentreins-runtime/config.json`：database、operatorToken、operatorName、sources `{sourceId:token}`，权限 640，服务组可读；不要提交凭证。
- 源端 sensor.py、gate_client.py、lab.py；`/etc/agentreins-runtime/sensor.json` 权限 600：url、token、containerPatterns、policies；按需设置 proxies。
- `deploy/agentreins-runtime*.service` 和 nginx-runtime.conf.example 提供服务样例。
- audit_bridge.py 新增 agentreins_sensitive 读取 watch 的路径/access 归一化。仅为已存在的敏感路径增加 `auditctl -w PATH -p r -k agentreins_sensitive`，把相同规则保存 rules.d；不要全局审计所有 read。
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
- S03 规范化空白并扩展 wget|sh、下载命令替换、nc -e 模式；主机适配器仍不产生已贯通任务身份的 model/tool 事件，生产 S02/S03 全面接入继续列为后续能力。
- P01 非敏感 env 参数完整可见；清洗后会隐藏/截断的参数拒绝审批，使用预配置凭据引用代替。每来源待审批上限 30。来源凭证不能处置，操作身份从配置的 `operators:{name:token}` 映射取得。旧 operatorToken 仅作升级兼容，建议迁移具名凭证。错误凭证每连接来源 60 秒内超过 15 次返回 429；合法凭证不受错误计数阻塞。
- 匿名详情返回 403；匿名搜索不接受主机/路径关键字查询，避免计数侧信道。脱敏投影只允许规则/级别/状态/次数/时间/匿名 ID。列表和详情查询是 SQLite 只读事务，过期由后台任务及写路径处理。
- WebLens 映射可通过 `intelligenceMappings` 配置并记录依据，未知组件不再一律映射 S02/S05。人工采纳保存资产关联和理由，规则卡片展示建议；不会自动启用阻断或更改实际采集范围。

回归：20 项原有测试 + `test_review_fixes.py` 10 项 + `test_public_api.py` 5 项。Grok SP01 在 Linux 重放 3000 条，唯一送达 3000 条、spoolDropped=0。Grok 用例复测采用新版明细鉴权，并给相对路径样例明确 cwd；原始用例保留。A08 是已声明的生产接入缺口；原脚本 A16 用无条件 False 判失败，用新增可配置映射/人工采纳 HTTP 用例验证替代，不能将原脚本宣称全部通过。
