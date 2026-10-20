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
