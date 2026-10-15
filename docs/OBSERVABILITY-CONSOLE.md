# 模型、工具与执行证据的观测平台

线上入口：[驾驶舱](https://www.agentreins.info/pentagi) / [控制台](https://www.agentreins.info/console)。企业联系：[smithjat@agentreins.info](mailto:smithjat@agentreins.info)。

## 架构与能力

宿主的 netlink / Docker / inotify / netfilter 采集器，加上 Linux audit 桥，写入 AgentReins JSONL。模型网关另外记录 OpenAI 兼容请求、响应、工具调用和后续工具结果。控制台在服务端增量建立 SQLite 历史索引，列表返回摘要，详情按需加载。无需读取 Agent 业务数据库。

驾驶舱中的模型反馈包括普通文本和结构化工具调用。仅展示模型实际返回的解释字段，不重建未返回的内部思考。模型与命令的候选关联采用命令文本和有限时间窗口；容忍秒级执行时间与毫秒级模型事件的精度差异，不能视作唯一任务归属。时间线单独保留同 PID、容器、时间范围内的退出事件，防止被大量网络事件挤出列表。

## Ubuntu / Docker 安装

需要 Python 3.10+、systemd、Docker，以及主机管理员权限。audit 规则适用于支持列出系统调用的 x86 Linux；先核对内核与架构，再按本机需要调整。采集器使用 Python 标准库。

```bash
sudo apt-get update
sudo apt-get install -y python3 auditd nginx
sudo install -d -m 700 /opt/agentreins /var/log/agentreins /etc/agentreins
sudo cp collector/agentreins_host_stream.py collector/audit_bridge.py collector/semantic_gateway.py /opt/agentreins/
sudo cp console/*.py console/pentagi_cockpit.html /opt/agentreins/
sudo cp deploy/agentreins-host-stream.service deploy/agentreins-audit-bridge.service deploy/agentreins-live.service deploy/agentreins-semantic-gateway.service /etc/systemd/system/
sudo cp deploy/console.env.example /etc/agentreins/console.env
sudo cp deploy/gateway.env.example /etc/agentreins/gateway.env
sudo cp deploy/60-agentreins.rules /etc/audit/rules.d/
sudo cp deploy/agentreins-logrotate /etc/logrotate.d/agentreins
```

启动前编辑：

1. `agentreins-host-stream.service` 中的 `--agent`、`--watch`，按实际 Agent 名称和存在的数据目录设置；授权网络分类可通过 `--targets` 传入。
2. `/etc/agentreins/console.env` 的容器名称 glob 或容器 ID，接入其他智能体时加入对应模式。可选 `AGENTREINS_REPORT_ROOT` 是映射到容器 `/work` 的宿主目录；只读取该目录内的 Nmap XML 报告，不覆盖所有容器的数据卷。
3. `/etc/agentreins/gateway.env` 的上游地址与监听地址。Docker 客户端需使用能访问的宿主桥地址，不能使用容器自身的 `127.0.0.1`。将 Agent 的 OpenAI 兼容 base URL 设置为 `http://宿主桥地址:18900/v1`；继续使用 Agent 自己配置的认证信息，网关不保存认证头。
4. 如需要文件审计，在规则末尾添加本机实际存在的数据目录；不需要的系统调用规则应删除。不要覆盖其他审计规则。

```bash
sudo augenrules --load
sudo systemctl daemon-reload
sudo systemctl enable --now agentreins-host-stream agentreins-audit-bridge agentreins-live agentreins-semantic-gateway
curl http://127.0.0.1:8899/api/cockpit
```

外网访问的 netfilter LOG 配置沿用主 README。仅使用 netfilter 的限速日志不能宣称完整流量覆盖；audit 的网络事件也受内核、规则和队列丢失情况影响。

## HTTPS 与公网入口

`deploy/nginx-console.conf.example` 是 HTTPS server 块内的反向代理配置片段。配置自己的域名、证书和自动续期后使用，HTTP 可跳转 HTTPS。线上 `www.agentreins.info` 通过此方式提供服务，默认进入 `/pentagi`。

控制台没有内置登录功能，默认仅监听回环地址。是否开放到公网由部署者的 Nginx 与网络访问规则决定；其中可能展示任务上下文、命令和工具输出，脱敏不是访问控制。模型网关只应提供给要观测的 Agent 客户端。

## API 与筛选

| 路径 | 用途 |
|---|---|
| `/pentagi` | 五阶段任务驾驶舱 |
| `/console` | 通用观测控制台 |
| `/api/cockpit?q=nmap` | 后端过滤行动摘要 |
| `/api/cockpit?id=PID%7C时间` | 进程行动详情及模型候选关联 |
| `/api/history?q=nmap&category=sandbox_activity` | 搜索沙箱内命令；支持 container/from/to/limit/offset |
| `/api/process?pid=PID&container=ID&time=时间` | 指定进程时间线，范围最多 30 分钟 |
| `/api/journeys` | 模型交互摘要 |
| `/api/journeys?id=请求ID` | 模型请求、反馈、工具与候选执行证据 |

历史证据保留受 JSONL 轮转配置和 SQLite 生命周期影响。轮转不自动删除已索引事件；当前不提供数据库自动过期策略，需要部署者规划存储。

## 实时语义与故障排查

- 页面使用 5 秒轮询，不是逐 token 推送。非流式响应完整返回后才能展示。
- 模型请求失败应展示错误；没有退出事件、模型关联或结果时，保留缺失状态，不能伪造补齐。
- 可选 TCP 中转必须将连接超时与已连接 socket 的读取超时分开。曾有中转因 `create_connection(...,15)` 保留 15 秒读取超时，提前切断正常模型请求；参考 `collector/tls_relay.py`。不需要跨网络中转的部署无需运行它。
- 用 `journalctl -u agentreins-semantic-gateway`、Agent 自身日志以及 JSONL 中 MODEL_ERROR / MODEL_INTERRUPTED 的 phase、elapsed、type 判断故障位置。不要把上游连接错误一律解释为用户断开。

## 验证

```bash
python3 -m unittest discover -s tests -p 'test_console_observation.py' -v
python3 -m compileall -q collector console
```

真实部署验证还应包括：一次正常 Agent 模型调用、一条容器命令、相应退出事件，以及页面上的反馈、命令和结果。仓库不附运行时日志、认证材料或特定用户的任务记录。
