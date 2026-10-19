# Dify 任务观测与容量治理

本目录发布实际部署代码，尚不是一键安装器。Dify 执行 API 适配器曾在 1.17.0 验证，升级 Dify 后需核对 API。公开演示站为站方授权展示；生产部署必须自行定义数据公开范围。

## 代码与部署位置

- `collector/activity_policy.py` 与两个采集脚本一起安装至 `/opt/agentreins/`。
- `console/history_store.py`、`tool_chains.py`、`generic_console.py` 同目录部署；替换前备份并停止对应服务。
- `integrations/dify/` 为执行 API、实时状态、平台指标、同步、搜索助手、REA 适配器。脚本通过绝对路径引用 `/opt/agentreins` 内的同伴模块。
- `console/dify/` 对应公网服务器 `/opt/agentreins-dify`，数据目录 `/var/lib/agentreins-dify`；启动方式见 `server.py` 末尾。
- REA 示例使用 `/home/smith/agentreins-rea`、固定 Node 版本路径和已有容器镜像。迁移部署时修改路径、网桥绑定与 OpenAPI URL。REA 自身代码与 Node 安装包不在本次提交中。

认证会话、sync.token、搜索助手配置由管理员在部署环境创建，不进 Git。源码只读取文件中的凭证。适配器会调用第三方模型服务；须明确授权发送内容与费用。

## 采集策略

保留执行、网络、隔离边界和异常证据。正常健康探测及空闲无 PID 的背景文件事件按签名每 60 秒保留首次并计数；Dify 源端还聚合已识别的内部后台连接。容器非探测执行触发 120 秒详细窗口；Dify API 报错或过期时保守保持详细模式。状态文件 `activity-policy-<pid>.json` 在收到事件时周期更新，不是独立心跳。

这不是完整的逐任务内核采集开关：未知流量、原始 audit 和关键执行事件仍保留。归属不能确定时不宣称已关联。移除完整事件 stdout，避免重复写 journald；audit 规范化事件只写 host.jsonl。

## 存储上限

历史索引最近 72 小时、最多 100000 条（先达到者先清理），每批/每轮裁剪。1 GiB 为逻辑使用量软阈值，超限清退最旧 10000 条；SQLite 页上限在 4096 字节页时为 2 GiB。WAL、JSONL、案例归档不计入该 SQLite 页上限，必须另外轮转和监控磁盘。删除索引不代表删除独立归档报告。重建数据库会失去未单独归档的旧采集检索历史。

JSONL 建议每 5–60 分钟检查 maxsize 100M，compress，rotate 7；配置备份放在 `/etc/logrotate.d` 以外，避免重复加载。copytruncate 有轮转竞态，不能承诺零丢失。

## 前端与反向代理

任务明细使用 allSettled，部分失败显示缺失提示；同步状态与历史列表独立加载；异步请求序号防止过时结果覆盖；移动端纵向排列；点击执行器打开命令、网络、内核及文件详情。

Dify 代理建议关闭磁盘请求/响应缓冲并启用 JSON gzip，避免磁盘满导致大响应被截断。将 social.png 与 favicon.svg 配为静态资源；若使用内联脚本 SHA256 CSP，每次前端变更必须重新生成哈希。线上 nginx 配置及证书不含在此源码包中。

## 验证与限制

已验证真实 REA 任务 10 条命令、77 条内核事件、report.md 正文、搜索和 390px 视口。REA 分析容器禁网，网络零值仅针对该执行容器。系统调用成功不代表业务任务成功；不提供模型未公开的内部思维链。

运行 `python3 tests/test_history_retention.py` 验证期限、数量和容量配置。发布包不包含实际运行日志、业务数据库、Cookie、Token、SSH 信息或报告正文。
