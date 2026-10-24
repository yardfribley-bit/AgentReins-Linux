# AgentReins 观测台

独立的只读展示。采集和检测仍在 `runtime/`，这个目录只读 `/runtime/api/v2/*` 和事先脱敏的回放文件。没有阻断、放行、加白或回滚。

P0 页面：总览、调用链、告警中心、演练计分板，外加一页精简的采集与覆盖。匿名看汇总；调用链明细只对操作员、裁判，或回放数据集开放。凭证只留在页面内存里，刷新即清除。

## 本地构建

```bash
cd web
npm ci
npm run build
```

产物在 `web/dist/`。开发时：

```bash
# 终端 1：runtime，监听 127.0.0.1:18920
PYTHONPATH=. python3 runtime/server.py

# 终端 2
cd web && npm run dev
```

打开 `http://127.0.0.1:5173/observe/`。Vite 把 `/runtime` 反代到 18920。不启动 runtime 时，顶栏切到「回放」仍能看脱敏样例。

## 静态文件怎么挂

构建结果按版本放到：

```text
/opt/agentreins-web/releases/<commit>/
/opt/agentreins-web/current -> releases/<commit>
```

`<commit>` 用 `git rev-parse HEAD`。不要把 `dist/` 提交进仓库。

```bash
commit=$(git rev-parse HEAD)
sudo mkdir -p /opt/agentreins-web/releases/$commit
sudo rsync -a --delete web/dist/ /opt/agentreins-web/releases/$commit/
sudo ln -sfn /opt/agentreins-web/releases/$commit /opt/agentreins-web/current
```

runtime 进程仍部署在 `/opt/agentreins-runtime`（`server.py`、`engine.py`、`observe_api.py`、`replay_dataset.json` 以及原有文件）。观测台静态文件和 runtime 分开，页面挂了不影响采集。

nginx 放在现有 HTTPS server 里，和 `deploy/nginx-runtime.conf.example` 一起用。`location = /runtime/api/v2/stream` 必须写在 `location ^~ /runtime/` 旁边，并且更具体，否则 30 秒读超时和默认缓冲会把 SSE 掐断。

```nginx
location = /observe { return 301 /observe/; }
location ^~ /observe/ {
    alias /opt/agentreins-web/current/;
    index index.html;
    try_files $uri $uri/ /observe/index.html;
}

location = /runtime/api/v2/stream {
    proxy_pass http://127.0.0.1:18920;
    proxy_http_version 1.1;
    proxy_buffering off;
    proxy_cache off;
    proxy_set_header Connection "";
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 1h;
    gzip off;
    add_header X-Accel-Buffering no;
}
```

完整片段见 `deploy/nginx-observe.conf.example`。这个 PR 不负责把文件拷到机器上，也不改正在跑的 nginx。

## 接口

只增加读接口，原来的 `/runtime/api/heartbeat`、`/ingest`、`/alerts` 不变。

| 方法 | 路径 | 匿名 |
|---|---|---|
| GET | `/runtime/api/v2/overview` | 汇总 |
| GET | `/runtime/api/v2/chains` 和 `/chains/{chainId}` | 只回放 `ch-*` 样例 |
| GET | `/runtime/api/v2/agents` 和 `/agents/{id}` | 别名和状态 |
| GET | `/runtime/api/v2/alerts` | 规则、级别、阶段、层 |
| GET | `/runtime/api/v2/coverage` | 汇总 |
| GET | `/runtime/api/v2/drill` | 默认关闭，`drill.yaml` 的 `public: true` 只公开数字 |
| GET | `/runtime/api/v2/stream` | SSE，只推脱敏字段 |

`/runtime/api/rules` 在原字段上增加 `asi`、`enabled`、`enabledReason`。裁判身份（`referees`）可以读证据，不能 POST 处置。演练时间窗写在 `config/drill.yaml`，复制到 `/etc/agentreins-runtime/drill.yaml` 或在 runtime `config.json` 里设 `drillFile`。平台不提供开始/结束按钮。
