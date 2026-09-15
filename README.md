# AgentReins Linux

AgentReins 旗下的 Linux 主机运行时安全产品，基于 KubeArmor 进行产品化。

## 目录结构

- `src/`：AgentReins Linux 自研代码与上游适配层
- `deploy/`：服务器部署、升级和卸载配置
- `config/`：产品配置与安全策略模板
- `docs/`：架构、开发和运维文档
- `branding/`：名称、图标和界面品牌资源
- `scripts/`：构建、打包、安装和维护脚本
- `tests/`：自动化测试

## 当前状态

项目目录已初始化。下一步建议先备份腾讯云主机上的现有 KubeArmor 部署清单和配置，再导入需要维护的上游源码。

## 上游项目

本产品计划基于 KubeArmor 开发。引入上游代码时，应保留原项目的许可证、版权声明和第三方依赖声明。
