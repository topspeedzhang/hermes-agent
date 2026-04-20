---
name: hermes-launchd-services
description: Hermes 相关服务的 launchd 配置与开机自启管理
---

# Hermes Launchd Services

## 已注册的 Services

### ai.hermes.gateway
- Gateway 主服务（端口等）
- plist: `~/Library/LaunchAgents/ai.hermes.gateway.plist`

### ai.hermes.skills
- Skills Hub 静态服务器（已被 skills_server.py 替代）
- plist: `~/Library/LaunchAgents/ai.hermes.skills.plist`

### ai.hermes.combo
- **组合服务**：同时启动 Open WebUI (8080) + Skills Hub (8787)
- plist: `~/Library/LaunchAgents/ai.hermes.combo.plist`
- 启动脚本: `/Users/zhangxicen/start-hermes-services.sh`

### ai.hermes.timeout-killer
- **超时进程守护进程**：监控并 kill 超时的后台进程
- plist: `~/Library/LaunchAgents/ai.hermes.timeout-killer.plist`
- 脚本: `~/.hermes/scripts/timeout-killer.py`
- **两种监控模式**：
  1. 扫描 `/tmp/auto_retry_*.json`（前台命令超时 JSON）→ kill 对应 PID
  2. 读取 `~/.hermes/processes.json`（Hermes checkpoint）→ kill 超时的后台进程
- **进程组 kill**：使用 `os.kill(-pgid, SIGTERM)` 确保子进程也被清理
- **阈值配置**：
  - open-webui: 300s
  - ollama: 60s
  - docker: 600s
  - 默认: 3600s
- **已知限制**：`background=True` 启动的进程通过 hermes snap shell 的 `nohup` 实现，不在 process_registry checkpoint 跟踪范围内（PID 1 的 bash -c 进程），因此模式2对这些进程无效。但模式1（auto_retry JSON）仍可用于清理由 auto_timeout_hook 写入的前台超时记录。

## 常用命令

```bash
# 加载所有 Hermes launchd 服务
launchctl load ~/Library/LaunchAgents/ai.hermes.combo.plist
launchctl load ~/Library/LaunchAgents/ai.hermes.gateway.plist

# 卸载
launchctl unload ~/Library/LaunchAgents/ai.hermes.combo.plist

# 查看状态
lsof -i :8080  # Open WebUI
lsof -i :8787  # Skills Hub
lsof -i :8642  # Hermes Gateway

# 手动重启单个服务
# Open WebUI
kill $(lsof -ti :8080); cd /Library/Frameworks/Python.framework/Versions/3.11/bin && ./open-webui serve &

# Skills Hub
kill $(cat /tmp/skills_server_8787.pid); cd /Users/zhangxicen/.hermes/hermes-agent/web && python3 skills_server.py --daemon

# 查看日志
cat /tmp/hermes-combo.log
cat /tmp/hermes-combo.err
```

## 添加新的组合服务

1. 写启动脚本（如 `/Users/zhangxicen/start-xxx-services.sh`）
2. 创建 plist 指向该脚本
3. `launchctl load` 注册

```bash
launchctl load /Users/zhangxicen/Library/LaunchAgents/ai.hermes.combo.plist
```
