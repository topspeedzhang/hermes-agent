#!/usr/bin/env python3
"""
auto-timeout-hook.py — 自动超时处理 hook 实现。

注册到 base.py 的 _timeout_hooks。
当终端命令超时时：
  1. 在 /tmp/auto_retry_<hash>.json 写入超时上下文
  2. 在后台线程中分析超时原因并生成优化建议
  3. Hermes Agent 启动时会检查这些文件并自动重试

使用方式（在 Hermes Agent 启动时或配置中加载）：
    import sys
    sys.path.insert(0, '/Users/zhangxicen/.hermes/scripts')
    from auto_timeout_hook import setup_timeout_hook
    setup_timeout_hook()
"""
import json
import os
import time
import threading
import hashlib
from pathlib import Path

# 超时命令的预期正常时长（秒），用于判断"严重超时"还是"轻度超时"
COMMAND_EXPECTED_DURATION = {
    "npm install": 120,
    "pip install": 90,
    "pip3 install": 90,
    "brew install": 180,
    "apt install": 120,
    "apt-get install": 120,
    "yarn install": 120,
    "pnpm install": 90,
    "bun install": 60,
    "cargo build": 300,
    "cargo fetch": 120,
    "go build": 180,
    "go mod download": 120,
    "make": 180,
    "make build": 180,
    "make install": 180,
    "docker build": 300,
    "docker pull": 180,
    "docker run": 120,
    "git clone": 120,
    "git fetch": 60,
    "git pull": 60,
    "curl": 60,
    "wget": 60,
    "rsync": 120,
}


def get_expected_duration(command: str) -> int:
    """根据命令类型返回预期最大时长（秒）"""
    cmd_lower = command.lower().strip()
    for key, duration in COMMAND_EXPECTED_DURATION.items():
        if cmd_lower.startswith(key):
            return duration
    return 60  # 默认为 60 秒


def infer_progress(output: str, command: str) -> dict:
    """从输出中推断命令进度"""
    output_lower = output.lower()

    if "npm install" in command or "yarn" in command or "pnpm" in command:
        # 检测安装进度
        if "added" in output_lower and "packages" in output_lower:
            return {"progress": 1.0, "stage": "completed", "summary": "安装完成"}
        lines = output.split("\n")
        done = sum(1 for l in lines if "✓" in l or "✔" in l or "done" in l.lower())
        total = sum(1 for l in lines if "http" in l or "resolve" in l)
        if done > 0 and total > 0:
            pct = min(done / max(total, 1), 0.99)
            return {"progress": pct, "stage": "installing", "summary": f"检测到 {done}/{total} 个包"}
        if "sandbox" in output_lower or "offline" in output_lower:
            return {"progress": 0.1, "stage": "network_wait", "summary": "等待网络/缓存"}
        return {"progress": 0.3, "stage": "installing", "summary": "正在安装依赖"}

    if "pip install" in command or "pip3 install" in command:
        if "successfully installed" in output_lower or "requirement already satisfied" in output_lower:
            return {"progress": 1.0, "stage": "completed", "summary": "安装完成"}
        if "downloading" in output_lower:
            pct = 0.4
            return {"progress": pct, "stage": "downloading", "summary": "正在下载包"}
        return {"progress": 0.5, "stage": "installing", "summary": "正在安装"}

    if "git clone" in command:
        if "cloning" in output_lower:
            lines = output.split("\n")
            for l in lines:
                if "%" in l:
                    try:
                        pct = int([c for c in l.split() if "%" in c][0].replace("%", "")) / 100
                        return {"progress": pct, "stage": "cloning", "summary": f"克隆进度 {int(pct*100)}%"}
                    except (ValueError, IndexError):
                        pass
            return {"progress": 0.3, "stage": "cloning", "summary": "正在克隆仓库"}
        return {"progress": 0.0, "stage": "starting", "summary": "刚开始"}

    if "make" in command:
        if "error" in output_lower:
            return {"progress": 0.0, "stage": "error", "summary": "编译出错"}
        if "done" in output_lower or "target" in output_lower:
            return {"progress": 0.8, "stage": "linking", "summary": "编译完成"}
        return {"progress": 0.5, "stage": "compiling", "summary": "正在编译"}

    if "docker build" in command:
        lines = output.split("\n")
        steps = [l for l in lines if "step" in l.lower() and "/" in l]
        if steps:
            try:
                parts = steps[-1].split("/")
                current = int(parts[0].split()[-1])
                total = int(parts[1].split()[0])
                pct = current / max(total, 1)
                return {"progress": pct, "stage": "building", "summary": f"Docker Step {current}/{total}"}
            except (ValueError, IndexError):
                pass
        return {"progress": 0.4, "stage": "building", "summary": "正在构建镜像"}

    if "curl" in command or "wget" in command:
        if "100%" in output or "saved" in output_lower:
            return {"progress": 1.0, "stage": "completed", "summary": "下载完成"}
        if "%" in output:
            try:
                pct = int([c for c in output.split() if "%" in c][-1].replace("%", "")) / 100
                return {"progress": pct, "stage": "downloading", "summary": f"下载进度 {int(pct*100)}%"}
            except (ValueError, IndexError):
                pass
        return {"progress": 0.5, "stage": "downloading", "summary": "正在下载"}

    # 默认未知命令
    return {"progress": None, "stage": "unknown", "summary": "进度未知"}


def analyze_timeout(command: str, elapsed: int, output: str, workspace: str) -> dict:
    """分析超时原因，返回诊断和优化建议"""
    progress = infer_progress(output, command)
    expected = get_expected_duration(command)
    severity = "high" if elapsed > expected * 2 else "medium"

    suggestions = []
    cause = "unknown"

    output_lower = output.lower()

    # 网络问题
    if any(k in output_lower for k in ["timeout", "connection refused", "network", "no route", "dns"]):
        cause = "network"
        suggestions.append("网络超时，建议检查网络或使用镜像源")
        if "npm" in command:
            suggestions.append("尝试: npm install --registry=https://registry.npmmirror.com")
        if "pip" in command:
            suggestions.append("尝试: pip install -i https://pypi.tuna.tsinghua.edu.cn/simple")
        if "git clone" in command:
            suggestions.append("尝试浅克隆: git clone --depth 1 <repo>")
        severity = "high"

    # 磁盘问题
    elif any(k in output_lower for k in ["no space", "disk full", "enospc", "permission denied"]):
        cause = "disk"
        suggestions.append("磁盘空间不足或权限问题")
        severity = "high"

    # 编译卡住
    elif any(k in output_lower for k in ["make", "compiling", "building", "link"]) and elapsed > 300:
        cause = "compile_stuck"
        suggestions.append("编译时间过长，可能卡在某个步骤")
        suggestions.append("检查是否有循环依赖或大型源文件")
        severity = "medium"

    # 正常慢速
    elif progress.get("progress") and progress["progress"] > 0:
        cause = "slow_progress"
        suggestions.append(f"命令正在执行（{progress['summary']}），但超过了设定阈值")
        suggestions.append(f"可增加 timeout 或检查是否有网络/CDN 问题")
        severity = "low"

    # 完全没输出
    elif len(output.strip()) == 0:
        cause = "no_output"
        suggestions.append("命令无任何输出，可能卡在等待输入或网络")
        suggestions.append("检查命令是否需要交互或环境配置")
        severity = "medium"

    # 内存不足
    elif any(k in output_lower for k in ["killed", "oom", "memory"]):
        cause = "memory"
        suggestions.append("内存不足，进程被系统 kill")
        suggestions.append("尝试减少并发数或增加 swap")
        severity = "high"

    # 默认
    else:
        cause = "unknown"
        suggestions.append("超时原因不明，建议检查命令本身")
        suggestions.append("可能需要增加 timeout 或检查环境")
        severity = "medium"

    return {
        "command": command,
        "workspace": workspace,
        "elapsed_seconds": elapsed,
        "expected_seconds": expected,
        "severity": severity,
        "cause": cause,
        "progress": progress,
        "suggestions": suggestions,
        "output_preview": output[-500:] if len(output) > 500 else output,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }


def _write_retry_context(info: dict) -> str:
    """将超时上下文写入 JSON 文件，返回文件路径"""
    # 用命令的 md5 做稳定文件名
    cmd_hash = hashlib.md5(info["command"].encode()).hexdigest()[:12]
    fpath = f"/tmp/auto_retry_{cmd_hash}.json"

    # 追加历史（不覆盖），同时追踪重试次数
    existing = []
    retry_count = 0
    if os.path.exists(fpath):
        try:
            with open(fpath) as f:
                existing = json.load(f)
        except Exception:
            existing = []

    if not isinstance(existing, list):
        existing = [existing] if existing else []

    # 计算历史重试次数（只看已标记 _retry_count 的记录）
    for rec in existing:
        if isinstance(rec, dict) and rec.get("command") == info["command"]:
            retry_count = max(retry_count, rec.get("_retry_count", 0))

    # 新记录附加重试次数
    info["_retry_count"] = retry_count + 1
    existing.append(info)

    tmp = fpath + ".tmp"
    with open(tmp, "w") as f:
        json.dump(existing, f, ensure_ascii=False, indent=2)
    os.rename(tmp, fpath)
    return fpath


def _timeout_handler(command: str, elapsed: int, output: str, workspace: str) -> None:
    """实际的 hook 回调 — 在 _wait_for_process 的超时路径中调用"""
    info = analyze_timeout(command, elapsed, output, workspace)
    fpath = _write_retry_context(info)

    # 打印到 stderr（Hermes 日志可见），带上可见标记
    import sys
    print(f"\n[H超时监控] 命令超时已记录 → {fpath}", file=sys.stderr)
    print(f"  [超时] {command[:80]}", file=sys.stderr)
    print(f"  [原因] {info['cause']} | [严重度] {info['severity']}", file=sys.stderr)
    for s in info["suggestions"]:
        print(f"  [建议] {s}", file=sys.stderr)


def setup_timeout_hook() -> None:
    """从 Hermes Agent 注册调用 — 将 _timeout_handler 注册到 base.py"""
    try:
        from tools.environments.base import register_timeout_hook
        register_timeout_hook(_timeout_handler)
        import sys
        print(f"[auto-timeout-hook] 已注册到 base.py 的超时 hook", file=sys.stderr)
    except Exception as exc:
        import sys
        print(f"[auto-timeout-hook] 注册失败: {exc}", file=sys.stderr)


# ---------------------------------------------------------------------------
# CLI 测试入口
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import sys
    if len(sys.argv) < 3:
        print("Usage: python3 auto-timeout-hook.py <command> <elapsed> [output]")
        sys.exit(1)

    cmd = sys.argv[1]
    elapsed = int(sys.argv[2])
    output = sys.argv[3] if len(sys.argv) > 3 else ""

    info = analyze_timeout(cmd, elapsed, output, "/tmp")
    print(json.dumps(info, ensure_ascii=False, indent=2))
