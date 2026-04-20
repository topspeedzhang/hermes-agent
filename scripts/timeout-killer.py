#!/usr/bin/env python3
"""
timeout-killer.py — 超时进程守护进程。

两种触发模式：
1. 扫描 /tmp/auto_retry_*.json（前台命令超时 JSON，由 auto_timeout_hook 写入）
2. 扫描 Hermes process_registry 跟踪的长期后台进程，超过阈值则 kill

作为 launchd daemon 持续运行，每 30 秒检查一次。
"""
import os
import sys
import json
import time
import signal
import logging
import threading
from glob import glob
from pathlib import Path

# ── Config ──────────────────────────────────────────────────────────────────

STATE_DIR = Path("/tmp")
AUTO_RETRY_PREFIX = "auto_retry_"
PROCESS_CHECKPOINT = Path.home() / ".hermes" / "processes.json"

# 后台进程最大存活时间（秒），超过则 kill
MAX_BACKGROUND_SECONDS = 3600  # 1小时默认阈值，可按进程名覆盖

# 按进程名覆盖阈值（命令名片段 → 超时秒数）
PROCESS_TIMEOUT_OVERRIDE = {
    "open-webui": 300,       # 5分钟还没启动完视为卡住
    "ollama": 60,             # ollama serve 应该秒开
    "postgres": 300,
    "redis": 60,
    "docker": 600,
}

# 日志
LOG_FILE = Path("/tmp/timeout-killer.log")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stderr),
    ],
)
logger = logging.getLogger("timeout-killer")

# ── 模式1: 扫描 auto_retry JSON（前台命令超时）───────────────────────────────

def scan_auto_retry_json() -> list[dict]:
    """返回所有 pending timeout JSON 条目"""
    results = []
    for fpath in glob(str(STATE_DIR / f"{AUTO_RETRY_PREFIX}*.json")):
        try:
            mtime = os.path.getmtime(fpath)
            age = time.time() - mtime
            if age > 600:          # 忽略 >10min 的旧文件
                continue
            with open(fpath) as f:
                data = json.load(f)
            # 支持 list（旧格式）和 dict（新格式）
            if isinstance(data, list):
                for item in data:
                    if item.get("status") == "timeout" or item.get("elapsed_seconds", 0) > 0:
                        results.append({"file": str(fpath), "data": item, "age": age})
            elif isinstance(data, dict):
                if data.get("elapsed_seconds", 0) > 0:
                    results.append({"file": str(fpath), "data": data, "age": age})
        except Exception:
            pass
    return results


def kill_pid(pid: int, grace_period: float = 3.0) -> bool:
    """Send SIGTERM to process group, wait graceful shutdown, then SIGKILL"""
    try:
        # Kill entire process group (negative PID) to catch all children
        pgid = os.getpgid(pid)
        logger.info(f"Sending SIGTERM to process group {pgid} (PID {pid})")
        try:
            os.kill(-pgid, signal.SIGTERM)
        except ProcessLookupError:
            # Fallback to single PID
            os.kill(pid, signal.SIGTERM)
        # Wait for graceful shutdown
        for _ in range(int(grace_period * 10)):
            time.sleep(0.1)
            try:
                os.kill(pid, 0)      # check if still alive
            except ProcessLookupError:
                logger.info(f"PID {pid} (PGID {pgid}) exited after SIGTERM")
                return True
        # Still alive → SIGKILL
        try:
            os.kill(-pgid, signal.SIGKILL)
            logger.warning(f"PGID {pgid} did not exit after SIGTERM, sent SIGKILL")
        except ProcessLookupError:
            os.kill(pid, signal.SIGKILL)
        return True
    except ProcessLookupError:
        logger.info(f"PID {pid} already exited")
        return False
    except PermissionError:
        logger.error(f"Permission denied to kill PID {pid}")
        return False
    except OSError as e:
        logger.error(f"Failed to kill PID {pid}: {e}")
        return False


def handle_auto_retry_json() -> int:
    """处理前台超时 JSON 文件，返回 kill 数量"""
    killed_count = 0
    for item in scan_auto_retry_json():
        data = item["data"]
        pid = data.get("pid")
        status = data.get("status", "")
        elapsed = data.get("elapsed_seconds", 0)

        # 判断是否需要 kill
        should_kill = False
        if status == "timeout" and pid:
            should_kill = True
            reason = f"status=timeout, elapsed={elapsed}s"

        # 超过预期时间 3 倍视为严重超时
        expected = data.get("expected_seconds", 60)
        if elapsed > expected * 3 and pid:
            should_kill = True
            reason = f"elapsed {elapsed}s > 3x expected {expected}s"

        if not should_kill:
            continue

        if kill_pid(pid):
            killed_count += 1
            # 更新 JSON 状态
            data["status"] = "killed_by_killer"
            data["killed_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
            data["kill_reason"] = reason
            tmp = item["file"] + ".tmp"
            try:
                with open(tmp, "w") as f:
                    json.dump(data, f, ensure_ascii=False)
                os.rename(tmp, item["file"])
            except Exception as e:
                logger.error(f"Failed to update JSON {item['file']}: {e}")

    return killed_count


# ── 模式2: 扫描后台进程（background=True 启动的）────────────────────────────

def scan_tracked_processes() -> list[dict]:
    """从 Hermes checkpoint 读取正在运行的进程，超过阈值则标记"""
    if not PROCESS_CHECKPOINT.is_file():
        return []

    results = []
    now = time.time()
    try:
        with open(PROCESS_CHECKPOINT) as f:
            entries = json.load(f)
    except Exception:
        return []

    for entry in entries:
        if not isinstance(entry, dict):
            continue
        pid = entry.get("pid")
        started_at = entry.get("started_at", 0)
        command = entry.get("command", "")
        elapsed = now - started_at

        # 确定超时阈值
        timeout_seconds = MAX_BACKGROUND_SECONDS
        for pattern, override in PROCESS_TIMEOUT_OVERRIDE.items():
            if pattern in command:
                timeout_seconds = min(timeout_seconds, override)

        if elapsed > timeout_seconds and pid:
            results.append({
                "pid": pid,
                "elapsed": int(elapsed),
                "timeout": timeout_seconds,
                "command": command,
                "data": entry,
            })
    return results


def handle_background_timeouts() -> int:
    """处理后台进程超时，返回 kill 数量"""
    killed_count = 0
    for proc in scan_tracked_processes():
        pid = proc["pid"]
        elapsed = proc["elapsed"]
        timeout = proc["timeout"]
        command = proc["command"][:60]

        logger.warning(f"[TIMEOUT] PID {pid} running {elapsed}s (limit={timeout}s): {command}")

        if kill_pid(pid, grace_period=5.0):
            killed_count += 1
            # 记录到日志
            log_entry = {
                "event": "background_killed",
                "pid": pid,
                "elapsed": elapsed,
                "timeout": timeout,
                "command": command,
                "killed_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            }
            logger.info(f"Background process killed: {log_entry}")

    return killed_count


# ── 主循环（daemon 模式）─────────────────────────────────────────────────────

CHECK_INTERVAL = 30  # 秒


def daemon_loop():
    """持续运行，每 CHECK_INTERVAL 秒检查一次"""
    logger.info(f"[START] timeout-killer daemon PID={os.getpid()}")
    logger.info(f"[CONFIG] MAX_BACKGROUND_SECONDS={MAX_BACKGROUND_SECONDS}")
    logger.info(f"[CONFIG] PROCESS_TIMEOUT_OVERRIDE={PROCESS_TIMEOUT_OVERRIDE}")
    logger.info(f"[CONFIG] CHECK_INTERVAL={CHECK_INTERVAL}s")

    while True:
        try:
            killed1 = handle_auto_retry_json()
            killed2 = handle_background_timeouts()
            total = killed1 + killed2
            if total > 0:
                logger.info(f"[SUMMARY] Cycle complete: killed {total} process(es)")
        except Exception as e:
            logger.exception(f"Error in killer loop: {e}")

        time.sleep(CHECK_INTERVAL)


# ── 单次运行（兼容旧接口）────────────────────────────────────────────────────

def run_once():
    """单次检查 + kill，用于 cronjob 或手动触发"""
    try:
        killed = handle_auto_retry_json()
        killed += handle_background_timeouts()
        if killed > 0:
            print(f"[timeout-killer] killed {killed} process(es)")
        else:
            print("[timeout-killer] no timed-out processes found")
    except Exception as e:
        print(f"[timeout-killer] error: {e}", file=sys.stderr)
        raise


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--daemon":
        daemon_loop()
    else:
        run_once()
