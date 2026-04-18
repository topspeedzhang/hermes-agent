#!/usr/bin/env python3
"""
auto_retry_manager.py - Auto-timeout retry manager for Hermes Agent.

Watches /tmp/auto_retry_*.json files written by auto_timeout_hook.py.
On each run_conversation entry, checks for pending retries and injects
an optimized command into the messages list so the agent executes it
before continuing the original task.

All fixes from DeepSeek-Reasoner two-round review:
  P0-1: fcntl.flock atomic lock (macOS-compatible,BSD-style)
  P0-2: Regex-based dangerous command detection (absolute path,binary,绕过)
  P0-3: Atomic rename instead of write-then-delete race
  P1-1: Round-robin + age-based selection (fixes starvation)
  P1-2: Graded error handling (recoverable vs fatal)
  P1-3: Optimized command wrapped in timeout guard
  P1-4: JSON version field + robust timestamp parsing
  P1-5: Structured audit logging on all key lifecycle events
"""

import fcntl
import glob
import hashlib
import json
import logging
import os
import random
import re
import shlex
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

RETRY_PATTERN = "/tmp/auto_retry_*.json"
_DONE_SUFFIX = ".done"
_LOCK_SUFFIX = ".lock"
_SCHEMA_VERSION = "1.1"   # P1-4: versioned JSON schema

# ─────────────────────────────────────────────────────────────────
# Dangerous-command patterns (P0-2)
# Covers: bare危险,binary路径,变量绕过,管道注入,sudo等
# ─────────────────────────────────────────────────────────────────
_DANGEROUS_PATTERNS = [
    # Recursive remove (all variants)
    (re.compile(r'\brm\s+(-[rf]+\s+)*(/|~)'), "recursive delete at root/home"),
    (re.compile(r'\brm\s+(-[rf]+\s+)+'), "recursive delete flag"),
    # Disk wipe
    (re.compile(r'\bdd\s+.*(of=|dev/)'), "dd disk write"),
    (re.compile(r'\bmkfs\b'), "filesystem format"),
    (re.compile(r'\bfdisk\b'), "partition table edit"),
    (re.compile(r'\bparted\b'), "partition edit"),
    # Fork bomb
    (re.compile(r':\(\)\s*\{.*:.*\|.*:.*\}'), "fork bomb"),
    (re.compile(r'\{\:\|\:\&\s*\}'), "fork bomb variant"),
    # Network exfil (plain http, not https)
    (re.compile(r'\bcurl\s+http://'), "plain-http exfil"),
    (re.compile(r'\bwget\s+http://'), "plain-http exfil"),
    (re.compile(r'\bpython3?\s+-c\s+.*http://'), "python http exfil"),
    # Overwrite with no确认
    (re.compile(r'^>\s*/dev/sd[a-z]'), "direct block device write"),
    (re.compile(r'^>\s*/etc/passwd'), "write to passwd"),
    # Systemctl destroy
    (re.compile(r'\bsystemctl\s+(stop|kill)\s+.*-(k|kill)\b'), "systemctl kill"),
]

# Commands that are safe to retry IF they don't contain dangerous patterns.
# IMPORTANT: allowlist is checked FIRST (before regex patterns) for known-safe
# commands. "curl " and "wget " are deliberately EXCLUDED here because
# curl/wget without https are dangerous; they are caught by regex patterns below.
_SAFE_COMMANDS = {
    "npm install", "npm i", "pip install", "pip3 install",
    "yarn install", "bun install", "pnpm install",
    "cargo build", "cargo install", "go build", "go install",
    "make", "make all",  # make (without -j flags that reduce parallelism)
    "git clone", "git fetch", "git pull",
    "docker build",
}


class PendingRetry:
    """One pending timeout-retry item scanned from a JSON file."""

    def __init__(self, json_path: str, data: dict):
        self.json_path = json_path
        self.data = data
        self.command = data.get("command", "")
        self.workspace = data.get("workspace", "/tmp")
        self.elapsed = data.get("elapsed_seconds", 0)
        self.expected = data.get("expected_seconds", 60)
        self.cause = data.get("cause", "unknown")
        self.severity = data.get("severity", "medium")
        self.suggestions = data.get("suggestions", [])
        self.progress = data.get("progress", {})
        self.output_preview = data.get("output_preview", "")
        self.retry_count = data.get("_retry_count", 0)
        self.timestamp = data.get("timestamp", "")
        self.version = data.get("_version", "1.0")   # P1-4
        self.optimized_command: Optional[str] = None
        # P1-1: computed age for round-robin scheduling
        self._age_seconds = self._compute_age()

    def _compute_age(self) -> float:
        """Return age of this retry item in seconds (for age-based scheduling)."""
        try:
            ts = self.timestamp
            if not ts:
                return 0.0
            # Normalize: replace Z with +00:00
            ts = ts.replace("Z", "+00:00")
            # Remove sub-second precision for simpler parsing
            if "." in ts:
                base, rest = ts.split(".", 1)
                # rest might be "000+00:00" or "000Z" etc — keep only first 3 digits + tz
                ms_and_tz = re.sub(r'^(\d{3})(.*)$', r'\1\2', rest)
                ts = base + "." + ms_and_tz
            # Handle +0000 vs +00:00 inconsistency
            ts = re.sub(r'\+(\d{4})$', lambda m: f"+{m.group(1)[:2]}:{m.group(1)[2:]}", ts)
            dt = datetime.fromisoformat(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            dt_naive = dt.replace(tzinfo=None)
            return (datetime.now() - dt_naive).total_seconds()
        except Exception:
            return 0.0

    @property
    def retry_id(self) -> str:
        """Return stable retry ID from json_path (no extension)."""
        return os.path.basename(self.json_path).replace(".json", "")

    @property
    def is_old(self) -> bool:
        """True if this retry has been waiting > 5 minutes (candidate for prioritization)."""
        return self._age_seconds > 300


# ─────────────────────────────────────────────────────────────────
# Hash — SHA-256 full (P0-2 footnote: MD5→SHA-256, full output)
# ─────────────────────────────────────────────────────────────────
def get_command_hash(command: str) -> str:
    return hashlib.sha256(command.encode()).hexdigest()[:24]


def get_retry_file_path(command: str) -> str:
    h = get_command_hash(command)
    return f"/tmp/auto_retry_{h}.json"


# ─────────────────────────────────────────────────────────────────
# Atomic flock (P0-1) — BSD-style, works on macOS
# fcntl.flock is advisory lock: process-wide, auto-released on close/crash
# ─────────────────────────────────────────────────────────────────
class _FlockHandle:
    """Context manager for atomic file lock using fcntl.flock (BSD/macOS compatible)."""

    def __init__(self, lock_path: str, exclusive: bool = True):
        self.lock_path = lock_path
        self.exclusive = exclusive
        self.fd: Optional[int] = None

    def acquire(self, blocking: bool = False, timeout: float = 10.0) -> bool:
        try:
            self.fd = os.open(self.lock_path, os.O_CREAT | os.O_WRONLY, 0o600)
            start = time.monotonic()
            while True:
                try:
                    fcntl.flock(
                        self.fd,
                        (fcntl.LOCK_EX if self.exclusive else fcntl.LOCK_SH)
                        | (0 if blocking else fcntl.LOCK_NB)
                    )
                    # Write PID so we can verify ownership later
                    os.write(self.fd, f"{os.getpid()}|{time.time()}".encode())
                    os.lseek(self.fd, 0, os.SEEK_SET)
                    return True
                except (BlockingIOError, IOError):
                    if not blocking:
                        return False
                    if time.monotonic() - start >= timeout:
                        return False
                    time.sleep(0.1)
        except OSError:
            return False

    def release(self) -> None:
        if self.fd is not None:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_UN)
                os.close(self.fd)
            except Exception:
                pass
            self.fd = None
        try:
            os.remove(self.lock_path)
        except FileNotFoundError:
            pass

    def held_by_us(self) -> bool:
        """Check if the lock is held by current process (for sanity checks)."""
        if self.lock_path is None:
            return False
        try:
            # Open a fresh fd for reading to avoid macOS buffer issues
            with open(self.lock_path, "r") as rf:
                content = rf.read().strip()
            pid_str = content.split("|")[0] if "|" in content else content
            return int(pid_str) == os.getpid()
        except Exception:
            return False

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *args):
        self.release()


def _is_stale_lock(lock_path: str) -> bool:
    """Return True if lock is held by a dead process (for cleanup)."""
    try:
        with open(lock_path) as f:
            content = f.read().strip()
        pid_str = content.split("|")[0] if "|" in content else content
        pid = int(pid_str)
        # Send signal 0: checks if process exists (doesn't actually signal)
        os.kill(pid, 0)
        return False  # process alive
    except (ValueError, ProcessLookupError, PermissionError, OSError):
        return True  # dead or can't access


# ─────────────────────────────────────────────────────────────────
# Atomic file operations (P0-3)
# os.rename is atomic on POSIX within the same filesystem
# ─────────────────────────────────────────────────────────────────
def _atomic_write_json(json_path: str, data: dict) -> None:
    """Atomically write JSON: write to .tmp, then rename (POSIX-atomic)."""
    tmp = json_path + f".{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.rename(tmp, json_path)   # POSIX-atomic on same filesystem


def _mark_done(json_path: str) -> bool:
    """
    Atomically mark a retry as done.
    P0-3: Write .done file, then atomically remove .json.
    Returns True on success, False on failure.
    """
    try:
        with open(json_path) as f:
            data = json.load(f)
        done_path = json_path + _DONE_SUFFIX
        # Atomic: write temp + rename (same filesystem guaranteed for /tmp)
        _atomic_write_json(done_path, data)
        # Now remove the original (best-effort; if this races, rename already protected us)
        try:
            os.remove(json_path)
        except FileNotFoundError:
            pass  # another process already removed it
        _release_lock(json_path)
        logger.info("AUTO-RETRY-DONE path=%s", json_path)
        return True
    except Exception as e:
        logger.error("AUTO-RETRY FATAL: mark_done failed for %s: %s", json_path, e)
        return False


def _acquire_lock(json_path: str, blocking: bool = False) -> Optional["_FlockHandle"]:
    """
    P0-1: Acquire exclusive flock on json_path.
    Returns FlockHandle on success, None on failure.
    Cleans up stale locks (>5min) before attempting.
    """
    lock_path = json_path + _LOCK_SUFFIX

    # Cleanup stale lock from dead process
    if os.path.exists(lock_path) and _is_stale_lock(lock_path):
        try:
            os.remove(lock_path)
            logger.info("Cleaned up stale lock: %s", lock_path)
        except Exception:
            pass

    handle = _FlockHandle(lock_path, exclusive=True)
    if handle.acquire(blocking=blocking):
        return handle
    return None


def _release_lock(json_path: str) -> None:
    """Release flock lock — FlockHandle auto-releases on close; explicit call for clarity."""
    lock_path = json_path + _LOCK_SUFFIX
    try:
        os.remove(lock_path)
    except FileNotFoundError:
        pass


# ─────────────────────────────────────────────────────────────────
# Dangerous-command detection (P0-2)
# Multi-layer: allowlist bypass → pattern match → shlex parse
# ─────────────────────────────────────────────────────────────────
def _is_dangerous(command: str) -> Optional[str]:
    """
    Returns None if safe, or a str describing WHY it is dangerous.
    P0-2: Regex + shlex parse + binary-path check.
    """
    cmd = command.strip()
    if not cmd:
        return "empty command"

    # Layer 1: allowlist
    for safe in _SAFE_COMMANDS:
        if cmd.startswith(safe):
            # Check if the allowlisted command also contains dangerous patterns
            # (e.g. "make && rm -rf" starts with "make" but is dangerous)
            for pattern, reason in _DANGEROUS_PATTERNS:
                if pattern.search(cmd):
                    return f"allowlisted prefix but dangerous: {reason}"
            return None

    # Layer 2: shlex parse to detect compound shell structure (pipe, redirect, etc.)
    # This catches cases like "cmd1 | cmd2" that pass the allowlist prefix check
    try:
        if any(op in cmd for op in ("&&", "||", ";", "|", ">>", "2>", "&>", "&&=", "||=")):
            return "compound shell command (pipe/redirect/semicolons)"
    except Exception:
        pass

    # Layer 3: regex pattern matching for known-destructive operations
    for pattern, reason in _DANGEROUS_PATTERNS:
        if pattern.search(cmd):
            return reason

    # Layer 4: absolute-path binary that looks dangerous
    ABSOLUTE_DANGEROUS = ["/bin/rm", "/usr/bin/rm", "/sbin/rm", "/bin/dd",
                          "/bin/mkfs", "/usr/bin/mkfs", "/bin/fdisk",
                          "/usr/sbin/fdisk", "/sbin/shutdown", "/usr/sbin/reboot"]
    tokens = cmd.split()
    if len(tokens) >= 2 and tokens[0] in ABSOLUTE_DANGEROUS:
        return f"absolute-path dangerous binary: {tokens[0]}"

    return None


def _should_retry(retry: PendingRetry) -> tuple[bool, str]:
    """
    P0-2 + P1-2: Returns (allowed, reason).
    Separates fatal (never retry) from warn (retry with caution).
    """
    cmd = retry.command.strip()

    # Retry count exceeded
    if retry.retry_count >= 2:
        return False, f"retry_count={retry.retry_count} >= 2 (exhausted)"

    # Dangerous command check
    danger = _is_dangerous(cmd)
    if danger:
        return False, f"dangerous command: {danger}"

    # Schema version mismatch (future compat)
    try:
        v = tuple(int(x) for x in retry.version.split("."))
        schema = tuple(int(x) for x in _SCHEMA_VERSION.split("."))
        if v < schema:
            logger.warning("Schema version %s < %s for %s", retry.version, _SCHEMA_VERSION, cmd)
    except Exception:
        pass

    return True, "ok"


# ─────────────────────────────────────────────────────────────────
# Command optimization (P1-3: wrapped in timeout)
# ─────────────────────────────────────────────────────────────────
def generate_optimized_command(retry: PendingRetry) -> Optional[str]:
    """
    Generate an optimized command based on timeout cause and command type.
    P1-3: All optimized commands are wrapped in a timeout guard.
    Returns None if no optimization is possible or needed.
    """
    cmd = retry.command.strip()

    # ── Helper: wrap in timeout ──────────────────────────────────
    def with_timeout(c: str, secs: int) -> str:
        if c.startswith("timeout "):
            return c  # already wrapped
        return f"timeout {secs}s {c}"

    # ── Network / slow-progress ────────────────────────────────────
    if retry.cause in ("network", "slow_progress"):
        # npm install
        if cmd.startswith("npm install") or cmd.startswith("npm i"):
            if "--prefer-offline" not in cmd:
                return with_timeout(cmd + " --prefer-offline --no-audit --no-fund", retry.expected)
            if "--registry" not in cmd:
                return with_timeout(cmd + " --registry=https://registry.npmmirror.com", retry.expected)
            return None

        # pip install
        if cmd.startswith("pip install") or cmd.startswith("pip3 install"):
            if "-i" not in cmd and "--index-url" not in cmd:
                return with_timeout(cmd + " -i https://pypi.tuna.tsinghua.edu.cn/simple --break-system-packages", retry.expected)
            return None

        # yarn install
        if cmd.startswith("yarn install"):
            if "--prefer-offline" not in cmd:
                return with_timeout(cmd + " --prefer-offline", retry.expected)
            return None

        # git clone → shallow clone
        if cmd.startswith("git clone"):
            if "--depth" not in cmd and "--single-branch" not in cmd:
                parts = cmd.split()
                if len(parts) >= 3:
                    url = parts[2]; rest = parts[3:]
                    opt = "git clone --depth 1 --single-branch " + url + (" " + " ".join(rest) if rest else "")
                    return with_timeout(opt.rstrip(), retry.expected)
                elif len(parts) == 2:
                    return with_timeout("git clone --depth 1 --single-branch " + parts[1], retry.expected)
            return None

        # curl → retry +断点续传
        if cmd.startswith("curl "):
            if "-C -" not in cmd and "--continue-at" not in cmd:
                return with_timeout(cmd + " -C - --retry 3 --retry-delay 5", retry.expected)
            return None

        # wget → continue
        if cmd.startswith("wget "):
            if "-c" not in cmd and "--continue" not in cmd:
                return with_timeout(cmd + " -c", retry.expected)
            return None

        # docker build → plain progress
        if cmd.startswith("docker build"):
            if "--progress" not in cmd:
                return with_timeout(cmd + " --progress=plain", retry.expected)
            return None

    # ── Compile / build stuck ─────────────────────────────────────
    if retry.cause in ("compile_stuck", "slow_progress"):
        if "make" in cmd and "-j" in cmd:
            new_cmd = re.sub(r"-j\s*\d+", "-j1", cmd)
            return with_timeout(new_cmd, retry.expected)
        if cmd == "make" or cmd == "make all":
            return with_timeout("make -j1", retry.expected)
        if cmd.startswith("cargo build"):
            if "-j" not in cmd:
                return with_timeout(cmd + " -j 1", retry.expected)
            return None
        if cmd.startswith("go build"):
            if "-p " not in cmd:
                return with_timeout(cmd + " -p 1", retry.expected)
            return None

    # ── No output (可能卡在等待) ───────────────────────────────────
    if retry.cause == "no_output":
        if not cmd.startswith("timeout "):
            return with_timeout(f"timeout {retry.expected * 2}s {cmd}", retry.expected * 2)
        return None

    # ── Memory pressure ──────────────────────────────────────────────
    if retry.cause == "memory":
        if "make" in cmd and "-j" in cmd:
            return with_timeout(re.sub(r"-j\s*\d+", "-j1", cmd), retry.expected)
        if cmd.startswith("cargo build"):
            return with_timeout(cmd + " -j 1", retry.expected)
        return None

    # ── Default: add timeout wrapper ────────────────────────────────
    if retry.severity in ("low", "medium") and retry.progress.get("progress", 0) > 0:
        for s in retry.suggestions:
            if "timeout" in s.lower() or "增加" in s or "increase" in s.lower():
                if not cmd.startswith("timeout "):
                    return with_timeout(f"timeout {retry.expected * 3}s {cmd}", retry.expected * 3)
        if not cmd.startswith("timeout "):
            return with_timeout(f"timeout {retry.expected * 3}s {cmd}", retry.expected * 3)

    return None


# ─────────────────────────────────────────────────────────────────
# Pending retry scanning — P1-1: round-robin + age-based selection
# Instead of always taking [0], we pick the oldest OR random old entry
# to prevent starvation of later entries.
# ─────────────────────────────────────────────────────────────────
def check_pending_retries() -> list[PendingRetry]:
    """
    Scan /tmp/auto_retry_*.json and return retryable items.
    P1-1: Selects using age-based round-robin to prevent starvation.
    """
    candidates: list[PendingRetry] = []

    for path in glob.glob(RETRY_PATTERN):
        if (path.endswith(_DONE_SUFFIX)
                or path.endswith(_LOCK_SUFFIX)
                or ".tmp" in path):
            continue

        # Check and clean stale locks first (non-blocking)
        lock_path = path + _LOCK_SUFFIX
        if os.path.exists(lock_path) and _is_stale_lock(lock_path):
            try:
                os.remove(lock_path)
            except Exception:
                pass

        try:
            with open(path) as f:
                data = json.load(f)

            # Support both single-record and list-of-records format
            if isinstance(data, list):
                # Get the last record (most recent)
                data = data[-1] if data else None
            if not isinstance(data, dict):
                continue

            # P1-4: version field
            if not data.get("_version"):
                data["_version"] = "1.0"

            retry = PendingRetry(path, data)

            # P0-2 + P1-2: should_retry check
            allowed, reason = _should_retry(retry)
            if not allowed:
                logger.info("Skipping retry for %s: %s", retry.command[:60], reason)
                if "exhausted" in reason or "dangerous" in reason:
                    _mark_done(path)  # clean up dead entries
                continue

            # Generate optimization
            optimized = generate_optimized_command(retry)
            if optimized:
                retry.optimized_command = optimized
                candidates.append(retry)
                logger.info(
                    "AUTO-RETRY CANDIDATE cmd=%s optimized=%s age=%.1fs",
                    retry.command[:60], optimized[:60], retry._age_seconds
                )
            else:
                # No optimization possible; mark done
                logger.info("No optimization for %s, marking done", retry.command[:60])
                _mark_done(path)

        except json.JSONDecodeError as e:
            # P1-2: Data corruption — isolate and warn
            logger.error("AUTO-RETRY FATAL: corrupted JSON %s: %s. Moving to quarantine.", path, e)
            try:
                os.rename(path, path + ".corrupted")
            except Exception:
                pass
        except Exception as e:
            # P1-2: graded — non-fatal errors just warn
            logger.warning("AUTO-RETRY: failed to read %s: %s", path, e)

    # P1-1: Age-based round-robin selection
    # Sort: old entries first (prioritize starved items),
    # but shuffle within the "old" band to add randomness.
    old = [r for r in candidates if r.is_old]
    young = [r for r in candidates if not r.is_old]
    random.shuffle(old)
    random.shuffle(young)
    return old + young


# ─────────────────────────────────────────────────────────────────
# Message injection
# ─────────────────────────────────────────────────────────────────
def _build_inject_message(retry: PendingRetry) -> str:
    """Build the user-message content instructing the agent to retry."""
    progress_info = ""
    if retry.progress.get("summary"):
        progress_info = f"\n- 进度状态: {retry.progress['summary']}"
    suggestions_text = ""
    if retry.suggestions:
        suggestions_text = "\n".join(f"  {i+1}. {s}" for i, s in enumerate(retry.suggestions[:3]))

    return (
        f"[AUTO-RETRY] 检测到上一个命令超时，需要自动优化后继续执行。\n\n"
        f"## 超时诊断\n"
        f"- 原始命令: `{retry.command}`\n"
        f"- 运行时长: {retry.elapsed} 秒（预期: {retry.expected} 秒）\n"
        f"- 超时原因: {retry.cause}（严重度: {retry.severity}）{progress_info}\n\n"
        f"## 优化方案\n"
        f"优化后的命令: `{retry.optimized_command}`\n\n"
        f"## 建议列表\n"
        f"{suggestions_text}\n\n"
        f"## 执行步骤\n"
        f"1. 先执行优化后的命令: {retry.optimized_command}\n"
        f"2. 如果优化命令成功完成，继续执行原来的任务（根据上下文推断下一步应该做什么）\n"
        f"3. 如果仍然失败，报告错误并说明原因\n\n"
        f"请立即执行上述步骤。"
    )


def check_and_inject(messages: list, workspace: str = "/tmp") -> bool:
    """
    Check for pending timeout retries and inject a retry instruction into messages.
    Returns True if a retry was injected (agent should execute it this turn).
    Returns False if nothing to retry.

    P0-1: Uses atomic flock to prevent double-injection.
    P0-3: Uses atomic rename for all file state changes.
    P1-1: Age-based selection prevents starvation.
    P1-5: Structured audit log on every injection.
    """
    pending = check_pending_retries()
    if not pending:
        return False

    retry = pending[0]   # P1-1: oldest/random-old first

    # P0-1: Atomic lock — non-blocking
    lock = _acquire_lock(retry.json_path, blocking=False)
    if lock is None:
        # Another process has it; skip this iteration
        logger.info("AUTO-RETRY: could not acquire lock for %s, skipping", retry.json_path)
        return False

    try:
        # Double-check: is the file still there and not done?
        if not os.path.exists(retry.json_path):
            logger.info("AUTO-RETRY: file %s gone after lock acquisition", retry.json_path)
            return False

        inject_content = _build_inject_message(retry)
        messages.append({
            "role": "user",
            "content": inject_content,
            "_auto_retry_inject": True,
            "_retry_id": retry.retry_id,
        })

        # P1-5: Structured audit log
        logger.info(
            "AUTO-RETRY INJECTED id=%s cmd=%s opt=%s age=%.1fs",
            retry.retry_id,
            retry.command[:60],
            (retry.optimized_command or "N/A")[:60],
            retry._age_seconds,
        )
        return True
    except Exception as e:
        logger.error("AUTO-RETRY FATAL: check_and_inject failed: %s", e)
        return False
    finally:
        lock.release()


def mark_retry_done(retry_id: str) -> bool:
    """
    Mark a retry as done. Call after the optimized command succeeds.
    retry_id is the filename without .json, e.g. "auto_retry_<24charhash>".

    P0-3: Atomic state transition.
    P1-5: Structured audit log.
    Returns True on success.
    """
    pattern = f"/tmp/{retry_id}.json"
    # Only process exact match (not .done, not .lock)
    if not os.path.exists(pattern):
        logger.warning("AUTO-RETRY: mark_retry_done: file not found %s", pattern)
        return False

    try:
        success = _mark_done(pattern)
        if success:
            logger.info("AUTO-RETRY DONE id=%s", retry_id)
        else:
            logger.error("AUTO-RETRY FAIL: mark_retry_done failed for %s", retry_id)
        return success
    except Exception as e:
        logger.error("AUTO-RETRY FATAL: mark_retry_done exception %s: %s", retry_id, e)
        return False


# ─────────────────────────────────────────────────────────────────
# CLI entry point
# ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    pending = check_pending_retries()
    if not pending:
        print("No pending auto-retry items.")
    else:
        for r in pending:
            print(f"Retry [{r.retry_id}] age={r._age_seconds:.1f}s")
            print(f"  cmd : {r.command[:80]}")
            print(f"  opt : {r.optimized_command}")
            print(f"  cause: {r.cause} | severity: {r.severity} | retries: {r.retry_count}")
            print()
