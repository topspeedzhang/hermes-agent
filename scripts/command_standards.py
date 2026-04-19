#!/usr/bin/env python3
"""
命令执行规范检查 — Command Standards Checker

所有 Agent 生成的终端命令在执行前必须通过此检查。
检查通过返回 {"pass": True}，不通过返回 {"pass": False, "error": "...", "suggestion": "..."}

检查维度：
  1. 后台任务规范（daemon / server / long-running process）
  2. 超时包裹规范（npm install / pip install / git clone 等）
  3. 前台命令规范（ls/cd/echo 等不需要 &）
  4. Shell 连接符规范（cd 后必须跟 &&）
  5. 危险命令黑名单（通过 auto_retry_manager.is_dangerous_command）
"""

import sys
import os
import re
import subprocess
from typing import Optional

# ── Dangerous command guard (delegates to auto_retry_manager if available) ────

def is_dangerous(cmd: str) -> tuple[bool, str]:
    """
    Returns (True, reason) if the command is in the dangerous blacklist.
    Returns (False, "") otherwise.
    """
    cmd_stripped = cmd.strip()

    # ── Layer 1: allowlist (known safe) ───────────────────────────────────
    ALLOWLIST = {
        "ls", "cd", "cat", "pwd", "echo", "grep", "find", "head", "tail",
        "wc", "cut", "sort", "uniq", "tr", "awk", "sed", "sort", "stat",
        "mkdir", "touch", "cp", "mv", "rm",  # rm is allowed but dangerous
        "git", "npm", "pip", "brew", "apt", "cargo", "go", "curl", "wget",
        "python3", "python", "node", "ruby", "perl", "php",
    }
    base = cmd_stripped.split()[0] if cmd_stripped.split() else ""
    if base in ALLOWLIST:
        # But still check for compound shell patterns below
        pass

    # ── Layer 2: compound shell command detection ─────────────────────────
    # If a command contains shell metacharacters, it's more dangerous because
    # it can embed subcommands
    SHELL_META = '|', '&', ';', '>', '<', '`', '$('
    has_meta = any(m in cmd_stripped for m in SHELL_META)
    if has_meta:
        # curl http://... | sh → blocked
        if re.search(r"curl\s+http://.*\|\s*sh\b", cmd_stripped):
            return True, "plain-http exfil (curl piped to shell)"
        if re.search(r"wget\s+http://.*\|\s*sh\b", cmd_stripped):
            return True, "plain-http exfil (wget piped to shell)"
        # Remote code via $()
        if re.search(r"\$\([^)]*\|\s*sh\b", cmd_stripped):
            return True, "remote code via pipe"
        # Block device writes
        if re.search(r"^\s*>", cmd_stripped) and re.search(r"/dev/[a-z]", cmd_stripped):
            return True, "block device write"
        # Password file overwrite
        if re.search(r">\s*/etc/passwd", cmd_stripped):
            return True, "system file overwrite"
        # rm -rf / or rm -rf /*
        if re.search(r"rm\s+-rf\s+/\s*(;|\||&|$)", cmd_stripped):
            return True, "recursive root delete"
        if re.search(r"rm\s+-rf\s+/", cmd_stripped):
            return True, "recursive delete system path"

    # ── Layer 3: regex patterns ──────────────────────────────────────────
    DANGEROUS_PATTERNS = [
        (r"\bdd\b.*\bof=/dev/",               "raw disk write"),
        (r"\bmkfs\b",                         "filesystem format"),
        (r":\(\)\{\s*:\|:&\s*\};:",           "fork bomb"),
        (r"chmod\s+-R\s+777\s+/",             "dangerous permission"),
        (r">\s*/etc/passwd",                 "system file overwrite"),
        (r">\s*/dev/sd[a-z]\b",              "block device write"),
        (r"curl\s+http://.*\|\s*sh",          "plain-http exfil"),
        (r"wget\s+http://.*\|\s*sh",          "plain-http exfil"),
    ]
    for pattern, reason in DANGEROUS_PATTERNS:
        if re.search(pattern, cmd_stripped, re.IGNORECASE):
            return True, reason

    return False, ""


# ── Timeout rules ─────────────────────────────────────────────────────────────

COMMAND_TIMEOUT = {
    "npm install": 120,
    "pip install": 90,
    "pip3 install": 90,
    "brew install": 180,
    "apt install": 120,
    "apt-get install": 120,
    "git clone": 120,
    "yarn install": 120,
    "pnpm install": 120,
}

# Commands that MUST run in background (daemon / server patterns)
DAEMON_PATTERNS = [
    r"python3?\s+[^\s]+\.py\b",         # python3 script.py [args]
    r"node\s+[^\s]+\.js\b",             # node script.js [args]
    r"uvicorn\s+",                       # uvicorn ...
    r"flask\s+run",                      # flask run ...
    r"fastapi\s+run",                    # fastapi run ...
    r"streamlit\s+run",                   # streamlit run ...
    r"next\s+dev",                       # next dev ...
    r"http\.server\s+",                  # python3 -m http.server ...
    r"php\s+-S\s+",                      # php -S ...
    r"redis-server\b",                    # redis-server
    r"postgres\b.*-D\s+",                # postgres -D ...
    r"mongod\b",                         # mongod
    r"nginx\b",                          # nginx
    r"skills_server\.py",                # explicit server script
    r">\s*/tmp/.*\.log\s+2>&1\s+&",      # already a background redirect (good!)
]

# Commands that are pure foreground (should NEVER have &)
FOREGROUND_ONLY_PATTERNS = [
    r"^\s*ls\b",
    r"^\s*cd\b",
    r"^\s*cat\b",
    r"^\s*grep\b",
    r"^\s*find\b",
    r"^\s*pwd\b",
    r"^\s*echo\b",
    r"^\s*git\s+status\b",
    r"^\s*git\s+diff\b",
    r"^\s*git\s+log\b",
    r"^\s*which\b",
    r"^\s*type\s+\w",
    r"^\s*stat\b",
    r"^\s*head\b",
    r"^\s*tail\b",
    r"^\s*wc\b",
    r"^\s*cut\b",
    r"^\s*sort\b",
    r"^\s*uniq\b",
]


def _get_base_command(cmd: str) -> str:
    """Extract the first token (the actual command)."""
    stripped = cmd.strip()
    # Remove leading env vars like FOO=bar
    if "=" in stripped and not stripped.startswith("-"):
        parts = stripped.split()
        for i, p in enumerate(parts):
            if "=" not in p or p.startswith("-"):
                return parts[i] if i < len(parts) else ""
    return stripped.split()[0] if stripped.split() else ""


def check_command_standards(
    command: str,
    background: Optional[bool] = None,
    timeout: Optional[int] = None,
) -> dict:
    """
    检查命令是否符合执行规范。

    Returns:
        {"pass": True}  — 命令可以执行
        {"pass": False, "error": "...", "suggestion": "..."}  — 需要修正
    """
    cmd = command.strip()
    if not cmd:
        return {"pass": False, "error": "Empty command", "suggestion": ""}

    base = _get_base_command(cmd)

    # ── 1. Dangerous command check ──────────────────────────────────────────
    dangerous, reason = is_dangerous(cmd)
    if dangerous:
        return {
            "pass": False,
            "error": f"Dangerous command detected: {reason}",
            "suggestion": "This command is blocked. If you intentionally want to run it, "
                          "please confirm explicitly and I will execute it with force=True.",
        }

    # ── 2. Daemon / long-running process check ─────────────────────────────
    is_daemon = any(re.search(p, cmd) for p in DAEMON_PATTERNS)
    ends_with_ampersand = cmd.rstrip().endswith("&")

    if is_daemon:
        if not ends_with_ampersand and not (background is True):
            # Missing nohup / & / background flag
            suggestion = (
                "This command looks like a long-running server or daemon. "
                "It should be started in the background. "
                f"Suggested: nohup {cmd} > /tmp/daemon.log 2>&1 &\n"
                "Or if you want to run it in foreground and wait for it, "
                "please confirm and set background=true explicitly."
            )
            return {"pass": False, "error": "Long-running server command needs background mode", "suggestion": suggestion}

    # ── 3. Foreground-only command check ───────────────────────────────────
    is_foreground_only = any(re.search(p, cmd, re.IGNORECASE) for p in FOREGROUND_ONLY_PATTERNS)
    if is_foreground_only and ends_with_ampersand:
        suggestion = (
            f"Command '{base}' is a simple foreground command that returns immediately. "
            "It should NOT be run in the background with &. "
            f"Just run it directly: {cmd.rstrip().rstrip('&').strip()}"
        )
        return {"pass": False, "error": f"Foreground-only command should not use &", "suggestion": suggestion}

    # ── 4. cd followed by ; (loses cd effect) ────────────────────────────────
    # Check for "cd /path; command" pattern (semicolon after cd, separate command)
    cd_semicolon = re.search(r"\bcd\s+[^\s;]+;\s*\w+", cmd)
    if cd_semicolon and "&&" not in cmd:
        return {
            "pass": False,
            "error": "cd followed by ';' loses its effect in subsequent commands",
            "suggestion": "Use '&&' instead of ';' to chain cd with other commands. "
                          "Example: cd /path && ls (not cd /path; ls)",
        }

    # ── 5. npm / pip / git install without timeout ───────────────────────────
    needs_timeout = any(cmd.startswith(k) for k in COMMAND_TIMEOUT.keys())
    if needs_timeout and timeout is None and not ends_with_ampersand:
        # Check if already has a timeout wrapper
        if not re.search(r"\btimeout\s+\d+", cmd):
            base_cmd = cmd.split("&&")[0].split(";")[0].strip()
            suggested_timeout = next((v for k, v in COMMAND_TIMEOUT.items() if base_cmd.startswith(k)), 120)
            return {
                "pass": False,
                "error": f"Command may hang without a timeout",
                "suggestion": f"Wrap this command with 'timeout {suggested_timeout}s'. "
                              f"Example: timeout {suggested_timeout}s {cmd}",
            }

    # ── 6. git clone without --depth ─────────────────────────────────────────
    if re.search(r"\bgit\s+clone\b", cmd) and "--depth" not in cmd and "|" not in cmd:
        return {
            "pass": False,
            "error": "git clone without --depth fetches entire repository history",
            "suggestion": "Use 'git clone --depth 1 --single-branch <url>' to clone only the latest commit. "
                          "Example: timeout 120s git clone --depth 1 --single-branch <url> /tmp/repo",
        }

    # ── 7. Missing >file 2>&1 for background commands ──────────────────────
    if ends_with_ampersand and ">" not in cmd and "2>&1" not in cmd:
        return {
            "pass": False,
            "error": "Background command (&) without output redirection will lose output",
            "suggestion": f"Add output redirection: nohup {cmd.rstrip('&').strip()} > /tmp/cmd.log 2>&1 &",
        }

    return {"pass": True}


# ── CLI for testing ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    if len(sys.argv) > 1:
        cmd = " ".join(sys.argv[1:])
    else:
        print("Usage: python3 command_standards.py <command>")
        print(json.dumps({
            "npm install express": check_command_standards("npm install express"),
            "python3 server.py": check_command_standards("python3 server.py"),
            "ls -la &": check_command_standards("ls -la &"),
            "cd /tmp; ls": check_command_standards("cd /tmp; ls"),
            "git clone https://github.com/user/repo": check_command_standards("git clone https://github.com/user/repo"),
        }, indent=2))
        sys.exit(0)

    result = check_command_standards(cmd)
    print(json.dumps(result, indent=2))
