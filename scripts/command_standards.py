#!/usr/bin/env python3
"""
命令生成规范 — Command Execution Standards for Hermes Agent

所有 Agent 生成的终端命令必须遵守以下规范，从源头避免命令卡住无法结束。

────────────────────────────────────────────
核心原则
────────────────────────────────────────────
1. 有副作用的长时间任务 → 后台运行 + nohup
2. 需要等待结果但可能超时的 → 用 timeout 包裹
3. 纯前台命令（ls/cd/echo）→ 直接执行，不加 &
4. 一条命令只做一件事，用 ; 链式调用

────────────────────────────────────────────
场景分类与标准写法
────────────────────────────────────────────

【场景 A】启动服务/守护进程（服务端持续运行）
────────────────────────────────────────────
✅ 标准写法：
    nohup python3 skills_server.py > /tmp/skills_server.log 2>&1 &
    echo "PID: $!"
    sleep 1
    lsof -i :8787 || echo "端口未监听"

⚠️ 常见错误（禁止这样写）：
    python3 skills_server.py &          # 容易被 SIGHUP 杀死
    python3 skills_server.py > file &   # 没有 2>&1，stderr 丢失
    python3 skills_server.py & sleep 2  # sleep 是前台，& 只管 python


【场景 B】需要等待结果但可能超时的命令
────────────────────────────────────────────
✅ 标准写法：
    timeout 60s npm install express --prefer-offline --no-audit --no-fund

⚠️ 常见错误：
    npm install express                  # 无限等待
    npm install express &                # npm install 是前台等待，不应该 &


【场景 C】纯前台命令（立即返回）
────────────────────────────────────────────
✅ 标准写法：
    ls -la
    cd /path/to && cat file.txt
    git status

⚠️ 常见错误：
    ls -la &                             # 不需要后台，浪费资源
    cd /path && command &                # 前台命令不应该 &


【场景 D】多个命令顺序执行（不管成功失败都继续）
────────────────────────────────────────────
✅ 标准写法：
    cd /path/to/project && \
    npm install && \
    npm run build

或一行：
    cd /path/to/project && npm install && npm run build

⚠️ 常见错误：
    cd /path; npm install    # cd 的效果在 ; 后面丢失（每个命令独立 shell）
    cd /path && npm install &  # npm install 是主要任务，不要后台


【场景 E】后台任务完成后想继续操作
────────────────────────────────────────────
✅ 标准写法：
    # 启动后台任务
    nohup python3 server.py > /tmp/server.log 2>&1 &
    SERVER_PID=$!
    echo "Server PID: $SERVER_PID"

    # 等待服务就绪（轮询检查，最多等 30s）
    for i in $(seq 1 30); do
        if lsof -i :8080 > /dev/null 2>&1; then
            echo "服务已就绪"
            break
        fi
        sleep 1
    done

⚠️ 常见错误：
    python3 server.py &; lsof -i :8080   # & 和 ; 不能这样连用
    sleep 30                              # 盲目等 30s，不检查是否真的就绪


【场景 F】Git clone 大仓库
────────────────────────────────────────────
✅ 标准写法（必须加 --depth 1）：
    timeout 120s git clone --depth 1 --single-branch https://github.com/user/repo.git /tmp/repo

⚠️ 常见错误：
    git clone https://github.com/user/repo.git  # 没有 --depth，下载整个历史


【场景 G】用户要求"等一下"或"先不要执行"
────────────────────────────────────────────
✅ 标准写法：不要执行任何命令，等用户下一步指示。

❌ 如果用户没有明确说"执行"，绝对不要运行任何有副作用的命令。


────────────────────────────────────────────
危险命令黑名单（绝对禁止自动执行）
────────────────────────────────────────────
以下命令在 Agent 自动执行时必须拦截，必须先问用户：

    dd if=... of=/dev/sdX              # 磁盘写入，可能毁掉系统
    rm -rf /                           # 删除根目录
    mkfs.*                             # 格式化文件系统
    :(){ :|:& };:                      # fork 炸弹
    curl http://... | sh               # 远程代码执行
    wget http://... -O- | sh           # 远程代码执行
    chmod -R 777 /                     # 权限大开
    > /etc/passwd                      # 覆盖系统文件

自动优化规则（auto_retry_manager）：
    dd ... of=/dev/sdX    → 拦截（危险）
    rm -rf /              → 拦截（危险）
    rm -rf /path          → 拦截（危险，除非用户明确要求）
    git clone            → git clone --depth 1 --single-branch
    npm install           → timeout 120s npm install --prefer-offline --no-audit --no-fund
    pip install           → timeout 90s pip install --quiet
    brew install          → timeout 180s brew install
    apt install           → timeout 120s apt install -y


────────────────────────────────────────────
命令审查清单（生成每条命令前自检）
────────────────────────────────────────────
生成命令后，对照以下问题检查：

[1] 这个命令会持续运行吗？（是 → 必须 nohup + & + 捕获 PID）
[2] 这个命令有最长等待时间吗？（是 → 必须用 timeout 包裹）
[3] 这个命令是纯前台立即返回吗？（是 → 直接执行，不加 &）
[4] 输出需要保存到日志吗？（是 → > file 2>&1）
[5] 这个命令在黑名单上吗？（是 → 拒绝执行，先问用户）
[6] 命令之间用了正确的分隔符吗？（; 表示顺序，&& 表示前一个成功，|| 表示前一个失败）
[7] cd 命令后面跟的是 && 还是 ; ？（; 会丢失 cd 效果，必须用 &&）
"""

if __name__ == "__main__":
    print(__doc__)
