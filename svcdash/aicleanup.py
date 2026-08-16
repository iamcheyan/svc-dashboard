# aicleanup.py — 一键智能清理: spawn omp agent 按描述词分析并清理本机资源
#
# 设计 (用户拍板): 不写死清理规则, 每次点击都调一个 omp agent, 给它一段固定
# 描述词, 让它像人工一样先调查再动手 (识别孤儿渲染进程/遗留浏览器/陈旧缓存/
# 高 CPU 自旋), 护住 goal 任务与基础服务。
#
# API:
#   aicleanup_start()  -> (ok, msg)  幂等: 已在跑则拒绝
#   aicleanup_status() -> {status, started, pid, log_path, result}
#
# 实现: ThreadingHTTPServer 是多线程的, 直接 threading.Thread + subprocess
# 跑 `omp -p --no-session`, 输出落 /tmp/svcdash-aiclean.log, 状态存模块级。

import os
import subprocess
import threading
import time

_OMP = "/home/tetsuya/.bun/bin/omp"
_LOG = "/tmp/svcdash-aiclean.log"
_LOCK = threading.Lock()
_STATE = {"status": "idle", "started": 0.0, "pid": None}
MAX_RUN_S = 900  # 15 分钟兜底, 防止 agent 永挂

# 描述词: 每次点击原样发给 agent。保护集 + 授权集 + 汇报要求。
PROMPT = """你是本机(NAS 服务器, Debian 13)的清理管家, 由 svc-dashboard 一键清理按钮调起。
任务: 把被无关进程/服务/临时文件占用的 CPU、内存、磁盘清出来, 给正在跑的 goal 任务让路。

【绝对保护 — 碰了就是事故】
- Docker 全部容器与 docker daemon (Immich 是生产数据)
- systemd 基础服务: tailscaled, xrdp, ssh*, smbd, earlyoom, low-memory-monitor
- goal 任务: tmux 会话 e5-data / e6-fix 里的 omp 进程, goal_watchdog cron, tmux 会话 zircon
- svc-dashboard 自己 (dashboard.py / :80)
- /data 下 Immich 相关挂载 (immich/Photos) 与 ~/immich/postgres
- 不重启机器, 不停基础服务, 不删 docker volume

【调查步骤 — 像人工一样先查再动】
1. ps aux --sort=-%cpu 和 -rss 找高耗进程; 每个可疑进程先 readlink /proc/<pid>/cwd 和 cat /proc/<pid>/cmdline 确认归属
2. 区分: goal 任务的子进程(mapviewer/webclient 等被 goal 正在用的调试服务保留) vs 孤儿(如 mapviewer 预热 worker: 主进程已死或 CPU 满载但服务已重启)
3. ~/.cache 下的 magiclab-chrome-* / *-chrome-profile 一次性浏览器 profile
4. /tmp 与 /data/NAS/TMP/mir3-mapviewer-cache 的陈旧缓存(注意版本 hash 子目录, 只删非活跃代且 mtime 超 12h)
5. 大文件: du 扫 /tmp ~/.cache, 超 100M 的临时产物列入候选

【动手规则】
- 杀进程: 只杀第 2 类孤儿; kill 前在输出里写明 pid/cmdline/理由; kill 后复查
- 删文件: 只删第 3/4 类; 单个 >1G 的目录删除前先 du 确认内容与预期一致
- 每一步动作后立即报告释放了多少 (对比 free -h / df -h)
- 拿不准归属的进程/文件: 跳过并在报告里说明, 不猜

【输出格式】最终回复必须是:
## 清理报告
- 已停止: <pid/进程名, 理由, 释放内存>
- 已删除: <路径, 大小>
- 跳过(拿不准): <项, 原因>
- 资源对比: 清理前/后 free 与 df 摘要
"""


def _work():
    os.makedirs(os.path.dirname(_LOG), exist_ok=True)
    with open(_LOG, "ab") as f:
        f.write(f"\n===== aiclean start {time.strftime('%F %T')} =====\n".encode())
        f.flush()
        try:
            p = subprocess.Popen(
                [_OMP, "-p", "--no-session", "--auto-approve", PROMPT],
                stdout=f, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                cwd="/home/tetsuya", start_new_session=True,
                env={**os.environ, "HOME": "/home/tetsuya",
                     "PATH": "/home/tetsuya/.bun/bin:" + os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin")})
            with _LOCK:
                _STATE["pid"] = p.pid
            p.wait(timeout=MAX_RUN_S)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            p.kill()
            rc = -9
        except Exception as e:
            f.write(f"[aiclean] spawn failed: {e}\n".encode())
            rc = -1
        f.write(f"[aiclean] done rc={rc} {time.strftime('%F %T')}\n".encode())
    with _LOCK:
        _STATE.update(status="idle" if rc == 0 else "error", pid=None)


def aicleanup_start():
    with _LOCK:
        if _STATE["status"] == "running":
            return False, f"busy: 已有清理在跑 (started {time.strftime('%H:%M:%S', time.localtime(_STATE['started']))})"
        _STATE.update(status="running", started=time.time(), pid=None)
    threading.Thread(target=_work, daemon=True).start()
    return True, "cleanup agent started"


def aicleanup_status():
    with _LOCK:
        st = dict(_STATE)
    if st["status"] == "running":
        st["elapsed_s"] = int(time.time() - st["started"])
    try:
        with open(_LOG, "rb") as f:
            f.seek(max(0, os.fstat(f.fileno()).st_size - 8192))
            st["log_tail"] = f.read().decode("utf-8", "replace")
    except OSError:
        st["log_tail"] = ""
    return st
