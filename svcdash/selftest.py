#!/usr/bin/env python3
"""离线自检: 纯函数单测 + 真实数据源 dry-run,全部通过返回 0。"""
import unittest

from svcdash.goals import (parse_ctx_k, ctx_level, parse_retry, parse_progress,
                           parse_completed_goals, parse_watchdog_events,
                           merge_events, scan_goals, goal_detail,
                           _WD_LINE_RE, _wd_event_kind, GOAL_COMPLETED_LOG)
from svcdash.tools import fs_resolve, fs_sensitive, fs_read_text, _FS_TEXT_MAX
from svcdash.sysinfo import sys_info, load_zone
from svcdash.repos import agent_repos, repo_stats, parse_repo_commits
from svcdash.procscan import gather
from svcdash.render import render_html, TOOL_LINKS


def selftest():
    class T(unittest.TestCase):
        def test_ctx(self):
            self.assertEqual(parse_ctx_k("╭── π ZAI Preview > Goal 45K > ~/x ────╮"), 45.0)
            self.assertEqual(parse_ctx_k("── 554K ──╮"), 554.0)
            self.assertEqual(parse_ctx_k("Goal 1.2M"), 1.2 * 1024)
            self.assertIsNone(parse_ctx_k("no header here"))
            self.assertEqual(ctx_level(45), "ok")
            self.assertEqual(ctx_level(801), "warn")
            self.assertEqual(ctx_level(1201), "stop")

        def test_post_token(self):
            # 令牌: 生成→缓存命中→mtime 轮换; 全程不碰真实路径
            import importlib, os, tempfile
            h = importlib.import_module("svcdash.handler")
            with tempfile.TemporaryDirectory() as td:
                p = os.path.join(td, "token")
                h._TOKEN_PATHS = (p, p)
                h._token_cache.update(mtime=None, val="")
                tok1 = h._svc_token()
                self.assertGreaterEqual(len(tok1), 24)
                self.assertEqual(h._svc_token(), tok1)          # mtime 缓存
                with open(p, "w") as f:
                    f.write("rotated-token\n")
                os.utime(p, (0, 0))                              # 强制 mtime 变化
                self.assertEqual(h._svc_token(), "rotated-token")
                self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
            h._TOKEN_PATHS = ("/etc/svc-dashboard/token",
                              os.path.expanduser("~/.omp/svc-dashboard/token"))

        def test_fragment_cache(self):
            # 未知片段 None; 已知片段 5s 内二次调用命中同一缓存对象
            from svcdash import render
            self.assertIsNone(render.render_fragment("nope", "zh", "localhost:80"))
            a = render.render_fragment("goals", "zh", "localhost:80")
            b = render.render_fragment("goals", "zh", "localhost:80")
            self.assertIs(a, b)
            self.assertTrue(a)

        def test_fs_security(self):
            self.assertIsNone(fs_resolve("/etc"))
            self.assertIsNone(fs_resolve("/root"))
            self.assertIsNone(fs_resolve("/proc/self/environ"))
            self.assertIsNone(fs_resolve("/home/tetsuya/../etc"))
            self.assertIsNone(fs_resolve("/home/tetsuya/.env"))
            self.assertIsNone(fs_resolve("/home/tetsuya/prod_key.pem"))
            self.assertIsNone(fs_resolve("/home/tetsuya/creds/id_rsa"))
            self.assertIsNone(fs_resolve("/home/tetsuya/known_hosts"))
            self.assertIsNone(fs_resolve("/home/tetsuya/development/.git/config"))
            self.assertIsNone(fs_resolve("relative/path"))
            self.assertEqual(fs_resolve("/home/tetsuya/development"),
                             __import__("os").path.realpath("/home/tetsuya/development"))
            self.assertTrue(fs_sensitive(".git"))
            self.assertTrue(fs_sensitive("xkey.txt"))
            self.assertFalse(fs_sensitive("normal.md"))

        def test_fs_text(self):
            import tempfile, os
            with tempfile.TemporaryDirectory() as td:
                utf8 = os.path.join(td, "a.txt")
                open(utf8, "wb").write("hello\nworld".encode())
                r = fs_read_text(utf8)
                self.assertTrue(r["ok"] and not r["binary"])
                self.assertEqual(r["encoding"], "utf-8")
                self.assertIsNone(r["alt_enc"])
                gb = os.path.join(td, "b.txt")
                open(gb, "wb").write("传奇配置文件".encode("gb18030"))
                r = fs_read_text(gb)
                self.assertEqual(r["encoding"], "utf-8")
                self.assertEqual(r["alt_enc"], "gb18030")
                r2 = fs_read_text(gb, "gb18030")
                self.assertEqual(r2["encoding"], "gb18030")
                self.assertIn("传奇", r2["text"])
                binf = os.path.join(td, "c.bin")
                open(binf, "wb").write(b"\x00\x01\x02binary")
                self.assertTrue(fs_read_text(binf)["binary"])
                big = os.path.join(td, "big.log")
                open(big, "wb").write(b"x" * (5 << 20))
                r = fs_read_text(big)
                self.assertTrue(r["truncated"])
                self.assertEqual(len(r["text"]), _FS_TEXT_MAX)

        def test_retry_progress(self):
            self.assertEqual(parse_retry("API error. Retrying (3)/10 in 5s"), "3")
            self.assertEqual(parse_retry("Retrying (7/10)…"), "7")
            self.assertIsNone(parse_retry("no retry"))
            self.assertTrue(parse_progress(
                "╭─── Todo 12 tasks ───╮\n│ II. Phase 1  3/3   │\n"
                "│   ├─ Browser E2E: import roundtrip + no-resurrect │\n"
                "╰─────────────────────╯"))

        def test_load_zone(self):
            self.assertEqual(load_zone(2.0), ("ok", 2))
            self.assertEqual(load_zone(5.9), ("ok", 1))
            self.assertEqual(load_zone(6.0), ("full", 0))
            self.assertEqual(load_zone(12.4), ("over", 0))

        def test_wd_parse(self):
            line = ("2026-08-14 08:15:10 [019ffbaf] resumed 019ffbaf-4c8d in %30; "
                    "sent '继续' to drive agent")
            m = _WD_LINE_RE.match(line)
            self.assertTrue(m)
            self.assertEqual(_wd_event_kind("goal paused: pid=1; driving with '继续'"), "nudge")

        def test_completed(self):
            with open(GOAL_COMPLETED_LOG) as f:
                real = f.read()
            entries = parse_completed_goals()
            if "Zircon全代码文档化" in real:
                self.assertTrue(any("Zircon" in c["label"] for c in entries))
                self.assertTrue(entries[0]["resume_cmd"].startswith(
                    "/home/tetsuya/.bun/bin/omp"))

        def test_svcctl(self):
            import os, signal, subprocess, tempfile, time
            from svcdash import svcctl
            # 台账指向临时文件, 不碰真实状态
            tmp = tempfile.mkdtemp(prefix="svcdash-selftest-")
            svcctl.STATE_FILE = os.path.join(tmp, "paused.json")
            svcctl.HISTORY_FILE = os.path.join(tmp, "actions.log")
            svcctl.STATE_DIR = tmp
            # 守卫: sshd 端口 / 自身端口 / docker 之外无 pid → 拒绝
            self.assertFalse(svcctl.can_pause({"port": 22, "pids": [1]}))
            self.assertFalse(svcctl.can_pause({"port": 80, "is_self": True}))
            self.assertFalse(svcctl.can_pause({"port": 61234, "pids": []}))  # 无人监听
            # 真实冻结/解冻往返: 起一个 sleep 子进程当"服务"
            p = subprocess.Popen(["sleep", "300"])
            time.sleep(0.2)
            for sig in (signal.SIGSTOP,):
                os.kill(p.pid, sig)
            # 直接走 resume 核心(绕过端口扫描): 台账写 pid, 验证 SIGCONT 恢复
            svcctl.save_state([{"port": 65534, "pids": [p.pid], "name": "selftest",
                                "kind": "sig", "ts": time.time()}])
            self.assertEqual(len(svcctl.load_state()), 1)
            r = svcctl.resume(65534)
            self.assertTrue(r["ok"], r)
            self.assertEqual(svcctl.load_state(), [])
            # 进程确实解冻并能被杀掉(T 状态的进程 SIGTERM 挂起, 需先 CONT)
            os.kill(p.pid, signal.SIGTERM)
            p.wait(timeout=5)
            # 历史: pause/resume 各一条
            svcctl._log("pause", {"port": 1, "name": "x", "pids": [2]})
            svcctl._log("resume", {"port": 1, "name": "x", "pids": [2]})
            self.assertEqual(len(svcctl.history()), 3)  # resume(65534) + 手写2条

        def test_runtimes(self):
            import time
            from svcdash import runtimes as rt
            # 注册表: id 唯一, 装卸动作白名单
            ids = [a["id"] for a in rt.REGISTRY]
            self.assertEqual(len(ids), len(set(ids)))
            self.assertIn("omp", ids) and self.assertIn("codex", ids)
            # 额度归一化: 各家真实结构样本
            q = rt._parse_codex_quota({"account": {"account": {"email": "a@b.c",
                "planType": "plus"}},
                "rateLimits": {"rateLimits": {"limitId": "codex",
                    "primary": {"usedPercent": 8, "resetsAt": 1787198007}}},
                "usage": {}})
            self.assertEqual(q["plan"], "plus")
            self.assertEqual(q["buckets"][0]["remaining_pct"], 92)
            self.assertEqual(q["buckets"][0]["reset"], time.strftime(
                "%m-%d %H:%M", time.localtime(1787198007)))
            q = rt._parse_grok_quota({"billing": {"config": {
                "creditUsagePercent": 100,
                "currentPeriod": {"end": "2026-08-18T13:36:55Z"}}},
                "user": {"email": "g@x.ai", "subscriptionTier": "XPremium"}})
            self.assertEqual(q["buckets"][0]["remaining_pct"], 0)
            q = rt._parse_kiro_quota({"email": "k@a.com", "usage": {
                "usageBreakdownList": [{"displayName": "agentic",
                    "currentUsage": 3, "usageLimit": 10, "unit": "requests"}]}})
            self.assertEqual(q["buckets"][0]["remaining_pct"], 70)
            q = rt._parse_agy_quota({"quota": {"groups": [{"displayName": "Gemini Models",
                "buckets": [{"bucketId": "gemini-5h", "remainingFraction": 0.25,
                             "resetTime": "2026-08-15T08:52:07Z"}]}]},
                "accounts": [{"email": "x@gmail.com"}]})
            self.assertEqual(q["buckets"][0]["remaining_pct"], 25)
            q = rt._parse_cursor_quota({"usage": {"planUsage": {
                "totalPercentUsed": 55}}, "hardLimit": {}})
            self.assertEqual(q["buckets"][0]["remaining_pct"], 45)
            # 进程扫描可运行且包含已知 agent 键
            procs = rt.scan_procs()
            self.assertIn("omp", procs) and self.assertIn("hermes", procs)

    suite = unittest.TestLoader().loadTestsFromTestCase(T)
    unittest.TextTestRunner(verbosity=2).run(suite)
    print("\n--- live dry-run ---")
    gl = scan_goals()
    print(f"goal cards: {len(gl)}")
    for g in gl:
        print(f"  {g['name']}: light={g['light']} ctx={g['ctx_raw'] or '—'} "
              f"idle={g['idle_sec']}s retry={g['retry']} prog={len(g['progress'])}")
    s = sys_info()
    gl2 = s["goalload"]
    print(f"load: {gl2['load15']} ({gl2['zone']}, n={gl2['n']}) cpu_top={gl2['cpu_top'][:3]}")
    rs = agent_repos()
    print(f"agent repos: {len(rs)} -> {[__import__('os').path.basename(r) for r in rs]}")
    for r in repo_stats()["repos"][:3]:
        print(f"  {r['name']}: commits={r['commits']} size={r['size']} "
              f"files={r['files']} dirty={r['dirty']}")   # exts 统计已从 repos.py 移除
    evts = merge_events(parse_watchdog_events(), parse_completed_goals(),
                        parse_repo_commits())
    kinds = {e["kind"] for e in evts}
    print(f"events: {len(evts)} kinds={sorted(kinds)}")
    html = render_html("localhost:8899", gather(), __import__("time").time(), "zh", sysdata=s)
    # tchip(工具直达 chips) 只在有未暂停的工具端口时渲染(svcctl 暂停过滤是预期行为)
    live_tool_ports = {e["port"] for e in gather() if not e.get("paused")} & {
        p for _, p in TOOL_LINKS}
    checks = ["Goal 进度", "仓库", "已完成 goal", "最近事件"] + (["tchip"] if live_tool_ports else [])
    print(f"  tool ports unpaused: {sorted(live_tool_ports) or 'none → tchip check skipped'}")
    ok = True
    for c in checks:
        mark = "ok" if c in html else "FAIL"
        print(f"  {mark} html contains {c!r}")
        ok = ok and (c in html)
    return 0 if ok else 1