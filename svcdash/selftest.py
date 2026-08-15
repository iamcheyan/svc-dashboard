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
from svcdash.render import render_html


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
              f"files={r['files']} dirty={r['dirty']} exts={r['exts'][:3]}")
    evts = merge_events(parse_watchdog_events(), parse_completed_goals(),
                        parse_repo_commits())
    kinds = {e["kind"] for e in evts}
    print(f"events: {len(evts)} kinds={sorted(kinds)}")
    html = render_html("localhost:8899", gather(), __import__("time").time(), "zh", sysdata=s)
    checks = ["Goal 进度", "仓库", "已完成 goal", "最近事件", "tchip"]
    ok = True
    for c in checks:
        mark = "ok" if c in html else "FAIL"
        print(f"  {mark} html contains {c!r}")
        ok = ok and (c in html)
    return 0 if ok else 1