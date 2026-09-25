#!/usr/bin/env python3
"""启动入口: 参数解析 + ThreadingHTTPServer。"""
import json, os, sys
from http.server import ThreadingHTTPServer

from svcdash.handler import Handler
from svcdash import procscan
from svcdash.config import DEFAULT_PORT, LISTEN_HOST
from svcdash.selftest import selftest


def main():
    args = sys.argv[1:]
    port = DEFAULT_PORT
    if "--port" in args:
        try:
            port = int(args[args.index("--port") + 1])
        except (ValueError, IndexError):
            print("用法: dashboard.py [--port N] [--scan] [--selftest]")
            return 2
    if "--scan" in args:
        print(json.dumps({"services": procscan.gather()}, ensure_ascii=False, indent=2))
        return 0
    if "--selftest" in args:
        return selftest()
    if "--export-static" in args:
        from svcdash.export import export_static
        try:
            out_dir = args[args.index("--export-static") + 1]
        except IndexError:
            print("错误: --export-static 需指定输出目录，如: dashboard.py --export-static ./dist")
            return 2
        cname = args[args.index("--cname") + 1] if "--cname" in args else None
        lang = args[args.index("--lang") + 1] if "--lang" in args else "zh"
        export_static(out_dir, lang=lang, cname=cname)
        print(f"[✓] 静态仪表盘已导出至: {os.path.abspath(out_dir)}")
        return 0
    if "--deploy-gh-pages" in args:
        from svcdash.export import deploy_gh_pages
        cname = args[args.index("--cname") + 1] if "--cname" in args else None
        lang = args[args.index("--lang") + 1] if "--lang" in args else "zh"
        return deploy_gh_pages(cname=cname, lang=lang)

    os.environ["SVC_PORT"] = str(port)   # svcctl 守卫用: 识别自身端口, 拒绝暂停自己
    httpd = ThreadingHTTPServer((LISTEN_HOST, port), Handler)
    httpd.daemon_threads = True
    print(f"svc-dashboard 已启动: http://0.0.0.0:{port}/  (Ctrl+C 退出)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0