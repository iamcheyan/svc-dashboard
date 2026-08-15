#!/usr/bin/env python3
"""启动入口: 参数解析 + ThreadingHTTPServer。"""
import json, sys
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

    httpd = ThreadingHTTPServer((LISTEN_HOST, port), Handler)
    httpd.daemon_threads = True
    print(f"svc-dashboard 已启动: http://0.0.0.0:{port}/  (Ctrl+C 退出)", flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0