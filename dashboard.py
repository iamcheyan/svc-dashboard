#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""svc-dashboard 入口(薄): 后端逻辑在 svcdash/ 包, 前端在 static/。
纯标准库零依赖: python3 dashboard.py [--port N] [--scan] [--selftest]"""
import sys
from svcdash.main import main

if __name__ == "__main__":
    sys.exit(main())