#!/usr/bin/env python3
"""验证静态公开快照的脱敏是否真的有效（需求 #138 第 3 点）。

做法：用真实数据跑一遍 export_static 到临时目录，然后逐字节扫描产物，
断言里面找不到任何敏感特征（密钥、真实邮箱、内网/Tailscale IP、
个人家目录、电话）。命中只打印「文件 + 类别 + 行号」，绝不打印值。

用法：
    python3 scripts/verify_static_masking.py            # 真实导出并扫描
    python3 scripts/verify_static_masking.py --self-test # 只跑注入用例
退出码 0 = 全部通过；1 = 发现泄漏；2 = 导出失败。
"""
import argparse
import os
import re
import shutil
import sys
import tempfile
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT)

# 恶意/敏感特征：在公开产物里一个都不应出现。
LEAK_PATTERNS = [
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,}")),
    ("openai-key", re.compile(r"\bsk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{32,}")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("telegram-token", re.compile(r"\b\d{8,12}:[A-Za-z0-9_-]{30,}\b")),
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("private-ip", re.compile(r"(?<![\d.])(?:192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})(?![\d.])")),
    ("tailscale-ip", re.compile(r"(?<![\d.])100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3}(?![\d.])")),
    ("home-path", re.compile(r"/home/(?!user\b)[A-Za-z0-9_.-]+")),
    ("real-email", re.compile(r"\b[A-Za-z0-9._%+-]+@(?!example\.(?:com|org|net)\b)(?![A-Za-z0-9.-]*users\.noreply\.github\.com\b)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("real-phone", re.compile(r"(?<![\d.])(?:\+\d{1,3}[ -]?)?0\d{2,3}[ -]\d{3,4}[ -]\d{4}(?![\d.])")),
]

# 这些产物本来就是资源文件，不参与文本扫描。
SKIP_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".woff", ".woff2", ".ttf", ".otf", ".map"}


def scan_dir(root):
    """扫描目录下所有文本文件，返回 [(path, category, line)]。"""
    findings = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() in SKIP_EXTS:
                continue
            path = os.path.join(dirpath, fn)
            try:
                text = open(path, "r", encoding="utf-8", errors="ignore").read()
            except OSError:
                continue
            for category, pat in LEAK_PATTERNS:
                for m in pat.finditer(text):
                    line = text.count("\n", 0, m.start()) + 1
                    findings.append((os.path.relpath(path, root), category, line))
    return findings


def self_test():
    """注入已知敏感值，确认扫描器能抓到；再确认脱敏后抓不到。"""
    from svcdash.privacy import sanitize_text

    # 样例在运行时拼接，避免本文件被 pre-commit 的邮箱/电话规则误打码。
    planted = [
        "token gh" + "p_" + "A" * 36,
        "mail someone@" + "real-company.co.jp",
        "ip 192.168.3.82", "ts 100.76.219.104",
        "home /home/tetsuya/secret",
        "phone 090-" + "1234-5678",
    ]
    tmp = tempfile.mkdtemp(prefix="svc-mask-selftest-")
    try:
        open(os.path.join(tmp, "leak.html"), "w").write("\n".join(planted))
        found = scan_dir(tmp)
        cats = {c for _f, c, _l in found}
        missing = {"github-token", "real-email", "private-ip", "tailscale-ip",
                   "home-path", "real-phone"} - cats
        if missing:
            print(f"[X] 自检失败：扫描器漏检 {sorted(missing)}")
            return 1
        # 脱敏后应当全部消失
        masked = sanitize_text("\n".join(planted))
        open(os.path.join(tmp, "leak.html"), "w").write(masked)
        left = scan_dir(tmp)
        if left:
            print(f"[X] 自检失败：脱敏后仍有残留 {sorted({c for _f, c, _l in left})}")
            return 1
        print(f"[✓] 自检通过：注入的 {len(planted)} 类敏感特征全部被扫描器捕获，脱敏后归零。")
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--keep", action="store_true", help="保留导出目录用于排查")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    from svcdash.export import export_static

    out = tempfile.mkdtemp(prefix="svc-mask-export-")
    started = time.time()
    try:
        export_static(out, lang="zh", cname="svc.iamcheyan.com")
    except Exception as exc:
        print(f"[X] 导出失败: {type(exc).__name__}: {exc}")
        return 2
    elapsed = time.time() - started

    findings = scan_dir(out)
    files = sum(len(f) for _d, _s, f in os.walk(out))
    print(f"导出完成: {files} 个文件, {elapsed:.1f}s -> {out}")
    if not findings:
        print("[✓] 静态快照脱敏有效：未发现任何密钥/邮箱/内网 IP/家目录/电话泄漏。")
        if not args.keep:
            shutil.rmtree(out, ignore_errors=True)
        return 0

    print(f"[X] 发现 {len(findings)} 处潜在泄漏（仅显示位置，不显示值）：")
    seen = set()
    for path, category, line in findings:
        key = (path, category)
        if key in seen:
            continue
        seen.add(key)
        print(f"  • {path}:{line}  [{category}]")
    print(f"导出目录保留在 {out}，请排查。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
