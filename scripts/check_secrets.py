#!/usr/bin/env python3
"""敏感信息与 API 密钥检测 Hook (Git Secret Scanner & Privacy Guard).
可在本地 pre-commit / pre-push 以及 GitHub Actions CI 中自动化运行。
"""
import sys, os, re, subprocess, argparse

# 确保能导入 svcdash.privacy
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
try:
    from svcdash.privacy import SECRET_PATTERNS
except ImportError:
    SECRET_PATTERNS = [
        ("OpenAI API Key", re.compile(r'\b(sk-(?:proj-)?[A-Za-z0-9_-]{20,T3BlbkFJ[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9_-]{32,})\b')),
        ("Anthropic API Key", re.compile(r'\b(sk-ant-[A-Za-z0-9_-]{20,})\b')),
        ("GitHub Token", re.compile(r'\b(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,}|gho_[A-Za-z0-9]{30,})\b')),
        ("Google API Key", re.compile(r'\b(AIza[0-9A-Za-z-_]{35})\b')),
        ("AWS Access Key", re.compile(r'\b(AKIA[0-9A-Z]{16})\b')),
        ("HuggingFace Token", re.compile(r'\b(hf_[A-Za-z0-9]{30,})\b')),
        ("Private Key", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')),
    ]

# 允许忽略的文件（二进制、测试用的模式库、lock文件等）
IGNORE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf"}
IGNORE_FILES = {"svcdash/privacy.py", "scripts/check_secrets.py"}


def is_false_positive(val: str, line: str) -> bool:
    """过滤误报（代码中的占位符、注释、规则定义等）。"""
    v_lower = val.lower()
    l_lower = line.lower()
    if any(k in v_lower for k in ("example", "dummy", "sample", "redacted", "your_token", "placeholder")):
        return True
    if any(k in l_lower for k in ("re.compile", "pattern", "mock", "<your-key>", "xxx")):
        return True
    return False


def scan_text_lines(text: str, filename: str = "") -> list:
    """按行扫描文本内容，返回发现的敏感项 [(line_no, pattern_name, masked_snip, line_snippet)]"""
    findings = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, 1):
        for name, pat in SECRET_PATTERNS:
            if "Generic" in name:
                continue
            for m in pat.finditer(line):
                val = m.group(0)
                if not is_false_positive(val, line):
                    masked = val[:6] + "..." + val[-4:] if len(val) > 12 else val[:4] + "***"
                    findings.append((idx, name, masked, line.strip()[:100]))
    return findings


def scan_git_staged() -> int:
    """扫描即将提交的 Git 暂存区 (pre-commit 模式)。"""
    try:
        # 获取暂存区文件列表
        out = subprocess.check_output(["git", "diff", "--cached", "--name-only"], text=True)
        files = [f.strip() for f in out.splitlines() if f.strip()]
    except Exception as e:
        print(f"[!] 无法获取 git 暂存区: {e}")
        return 0

    all_findings = []
    for f in files:
        if f in IGNORE_FILES or any(f.endswith(ext) for ext in IGNORE_EXTS):
            continue
        try:
            # 读取暂存区实际内容
            content = subprocess.check_output(["git", "show", f":{f}"], text=True, errors="ignore")
            findings = scan_text_lines(content, f)
            for lineno, kind, snip, snippet in findings:
                all_findings.append((f, lineno, kind, snip, snippet))
        except Exception:
            pass

    return report_findings(all_findings, stage="pre-commit")


def scan_git_push() -> int:
    """扫描即将推送到远端的 commits (pre-push 模式)。"""
    try:
        # 检查待推送的变更
        out = subprocess.check_output(["git", "log", "@{u}..HEAD", "--name-only", "--oneline"], text=True)
        lines = out.splitlines()
        changed_files = set()
        for ln in lines:
            ln = ln.strip()
            if ln and not ln.startswith(("feat", "fix", "chore", "docs", "refactor", "test", "commit")):
                changed_files.add(ln)
    except Exception:
        # 若没有 upstream 或检测失败，回退为全仓库扫描
        return scan_all_tracked()

    all_findings = []
    for f in changed_files:
        if not os.path.isfile(f) or f in IGNORE_FILES or any(f.endswith(ext) for ext in IGNORE_EXTS):
            continue
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fp:
                findings = scan_text_lines(fp.read(), f)
                for lineno, kind, snip, snippet in findings:
                    all_findings.append((f, lineno, kind, snip, snippet))
        except Exception:
            pass

    return report_findings(all_findings, stage="pre-push")


def scan_all_tracked() -> int:
    """全仓库所有 tracked 文件扫描 (CI / 手动全量审计)。"""
    try:
        out = subprocess.check_output(["git", "ls-files"], text=True)
        files = [f.strip() for f in out.splitlines() if f.strip()]
    except Exception as e:
        print(f"[!] git ls-files 失败: {e}")
        return 0

    all_findings = []
    for f in files:
        if f in IGNORE_FILES or any(f.endswith(ext) for ext in IGNORE_EXTS) or not os.path.isfile(f):
            continue
        try:
            with open(f, "r", encoding="utf-8", errors="ignore") as fp:
                findings = scan_text_lines(fp.read(), f)
                for lineno, kind, snip, snippet in findings:
                    all_findings.append((f, lineno, kind, snip, snippet))
        except Exception:
            pass

    return report_findings(all_findings, stage="all-files")


def report_findings(findings: list, stage: str = "check") -> int:
    """统一格式化输出检测报告。"""
    if not findings:
        print(f"[\033[32m✓\033[0m] Secret Scan ({stage}): 未检测到任何 API 密钥或敏感凭据，安全通过。")
        return 0

    print(f"\n\033[31m{'='*65}\033[0m")
    print(f"\033[31m[!] 拦截警告：检测到 {len(findings)} 处疑似明文 API 密钥或高危敏感信息！\033[0m")
    print(f"\033[31m{'='*65}\033[0m")
    for f, lineno, kind, snip, snippet in findings:
        print(f"  • 文件: \033[33m{f}\033[0m:\033[36m{lineno}\033[0m")
        print(f"    类型: \033[35m{kind}\033[0m (指纹: {snip})")
        print(f"    代码: {snippet}")
        print()

    print("\033[31m[X] 安全门禁已阻止提交/推送！请移除上述敏感凭据后再试。\033[0m\n")
    return 1


def install_hooks():
    """一键安装 Git pre-commit 与 pre-push 钩子。"""
    git_dir = subprocess.check_output(["git", "rev-parse", "--git-dir"], text=True).strip()
    hooks_dir = os.path.join(git_dir, "hooks")
    os.makedirs(hooks_dir, exist_ok=True)

    hook_script = """#!/bin/sh
# Auto-generated by check_secrets.py
python3 scripts/check_secrets.py --staged
"""
    pre_commit_path = os.path.join(hooks_dir, "pre-commit")
    with open(pre_commit_path, "w", encoding="utf-8") as fp:
        fp.write(hook_script)
    os.chmod(pre_commit_path, 0o755)
    print(f"[✓] 已成功安装 pre-commit 钩子: {pre_commit_path}")

    push_script = """#!/bin/sh
# Auto-generated by check_secrets.py
python3 scripts/check_secrets.py --push
"""
    pre_push_path = os.path.join(hooks_dir, "pre-push")
    with open(pre_push_path, "w", encoding="utf-8") as fp:
        fp.write(push_script)
    os.chmod(pre_push_path, 0o755)
    print(f"[✓] 已成功安装 pre-push 钩子: {pre_push_path}")


def main():
    parser = argparse.ArgumentParser(description="Git Secret Scanner & Privacy Guard")
    parser.add_argument("--staged", action="store_true", help="扫描 git 暂存区 (pre-commit)")
    parser.add_argument("--push", action="store_true", help="扫描待 push 的 commits (pre-push)")
    parser.add_argument("--all", action="store_true", help="扫描全量 tracked 文件")
    parser.add_argument("--install-hooks", action="store_true", help="自动安装 Git hooks")
    parser.add_argument("--file", type=str, help="扫描单个指定文件")

    args = parser.parse_args()

    if args.install_hooks:
        install_hooks()
        return 0

    if args.staged:
        return scan_git_staged()
    elif args.push:
        return scan_git_push()
    elif args.file:
        if not os.path.isfile(args.file):
            print(f"[!] 文件不存在: {args.file}")
            return 1
        with open(args.file, "r", encoding="utf-8", errors="ignore") as fp:
            findings = scan_text_lines(fp.read(), args.file)
            return report_findings([(args.file, l, k, s, sn) for l, k, s, sn in findings], stage="file")
    else:
        return scan_all_tracked()


if __name__ == "__main__":
    sys.exit(main())
