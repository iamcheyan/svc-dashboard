#!/usr/bin/env python3
"""敏感信息与 API 密钥检测 Hook (Git Secret Scanner & Privacy Guard).
可在本地 pre-commit / pre-push 以及 GitHub Actions CI 中自动化运行。
"""
import sys, os, re, subprocess, argparse

# 确保能导入 svcdash.privacy
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
try:
    from svcdash.privacy import SECRET_PATTERNS, _secret_assignment_is_credential
except ImportError as exc:
    print(f"[!] 无法加载统一凭据扫描规则，拒绝继续: {exc}", file=sys.stderr)
    sys.exit(2)

# 允许忽略的文件（二进制、测试用的模式库、lock文件等）
IGNORE_EXTS = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".woff", ".woff2", ".ttf"}
IGNORE_FILES = {"svcdash/privacy.py", "scripts/check_secrets.py"}


# 代码/配置类文件：自动打码只处理凭据、邮箱、电话。
# 不能把 /home/xxx、内网 IP 在本文件里就地打码——那会改写可执行字符串
# 常量（如 _DEVELOPMENT_ROOT、PVE_URL 默认值）并静默改坏服务。
# 这类文件只报告位置，由人决定删除或改成环境变量。
CODE_EXTS = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".go", ".rs",
    ".sh", ".bash", ".zsh", ".fish", ".c", ".h", ".cc", ".cpp", ".hpp",
    ".java", ".kt", ".rb", ".php", ".lua", ".sql", ".toml", ".yaml", ".yml",
}


def redact_text(text: str, mask_infra: bool = True) -> tuple[str, int]:
    """把命中的敏感内容就地替换成 ******，返回 (新文本, 命中数)。

    需求 #138：提交时不再阻断，而是直接把敏感值处理成 ******，
    宁可误杀。仅处理文本，二进制/忽略文件不碰。

    mask_infra=False 时只打码凭据/邮箱/电话，不动内网 IP 与家目录
    （用于代码与配置文件，避免把路径常量、默认地址改坏）。
    """
    from svcdash.privacy import (
        SECRET_PATTERNS, _secret_assignment_is_credential, MASK,
        PRIVATE_IP_RE, TAILSCALE_IP_RE, HOME_DIR_RE, EMAIL_RE, PHONE_RE,
    )
    out = text
    hits = 0

    for name, pat in SECRET_PATTERNS:
        def repl(match):
            nonlocal hits
            if name in ("Secret Assignment", "Generic Secret Arg"):
                if not _secret_assignment_is_credential(match.group(3), match.group(2)):
                    return match.group(0)
                hits += 1
                return match.group(1) + match.group(2) + MASK + match.group(2)
            if name == "Generic Secret Key-Val":
                hits += 1
                return match.group(1) + MASK + match.group(3)
            hits += 1
            return MASK
        out = pat.sub(repl, out)

    if mask_infra:
        # 文档/清单类：内网/Tailscale IP 与个人家目录直接打码。
        out, n1 = PRIVATE_IP_RE.subn(MASK, out)
        out, n2 = TAILSCALE_IP_RE.subn(MASK, out)
        out, n3 = HOME_DIR_RE.subn(MASK, out)
        hits += n1 + n2 + n3

    # 邮箱/电话：不公开真实联系方式；示例域名与 noreply 保留（降低误杀）。
    SAFE_MAIL = ("example.com", "example.org", "example.net",
                 "users.noreply.github.com")

    def mask_mail(match):
        nonlocal hits
        addr = match.group(0)
        dom = addr.rsplit("@", 1)[-1].lower()
        if dom in SAFE_MAIL or dom.endswith(".example"):
            return addr
        hits += 1
        return MASK

    out = EMAIL_RE.sub(mask_mail, out)
    out, n4 = PHONE_RE.subn(MASK, out)
    hits += n4
    return out, hits


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
    """Scan whole text, including multiline credentials; results never include raw lines."""
    findings = []
    if not isinstance(text, str):
        return findings
    for name, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(3) if name in ("Secret Assignment", "Generic Secret Arg") else match.group(0)
            if name in ("Secret Assignment", "Generic Secret Arg") and not _secret_assignment_is_credential(value, match.group(2), filename):
                continue
            line_no = text.count("\n", 0, match.start()) + 1
            if not is_false_positive(value, ""):
                findings.append((line_no, name, "[redacted]", "[内容已隐藏]"))
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
    """Scan every outgoing commit's files and messages, not only the worktree tip."""
    try:
        commits = subprocess.check_output(
            ["git", "rev-list", "--reverse", "@{u}..HEAD"], text=True
        ).splitlines()
    except Exception:
        return scan_all_tracked()

    all_findings = []
    for commit in commits:
        try:
            paths = subprocess.check_output(
                ["git", "diff-tree", "--root", "--no-commit-id", "--name-only", "-r", commit],
                text=True,
            ).splitlines()
            message = subprocess.check_output(
                ["git", "show", "-s", "--format=%B", commit], text=True, errors="ignore"
            )
            for lineno, kind, snip, snippet in scan_text_lines(message):
                all_findings.append((f"commit:{commit[:12]}", lineno, kind, snip, snippet))
        except Exception:
            return 1

        for path in paths:
            if not path or path in IGNORE_FILES or any(path.endswith(ext) for ext in IGNORE_EXTS):
                continue
            try:
                blob = subprocess.check_output(
                    ["git", "show", f"{commit}:{path}"], stderr=subprocess.DEVNULL
                )
                if b"\0" in blob[:8192]:
                    continue
                content = blob.decode("utf-8", "ignore")
                for lineno, kind, snip, snippet in scan_text_lines(content, path):
                    all_findings.append((path, lineno, kind, snip, snippet))
            except subprocess.CalledProcessError:
                # Deleted paths have no blob in this commit.
                continue

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


def fix_staged() -> int:
    """把暂存区里命中的敏感值改写成 ******，并重新 add。

    需求 #138：commit 时直接打码，不阻断提交。工作区文件同步改写，
    保证 index 与工作区一致。
    """
    try:
        out = subprocess.check_output(["git", "diff", "--cached", "--name-only"], text=True)
        files = [f.strip() for f in out.splitlines() if f.strip()]
    except Exception as e:
        print(f"[!] 无法获取 git 暂存区: {e}")
        return 0

    touched = []
    for f in files:
        if f in IGNORE_FILES or any(f.endswith(ext) for ext in IGNORE_EXTS):
            continue
        try:
            blob = subprocess.check_output(["git", "show", f":{f}"], stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError:
            continue
        if b"\0" in blob[:8192]:
            continue
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError:
            continue
        ext = os.path.splitext(f)[1].lower()
        new_text, hits = redact_text(text, mask_infra=ext not in CODE_EXTS)
        if not hits or new_text == text:
            continue
        try:
            with open(f, "w", encoding="utf-8") as fp:
                fp.write(new_text)
            subprocess.check_call(["git", "add", "--", f])
            touched.append((f, hits))
        except Exception as e:
            print(f"[!] 打码失败 {f}: {e}")

    if touched:
        print("\033[33m[~] 已自动打码敏感内容为 ******：\033[0m")
        for f, n in touched:
            print(f"  • {f}  ({n} 处)")
        print("  请检查上述文件是否符合预期（可能误杀）。")
        return 0
    print("[\033[32m✓\033[0m] 暂存区无需打码。")
    return 0


def fix_commit_message(path: str) -> int:
    """把 commit message 文件里的敏感值改写成 ******。"""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fp:
            text = fp.read()
    except OSError:
        return 0
    # commit message 是纯文本，内网 IP/路径一并打码。
    new_text, hits = redact_text(text, mask_infra=True)
    if hits and new_text != text:
        with open(path, "w", encoding="utf-8") as fp:
            fp.write(new_text)
        print(f"\033[33m[~] commit message 已打码 {hits} 处敏感内容。\033[0m")
    return 0


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
# 需求 #138: 提交时直接把敏感值打码成 ******，而不是阻断提交。
python3 scripts/check_secrets.py --staged --fix
"""
    pre_commit_path = os.path.join(hooks_dir, "pre-commit")
    with open(pre_commit_path, "w", encoding="utf-8") as fp:
        fp.write(hook_script)
    os.chmod(pre_commit_path, 0o755)
    print(f"[✓] 已成功安装 pre-commit 钩子: {pre_commit_path}")

    msg_script = """#!/bin/sh
# Auto-generated by check_secrets.py
python3 scripts/check_secrets.py --commit-msg "$1"
"""
    commit_msg_path = os.path.join(hooks_dir, "commit-msg")
    with open(commit_msg_path, "w", encoding="utf-8") as fp:
        fp.write(msg_script)
    os.chmod(commit_msg_path, 0o755)
    print(f"[✓] 已成功安装 commit-msg 钩子: {commit_msg_path}")

    push_script = """#!/bin/sh
# Auto-generated by check_secrets.py
# 推送无法安全改写历史，命中即阻断（fail closed）。
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
    parser.add_argument("--fix", action="store_true", help="把命中的敏感值打码为 ****** 并重新 add")
    parser.add_argument("--commit-msg", type=str, help="就地打码 commit message 文件")
    parser.add_argument("--push", action="store_true", help="扫描待 push 的 commits (pre-push)")
    parser.add_argument("--all", action="store_true", help="扫描全量 tracked 文件")
    parser.add_argument("--install-hooks", action="store_true", help="自动安装 Git hooks")
    parser.add_argument("--file", type=str, help="扫描单个指定文件")

    args = parser.parse_args()

    if args.install_hooks:
        install_hooks()
        return 0

    if args.commit_msg:
        return fix_commit_message(args.commit_msg)

    if args.staged and args.fix:
        return fix_staged()

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
