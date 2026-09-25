#!/usr/bin/env python3
"""敏感信息脱敏与安全扫描引擎 (Privacy & Secret Protection Engine).
提供全面的 API 密钥、个人身份路径、内网与 Tailscale IP、终端对话输出的深度脱敏与审计。
"""
import re, os, hashlib

# 常见 API 密钥与凭证正则特征库
SECRET_PATTERNS = [
    ("OpenAI API Key", re.compile(r'\b(sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,T3BlbkFJ[A-Za-z0-9_-]{20,}|sk-(?!ant-)[A-Za-z0-9_-]{32,})\b')),
    ("Anthropic API Key", re.compile(r'\b(sk-ant-[A-Za-z0-9_-]{20,})\b')),
    ("GitHub Token", re.compile(r'\b(ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,}|gho_[A-Za-z0-9]{30,})\b')),
    ("Google API Key", re.compile(r'\b(AIza[0-9A-Za-z-_]{35})\b')),
    ("AWS Access Key", re.compile(r'\b(AKIA[0-9A-Z]{16})\b')),
    ("HuggingFace Token", re.compile(r'\b(hf_[A-Za-z0-9]{30,})\b')),
    ("Private Key", re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----')),
    ("JWT / Bearer Token", re.compile(r'\b(?:Bearer\s+|ey)[A-Za-z0-9_-]{25,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b')),
    ("Generic Secret Arg", re.compile(r'(?i)(--?(?:api[_-]?key|secret|token|password|auth|passwd)[=\s]+)(["\']?)([^"\'\s]{6,})\2')),
    ("Generic Secret Key-Val", re.compile(r'(?i)("(?:api[_-]?key|secret|token|password|auth|passwd)"\s*:\s*")([^"\\]{6,})(")')),
]

# 私有 IP 地址特征
PRIVATE_IP_RE = re.compile(r'\b(192\.168\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b')
TAILSCALE_IP_RE = re.compile(r'\b(100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3}\.\d{1,3})\b')

# 个人家目录路径特征 (如 /home/tetsuya -> ~)
HOME_DIR_RE = re.compile(r'/home/[a-zA-Z0-9_.-]+')
HOME_REL_RE = re.compile(r'~(?:/[^\s/]+)+')

# 静态公网版的第二层隐私边界：凭据/IP 脱敏并不等于对话内容安全。
# 这些字段通常包含用户原话、内部项目上下文、命令或可复现操作。
PUBLIC_CONTENT_KEYS = frozenset({
    "title", "objective", "transcript", "text", "subject",
    "command", "cmd", "cmdline", "resume_cmd", "attach_cmd",
    "label", "repo", "branch",
})
PUBLIC_PATH_KEYS = frozenset({"cwd", "workdir", "path"})


def _public_session_id(value):
    """为公网视图生成稳定但不可读的会话标识。"""
    digest = hashlib.sha256(str(value).encode("utf-8", "replace")).hexdigest()[:8]
    return f"session-{digest}"


def sanitize_public_payload(data):
    """清除静态公网版中的对话/日志/命令语义，同时保留结构和统计字段。"""
    if isinstance(data, dict):
        clean = {}
        for key, value in data.items():
            key_lower = str(key).lower()
            if key_lower in PUBLIC_CONTENT_KEYS:
                clean[key] = "[内容已脱敏]"
            elif key_lower in PUBLIC_PATH_KEYS:
                clean[key] = "[路径已脱敏]"
            elif key_lower in ("session", "session_name", "tmux") and value:
                clean[key] = _public_session_id(value)
            else:
                clean[key] = sanitize_public_payload(value)
        return clean
    if isinstance(data, list):
        return [sanitize_public_payload(item) for item in data]
    if isinstance(data, str):
        # 兜底处理未被字段名识别的 home 路径和 URL。
        value = HOME_REL_RE.sub("[路径已脱敏]", data)
        value = re.sub(r'https?://[^\s<>"\']+', "[链接已脱敏]", value)
        return sanitize_text(value, mask_ips=True, mask_paths=True)
    return data


def mask_secret(text: str) -> str:
    """对字符串执行全局 API 密钥与凭证脱敏。"""
    if not isinstance(text, str):
        return text

    out = text
    # 1. 明确匹配已知 API 密钥
    for name, pat in SECRET_PATTERNS:
        if name == "Generic Secret Arg":
            out = pat.sub(r'\1\2***REDACTED***\2', out)
        elif name == "Generic Secret Key-Val":
            out = pat.sub(r'\1***REDACTED***\3', out)
        else:
            out = pat.sub(r'[REDACTED_SECRET]', out)

    return out


def sanitize_text(text: str, mask_ips: bool = True, mask_paths: bool = True) -> str:
    """深度脱敏单个字符串（包含密钥、IP、私有家目录）。"""
    if not isinstance(text, str):
        return text

    out = mask_secret(text)

    if mask_paths:
        out = HOME_DIR_RE.sub("~", out)

    if mask_ips:
        out = PRIVATE_IP_RE.sub("192.168.*.*", out)
        out = TAILSCALE_IP_RE.sub("100.*.*.*", out)

    return out


def deep_sanitize(data, mask_ips: bool = True, mask_paths: bool = True):
    """递归脱敏数据结构（dict / list / str）。"""
    if isinstance(data, dict):
        new_d = {}
        for k, v in data.items():
            # 特殊敏感字段直接置空或脱敏
            if k in ("has_key", "key_present"):
                new_d[k] = False
            elif any(s in k.lower() for s in ("token", "password", "secret", "private_key")):
                new_d[k] = "***REDACTED***"
            else:
                new_d[k] = deep_sanitize(v, mask_ips=mask_ips, mask_paths=mask_paths)
        return new_d
    elif isinstance(data, list):
        return [deep_sanitize(item, mask_ips=mask_ips, mask_paths=mask_paths) for item in data]
    elif isinstance(data, str):
        return sanitize_text(data, mask_ips=mask_ips, mask_paths=mask_paths)
    return data


def sanitize_tmux_for_public(tmux_data: dict) -> dict:
    """对 Tmux 会话数据进行公网安全脱敏。
    核心安全红线：彻底清除/屏蔽实际终端输出 (preview)，防止命令回显与对话敏感信息泄露！
    """
    if not isinstance(tmux_data, dict):
        return {}

    clean = deep_sanitize(tmux_data, mask_ips=True, mask_paths=True)

    # 彻底清洗 sessions 内的 panes
    sessions = clean.get("sessions") or []
    for s in sessions:
        # 会话名称脱敏
        if s.get("name"):
            s["name"] = _public_session_id(s["name"])
        for w in s.get("windows") or []:
            for p in w.get("panes") or []:
                # 终端输出: 公网只读模式下完全屏蔽终端捕获文本
                p["preview"] = [" [公网只读视图：终端屏幕输出已安全屏蔽] "]
                if p.get("cwd"):
                    p["cwd"] = HOME_DIR_RE.sub("~", p["cwd"])
                if p.get("command"):
                    p["command"] = sanitize_text(p["command"])

    # 清洗 watchdog 关联的 resume 命令与目标
    for s in sessions:
        if s.get("goal"):
            g = s["goal"]
            if g.get("resume_cmd"):
                g["resume_cmd"] = "omp --resume [ID] (公网已脱敏)"
            if g.get("workdir"):
                g["workdir"] = HOME_DIR_RE.sub("~", g["workdir"])
            if g.get("objective"):
                g["objective"] = sanitize_text(g["objective"])

    return clean


def sanitize_services_for_public(services: list) -> list:
    """对服务列表进行公网安全脱敏。"""
    out = []
    for s in services or []:
        svc = dict(s)
        # 公网服务页只展示服务/端口/资源，不把可复制的启动命令和工作目录带出去。
        svc["cmdline"] = "[命令已隐藏]"
        svc["cwd"] = "[路径已隐藏]" if svc.get("cwd") else None
        # 对 IP 进行脱敏: 私有 IP 和 Tailscale IP 脱敏为 127.0.0.1 或 0.0.0.0
        ip = svc.get("ip") or ""
        if PRIVATE_IP_RE.search(ip) or TAILSCALE_IP_RE.search(ip):
            svc["ip"] = "127.0.0.1"
        # 锁定只读与安全
        svc["manageable"] = False
        svc["actions"] = []
        svc["svcctl_paused"] = False
        out.append(svc)
    return out


def sanitize_tools_conf_for_public(tools_conf_data: dict) -> dict:
    """对工具配置进行公网脱敏，抹除局域网 IP 与 Tailscale 真实地址。"""
    if not isinstance(tools_conf_data, dict):
        return {}
    conf = dict(tools_conf_data)
    # 抹除真实主机 IP 与 SSH 用户名
    conf["hosts"] = {
        "tailscale": "100.*.*.*",
        "lan": "192.168.*.*",
        "ssh_user": "user"
    }
    return conf


def sanitize_agent_detail_for_public(detail: dict) -> dict:
    """对 Agent 详细信息进行公网安全脱敏。
    保护:
    - 个人记忆/人设完全脱敏（公网视图只保留条数与脱敏占位）
    - 路径脱敏 (/home/tetsuya -> ~)
    - 平台状态与账号脱敏（隐藏 Telegram chat_id、user_id、真实邮箱与凭据）
    - 定时任务提示词中的私有细节脱敏
    - 抹除内网与 Tailscale IP、密钥
    """
    if not isinstance(detail, dict):
        return {}

    clean = deep_sanitize(detail, mask_ips=True, mask_paths=True)

    # 记忆与人设安全处理
    if "memories" in clean and isinstance(clean["memories"], dict):
        mems = clean["memories"]
        for key in list(mems.keys()):
            if isinstance(mems[key], dict):
                # 隐藏私有记忆原文，仅保留条目数与脱敏提示
                count = mems[key].get("count", 0)
                mems[key] = {
                    "count": count,
                    "preview": f"[公网视图记忆已脱敏 (共 {count} 条设定)]",
                    "topics": ["[设定已脱敏]"] if count > 0 else []
                }

    # 定时任务处理 (如 Hermes cron)
    if "cron" in clean and isinstance(clean["cron"], list):
        for job in clean["cron"]:
            if isinstance(job, dict):
                if job.get("prompt"):
                    job["prompt"] = "[公网视图提示词已安全脱敏]"
                if "origin" in job and isinstance(job["origin"], dict):
                    orig = job["origin"]
                    if "chat_id" in orig: orig["chat_id"] = "******"
                    if "user_id" in orig: orig["user_id"] = "******"
                    if "chat_name" in orig: orig["chat_name"] = "User"

    # Gateway 与通讯平台
    if "gateway" in clean and isinstance(clean["gateway"], dict):
        gw = clean["gateway"]
        if "platforms" in gw and isinstance(gw["platforms"], dict):
            for p_name, p_data in gw["platforms"].items():
                if isinstance(p_data, dict):
                    # 隐藏内部 PID / writer 信息
                    p_data.pop("writer_pid", None)
                    p_data.pop("writer_start_time", None)

    return clean


def scan_for_secrets(content: str) -> list:
    """审计文本内容，检测是否包含未加密的高危 API 密钥与凭证。
    返回: [(pattern_name, snippet), ...]
    """
    found = []
    if not isinstance(content, str):
        return found

    for name, pat in SECRET_PATTERNS:
        # 跳过通用参数名匹配，只报高确信度的真实密钥特征
        if "Generic" in name:
            continue
        for m in pat.finditer(content):
            val = m.group(0)
            if "REDACTED" in val or "example" in val.lower() or "dummy" in val.lower():
                continue
            snip = val[:6] + "..." + val[-4:] if len(val) > 12 else val[:4] + "***"
            found.append((name, snip))

    return found
