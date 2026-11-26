#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""TaskHub 桥接层: 把本机 TaskHub 引擎(127.0.0.1:8096)的能力接入 svc-dashboard。

设计: svc-dashboard 是唯一入口与唯一界面, 任务执行的细节(worktree / tmux / 远程机器 /
agent 命令)仍由 TaskHub 引擎负责, 这里只做 HTTP 转发与前端需要的整形。任何一步失败都
降级为 {ok: False, msg: ...}, 绝不让仪表盘整体 500。
"""
import json
import os
import urllib.error
import urllib.parse
import urllib.request

API_BASE = os.environ.get("TASKHUB_API", "http://127.0.0.1:8096").rstrip("/")
ACTIVE_STATES = ("queued", "starting", "running", "waiting_user")


def _req(path, method="GET", body=None, timeout=30):
    url = API_BASE + path
    data = None
    headers = {"Accept": "application/json"}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            return json.loads(raw) if raw.strip() else {}
    except urllib.error.HTTPError as e:
        try:
            payload = json.loads(e.read().decode("utf-8", "replace") or "{}")
        except ValueError:
            payload = {}
        return {"ok": False, "msg": payload.get("detail") or f"HTTP {e.code}"}
    except (urllib.error.URLError, TimeoutError, OSError) as e:
        return {"ok": False, "msg": f"TaskHub 引擎不可达: {e}"}


def health():
    d = _req("/api/health", timeout=8)
    if not d.get("ok"):
        return {"ok": False, "msg": d.get("msg") or "引擎不可达"}
    agents = [a for a in (_req("/api/agents", timeout=8).get("agents") or []) if not a.get("hidden")]
    repos_res = _req("/api/repos", timeout=8)
    repos_list = [r.get("slug") for r in (repos_res.get("repos") or []) if r.get("enabled") and r.get("slug")]
    preferred = d.get("default_agent") or "hermes"
    ids = [a.get("id") for a in agents]
    if preferred in ids:
        ids.remove(preferred)
        ids.insert(0, preferred)
    return {"ok": True, "issue_repo": d.get("issue_repo"), "agents": ids,
            "repos": repos_list,
            "agent_labels": {a.get("id"): a.get("label") or a.get("id") for a in agents},
            "default_agent": preferred or (ids[0] if ids else "hermes")}


_hosts_cache = {"t": 0.0, "data": None}
HOSTS_TTL = 45


def hosts(force=False):
    import time as _time
    now = _time.time()
    if not force and _hosts_cache["data"] and now - _hosts_cache["t"] < HOSTS_TTL:
        return _hosts_cache["data"]
    d = _req("/api/hosts", timeout=25)
    if d.get("ok") is False:
        return _hosts_cache["data"] or d
    data = {"ok": True, "hosts": d.get("hosts") or [], "default": d.get("default")}
    _hosts_cache.update(t=now, data=data)
    return data


def issues(mode="open", q=""):
    """mode: open | running | closed | all"""
    remote = "closed" if mode == "closed" else ("all" if mode == "all" else "open")
    qs = urllib.parse.urlencode({"state": remote, "search": q or ""})
    d = _req("/api/issues?" + qs, timeout=45)
    if d.get("ok") is False:
        return d
    items = d.get("issues") or []
    if mode == "running":
        items = [i for i in items if (i.get("run") or {}).get("state") in ACTIVE_STATES]
    return {"ok": True, "repo": d.get("repo"), "issues": items}


def task(number):
    """一个任务 = Issue + 它的全部 run + 最近 run 的事件流。"""
    h = health()
    if not h.get("ok"):
        return h
    repo = h.get("issue_repo")
    if not repo:
        return {"ok": False, "msg": "未配置 Issue 仓库"}
    issue = _req(f"/api/issues/{repo}/{int(number)}", timeout=45)
    if issue.get("ok") is False:
        return issue
    for r in issue.get("runs") or []:
        r.pop("events", None)
    runs = issue.get("runs") or []
    latest = runs[0] if runs else None
    events = []
    if latest:
        detail = _req(f"/api/runs/{latest['id']}", timeout=20)
        events = detail.get("events") or []
    return {"ok": True, "repo": repo, "issue": issue, "runs": runs,
            "latest": latest, "events": events, "agents": h.get("agents"),
            "default_agent": h.get("default_agent")}


def runs(limit=40):
    d = _req(f"/api/runs?limit={int(limit)}", timeout=20)
    if d.get("ok") is False:
        return d
    return {"ok": True, "runs": d.get("runs") or []}


def run_detail(rid):
    d = _req(f"/api/runs/{urllib.parse.quote(rid)}", timeout=20)
    return d if "state" in d else {"ok": False, "msg": d.get("msg") or "未知 run"}


def run_log(rid, lines=300):
    d = _req(f"/api/runs/{urllib.parse.quote(rid)}/log?lines={int(lines)}", timeout=30)
    if "log" not in d:
        return {"ok": False, "msg": d.get("msg") or "读取日志失败"}
    return {"ok": True, "log": d.get("log") or ""}


def dispatch(number, agent=None, host=None, target_repo=None):
    h = health()
    if not h.get("ok"):
        return h
    body = {"repo": h.get("issue_repo"), "issue_number": int(number), "agent": agent or "hermes"}
    if host:
        body["host"] = host
    if target_repo:
        body["target_repo"] = target_repo
    d = _req("/api/runs", method="POST", body=body, timeout=90)
    if d.get("id"):
        return {"ok": True, "id": d["id"]}
    if d.get("needs_repo"):
        return {"ok": True, "needs_repo": True, "question": d.get("question") or ""}
    return {"ok": False, "msg": d.get("msg") or "派发失败"}


def create(title, body, agent="hermes", host="", target_repo=None):
    """新建任务：在 issue 仓库里开 issue，然后立刻派发。

    仓库判断不在这里做：TaskHub 解析不出来会先挂起并在 Telegram 里问，而不是让 UI 报错。
    """
    h = health()
    if not h.get("ok"):
        return h
    repo = h.get("issue_repo")
    if not repo:
        return {"ok": False, "msg": "未配置 Issue 仓库"}
    title = (title or "").strip()
    if not title:
        return {"ok": False, "msg": "标题不能为空"}
    d = _req(f"/api/issues/{repo}", method="POST",
             body={"title": title[:200], "body": (body or "").strip()}, timeout=90)
    if not d.get("ok") or not d.get("number"):
        return {"ok": False, "msg": d.get("msg") or "创建 Issue 失败"}
    number = int(d["number"])
    run_body = {"repo": repo, "issue_number": number, "agent": agent or "hermes"}
    if host:
        run_body["host"] = host
    if target_repo:
        run_body["target_repo"] = target_repo
    r = _req("/api/runs", method="POST", body=run_body, timeout=120)
    if r.get("needs_repo"):
        return {"ok": True, "number": number, "url": d.get("url"), "needs_repo": True,
                "question": r.get("question") or ""}
    if r.get("id"):
        return {"ok": True, "number": number, "url": d.get("url"), "id": r["id"],
                "needs_repo": bool(r.get("needs_repo")), "question": r.get("question") or ""}
    return {"ok": False, "number": number, "url": d.get("url"),
            "msg": r.get("msg") or "Issue 已创建，但派发失败"}


def set_state(number, state):
    h = health()
    if not h.get("ok"):
        return h
    repo = h.get("issue_repo")
    if not repo:
        return {"ok": False, "msg": "未配置 Issue 仓库"}
    d = _req(f"/api/issues/{repo}/{int(number)}/state", method="POST", body={"state": state}, timeout=45)
    return {"ok": True} if d.get("ok") else {"ok": False, "msg": d.get("msg") or "操作失败"}


def cancel(rid):
    d = _req(f"/api/runs/{urllib.parse.quote(rid)}/cancel", method="POST", body={}, timeout=30)
    return {"ok": True} if d.get("ok") else {"ok": False, "msg": d.get("msg") or "取消失败"}


def resume(rid, text):
    d = _req(f"/api/runs/{urllib.parse.quote(rid)}/resume", method="POST", body={"text": text}, timeout=30)
    return {"ok": True} if d.get("ok") else {"ok": False, "msg": d.get("msg") or "发送失败"}
