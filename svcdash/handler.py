#!/usr/bin/env python3
"""svcdash HTTP 处理器: HTTP/1.1 keep-alive + gzip + 静态 ETag/304 + 壳 ETag。
路由与旧版逐端点对齐(golden diff 校验)。"""
import gzip, hashlib, hmac, ipaddress, json, os, re, secrets, socket, time
from html import escape
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, quote, urlparse

from svcdash import procscan, sysinfo, tasks, manage, agents, goals, repos, tools, render, svcctl, runtimes
from svcdash.i18n import t, detect_lang, DEFAULT_LANG
from svcdash.config import SERVER_VER

_STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
_STATIC_CACHE = {}   # relpath -> (raw_bytes, gz_bytes, etag)

# ---------------- POST 令牌: 管理动作鉴权 ----------------
# token 文件 root:0600(/etc/svc-dashboard/token), 普通用户跑(dev --port)回落家目录。
# 页面不内嵌 token: GET 首页的匿名访客拿不到, 只有持有文件内容的调用者能 POST。
# mtime 缓存 → 改文件即轮换, 免重启。
_TOKEN_PATHS = ("/etc/svc-dashboard/token",
                os.path.expanduser("~/.omp/svc-dashboard/token"))
_token_cache = {"mtime": None, "val": ""}


def _token_file():
    """可用 token 路径: 已存在者优先; 否则第一个可写位置(自动生成)。"""
    for p in _TOKEN_PATHS:
        if os.path.isfile(p):
            return p
    base = os.path.dirname(_TOKEN_PATHS[0])
    if os.access(os.path.dirname(base), os.W_OK):
        return _TOKEN_PATHS[0]
    return _TOKEN_PATHS[1]


def _svc_token():
    """读(或首次生成)POST 令牌; 读不到返回空串(空串 => POST 全拒, fail-closed)。"""
    p = _token_file()
    try:
        st = os.stat(p)
        if _token_cache["mtime"] == st.st_mtime_ns:
            return _token_cache["val"]
        with open(p, encoding="ascii") as f:
            val = f.read().strip()
    except OSError:
        try:
            os.makedirs(os.path.dirname(p), mode=0o755, exist_ok=True)
            val = secrets.token_urlsafe(24)
            fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="ascii") as f:
                f.write(val + "\n")
        except OSError as e:
            print(f"[warn] 无法创建 POST 令牌 {p}: {e}", flush=True)
            _token_cache.update(mtime=None, val="")
            return ""
        st = os.stat(p)
    _token_cache.update(mtime=st.st_mtime_ns, val=val)
    return val


def _load_static(relpath):
    """读静态文件并预压缩; mtime 变化自动重载(开发免重启); 返回 (raw, gz, etag) 或 None(不存在/越界)。"""
    safe = os.path.normpath(relpath)
    if safe.startswith("..") or os.path.isabs(safe) or ".." in safe.split(os.sep):
        return None
    full = os.path.join(_STATIC_DIR, safe)
    try:
        mtime = os.stat(full).st_mtime
    except OSError:
        return None
    if os.path.realpath(full) != full:   # 防符号链接越界
        return None
    ent = _STATIC_CACHE.get(relpath)
    if ent and ent[3] == mtime:
        return ent
    with open(full, "rb") as f:
        raw = f.read()
    gz = gzip.compress(raw, 6)
    etag = '"' + hashlib.sha1(raw).hexdigest()[:16] + '"'
    ent = (raw, gz, etag, mtime)
    _STATIC_CACHE[relpath] = ent
    return ent


def _stamp_asset_versions(body):
    """把壳里 app.js/app.css 的 ?v= 替换为文件内容 sha1 前 8 位(与 ETag 同源)。
    静态资源 immutable 缓存因此只在内容真变时换 URL —— 手动维护 v= 的失步缺口根治。"""
    for name in ("app.js", "app.css"):
        ent = _load_static(name)
        if ent:
            h = ent[2].strip('"')[:8]
            body = re.sub(rf"({re.escape(name)}\?v=)[0-9a-zA-Z]*", rf"\g<1>{h}", body)
    return body

class Handler(BaseHTTPRequestHandler):
    server_version = f"svc-dashboard/{SERVER_VER}"
    protocol_version = "HTTP/1.1"

    def _host(self):
        return self.headers.get("Host") or f"localhost:{self.server.server_address[1]}"

    def _client_ip(self):
        # 仅信任来自 Tailscale 直连 peer 的 XFF; LAN 客户端可伪造 XFF 但不能改变模式/将来鉴权。
        peer = self.client_address[0] if self.client_address else ""
        if self.headers.get("X-Forwarded-For"):
            try:
                if ipaddress.ip_address(peer) in ipaddress.ip_network("100.64.0.0/10"):
                    return self.headers["X-Forwarded-For"].split(",")[0].strip()
            except ValueError:
                pass
        return peer

    def _is_tailscale_client(self):
        try:
            return ipaddress.ip_address(self._client_ip()) in ipaddress.ip_network("100.64.0.0/10")
        except ValueError:
            return False

    def _gz_ok(self):
        ae = self.headers.get("Accept-Encoding", "")
        return "gzip" in ae.lower()

    def _finish(self, code, content_type, body, cache=None, etag=None, extra=None):
        """统一响应: 自动 gzip(Accept-Encoding), Content-Length, ETag/304。"""
        inm = self.headers.get("If-None-Match")
        if etag and inm and etag in inm:
            self.send_response(304)
            self.send_header("ETag", etag)
            if cache:
                self.send_header("Cache-Control", cache)
            self.end_headers()
            return
        raw = body if isinstance(body, (bytes, bytearray)) else body.encode("utf-8")
        headers = [("Content-Type", content_type)]
        if cache:
            headers.append(("Cache-Control", cache))
        if etag:
            headers.append(("ETag", etag))
        if self._gz_ok() and len(raw) > 512:
            payload = gzip.compress(raw, 6)
            headers.append(("Content-Encoding", "gzip"))
            headers.append(("Vary", "Accept-Encoding"))
        else:
            payload = raw
        headers.append(("Content-Length", str(len(payload))))
        if extra:
            headers += extra
        try:
            self.send_response(code)
            for k, v in headers:
                self.send_header(k, v)
            self.end_headers()
            if payload:
                self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _send_json(self, code, obj):
        try:
            payload = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        except Exception:
            payload = b'{"ok":false,"msg":"encode error"}'
            code = 500
        self._finish(code, "application/json; charset=utf-8", payload,
                     cache="no-store")

    def _send_html(self, body_str, etag=None):
        self._finish(200, "text/html; charset=utf-8", body_str,
                     cache="no-cache" if etag else "no-store", etag=etag)

    def _send_static(self, relpath):
        ent = _load_static(relpath)
        if not ent:
            self.send_error(404)
            return
        raw, gz, etag, _mtime = ent
        inm = self.headers.get("If-None-Match")
        if inm and etag in inm:
            self.send_response(304)
            self.send_header("ETag", etag)
            self.send_header("Cache-Control", "public, max-age=31536000, immutable")
            self.end_headers()
            return
        if self._gz_ok():
            payload, enc = gz, "gzip"
        else:
            payload, enc = raw, None
        ctype = "text/css; charset=utf-8" if relpath.endswith(".css") else (
                "application/javascript; charset=utf-8" if relpath.endswith(".js") else
                "application/octet-stream")
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "public, max-age=31536000, immutable")
        self.send_header("ETag", etag)
        if enc:
            self.send_header("Content-Encoding", enc)
            self.send_header("Vary", "Accept-Encoding")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        path = urlparse(self.path).path
        try:
            self._handle_get(path)
        except Exception as e:
            self._send_json(500, {"ok": False, "msg": f"server error: {e}"})

    def _handle_get(self, path):
        if path in ("/", "/index.html"):
            lang = detect_lang(self.headers.get("Accept-Language", ""),
                               urlparse(self.path).query)
            ts_mode = self._is_tailscale_client()
            body = render.render_html(self._host(), [], time.time(), lang,
                                       sysdata={}, ts_mode=ts_mode)
            body = _stamp_asset_versions(body)   # ?v= 注入静态内容哈希, 根治手动维护失步
            etag = '"' + hashlib.sha1(
                (lang + "\x00" + str(ts_mode) + "\x00" + body).encode()).hexdigest()[:16] + '"'
            self._send_html(body, etag=etag)
        elif path.startswith("/static/"):
            self._send_static(path[len("/static/"):])
        elif path == "/api":
            self._send_json(200, {"updated": time.time(), "services": procscan.gather()})
        elif path == "/api/sys":
            self._send_json(200, sysinfo.sys_info())
        elif path == "/api/fragment":
            lang = detect_lang(self.headers.get("Accept-Language", ""),
                               urlparse(self.path).query)
            qs = parse_qs(urlparse(self.path).query)
            frag = (qs.get("p") or [""])[0]
            html = render.render_fragment(frag, lang, self._host(), self._is_tailscale_client())
            if html is None:
                self._send_json(404, {"ok": False, "msg": "unknown fragment"})
            else:
                self._send_html(html)
        elif path == "/api/goaldetail":
            qs = parse_qs(urlparse(self.path).query)
            gid = (qs.get("gid") or [""])[0]
            session = (qs.get("session") or [""])[0]
            if not gid and not session:
                self._send_json(400, {"ok": False, "msg": "gid or session required"})
            else:
                self._send_json(200, goals.goal_detail(gid, session))
        elif path == "/api/goals":
            qs = parse_qs(urlparse(self.path).query)
            try:
                lim = max(1, min(200, int((qs.get("limit") or ["24"])[0])))
            except ValueError:
                lim = 24
            self._send_json(200, {"updated": time.time(), "goals": goals.scan_goals(),
                                  "completed": goals.parse_completed_goals(limit=lim),
                                  "events": goals.merge_events(
                                      goals.parse_watchdog_events(limit=min(lim, 80)),
                                      goals.parse_completed_goals(limit=lim),
                                      repos.parse_repo_commits(), limit=lim)})
        elif path == "/api/repos":
            qs = parse_qs(urlparse(self.path).query)
            refresh = (qs.get("refresh") or ["0"])[0] in ("1", "true")
            self._send_json(200, repos.repo_stats(refresh=refresh))
        elif path == "/api/tasks":
            lang = detect_lang(self.headers.get("Accept-Language", ""), urlparse(self.path).query)
            self._send_json(200, {"tasks": tasks.scan_tasks(lang)})
        elif path == "/api/omp":
            self._send_json(200, {"updated": time.time(), "omp": agents.scan_omp(),
                                  "codex": agents.scan_codex()})
        elif path == "/api/tmux":
            self._send_json(200, {"updated": time.time(), "panes": agents.scan_tmux()})
        elif path == "/api/manage":
            qs = parse_qs(urlparse(self.path).query)
            uid = (qs.get("unit") or [""])[0]
            lang = detect_lang(self.headers.get("Accept-Language", ""), urlparse(self.path).query)
            if not uid:
                self._send_json(200, {"units": [{"id": u["id"], "label": u["label"], "desc": u["desc"]}
                                       for u in manage.MANAGE_UNITS]})
            else:
                self._send_json(200, manage.manage_status(uid, lang))
        elif path == "/api/svcctl":
            self._send_json(200, svcctl.status())
        elif path == "/api/trajectory":
            qs = parse_qs(urlparse(self.path).query)
            repo = (qs.get("repo") or [""])[0]
            self._send_json(200, repos.repo_trajectory(repo))
        elif path.startswith("/api/agentlog"):
            qs = parse_qs(urlparse(self.path).query)
            sid = (qs.get("sid") or [""])[0]
            cwd = (qs.get("cwd") or [""])[0]
            tmx = (qs.get("tmux") or [""])[0]
            if not tmx and cwd:
                tmx = agents._tmux_by_cwd(cwd)
            lang = detect_lang(self.headers.get("Accept-Language", ""), urlparse(self.path).query)
            self._send_json(200, {"events": agents.scan_agent_log(sid, lang) if sid else [],
                                  "capture": agents._tmux_capture(tmx)})
        elif path == "/api/fs/list":
            qs = parse_qs(urlparse(self.path).query)
            p = (qs.get("path") or [""])[0]
            data = tools.fs_list(p)
            if not data.get("ok"):
                self.log_message("fs/list rejected %r -> 404", p[:160])
                self._send_json(404, data)
            else:
                self._send_json(200, data)
        elif path == "/api/fs/file":
            self._fs_file()
        elif path == "/api/health":
            self._send_json(200, tools.health_check())
        elif path == "/api/nettest":
            self._send_json(200, tools.net_test())
        elif path == "/api/runtimes":
            # 额度后台刷新(过期 5 分钟且无任务在跑时触发), 本响应返回缓存快照
            if not runtimes.quota_snapshot()["running"]:
                runtimes.refresh_quota()
            self._send_json(200, runtimes.scan_runtimes())
        elif path == "/api/agentctl":
            self._send_json(200, runtimes.agentctl_status())
        elif path == "/api/models":
            self._send_json(200, runtimes.scan_models())
        elif path == "/api/toolports":
            self._send_json(200, tools.tool_ports_alive())
        elif path == "/api/aicleanup":
            from . import aicleanup
            self._send_json(200, aicleanup.aicleanup_status())
        elif path == "/api/uservice":
            self._send_json(200, {"ok": True, "units": tools.user_services()})
        else:
            self.send_error(404)

    def _fs_file(self):
        """GET /api/fs/file?path=&mode=view|download[&enc=gb18030]"""
        qs = parse_qs(urlparse(self.path).query)
        p = (qs.get("path") or [""])[0]
        mode = (qs.get("mode") or ["view"])[0]
        enc = (qs.get("enc") or [""])[0]
        real = tools.fs_resolve(p)
        if not real or not os.path.isfile(real):
            self.log_message("fs/file rejected %r mode=%s -> 404", p[:160], mode)
            self.send_error(404)
            return
        kind, mime = tools.fs_meta(real)
        if mode == "view" and kind != "image":
            data = tools.fs_read_text(real, enc)
            if not data.get("ok"):
                self.log_message("fs/file read error %r: %s", p[:160], data.get("msg"))
                self._send_json(500, data)
            else:
                self._send_json(200, data)
            return
        try:
            size = os.path.getsize(real)
            self.send_response(200)
            ctype = mime if (mode != "download" and kind == "image") else "application/octet-stream"
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(size))
            self.send_header("Cache-Control", "no-store")
            if mode == "download":
                fn = os.path.basename(real)
                safe = re.sub(r"[^A-Za-z0-9._-]", "_", fn) or "download"
                self.send_header("Content-Disposition",
                                 f'attachment; filename="{safe}"; filename*=UTF-8\'\'{quote(fn)}')
            self.end_headers()
            with open(real, "rb") as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except (OSError, BrokenPipeError) as ex:
            self.log_message("fs/file stream error: %s", ex)

    def _origin_ok(self):
        """浏览器跨站 POST 防护(CSRF): Origin/Referer 任一存在时, 其 host 必须与
        本次请求 Host 一致(即页面由本服务正常下发)。无两者(curl/监控脚本)放行,
        浏览器跨站表单必带 Origin → 拒绝。挡住恶意页面驱动 root 动作端点。"""
        host = (self.headers.get("Host") or "").lower()
        for h in ("Origin", "Referer"):
            v = self.headers.get(h)
            if not v:
                continue
            origin_host = urlparse(v).netloc.lower()
            if origin_host and origin_host != host:
                self.log_message("blocked cross-site POST: %s=%s host=%s", h, v, host)
                return False
        return True

    def _token_ok(self):
        """POST 令牌鉴权: X-Svc-Token 须与 token 文件内容一致(常数时间比较)。
        token 不随页面下发 → 匿名 GET / 拿不到, CSRF 页面/未授权调用者一律 403。"""
        expect = _svc_token()
        if not expect:
            self.log_message("POST auth unavailable: token file unreadable")
            return False
        got = self.headers.get("X-Svc-Token") or ""
        return hmac.compare_digest(got.encode("utf-8", "replace"),
                                   expect.encode("utf-8", "replace"))

    def do_POST(self):
        path = urlparse(self.path).path
        if path not in ("/api/manage", "/api/cleanup", "/api/aicleanup", "/api/uservice", "/api/svcctl", "/api/runtimes", "/api/models"):
            self.send_error(404)
            return
        # 先消费请求体再鉴权: 403(跨站/无token)提前返回时若 body 残留在
        # keep-alive 连接里, 下一个请求会拼成 '{"dry_run":true}GET /' → 501
        # (2026-08-16 实测用户浏览器因此看到 Error response 501 页)。
        try:
            ln = int(self.headers.get("Content-Length") or 0)
            if ln < 0 or ln > (1 << 20):
                self.close_connection = True
                self._send_json(400, {"ok": False, "msg": "bad content-length"})
                return
            if ln:
                raw = self.rfile.read(ln)
            else:
                raw = b""
        except Exception as e:
            self._send_json(400, {"ok": False, "msg": f"bad request: {e}"})
            return
        if not self._origin_ok():
            self._send_json(403, {"ok": False, "msg": "cross-site POST rejected"})
            return
        if not self._token_ok():
            self._send_json(403, {"ok": False, "needToken": True,
                                  "msg": "invalid or missing X-Svc-Token"})
            return
        try:
            body = json.loads(raw.decode("utf-8") or "{}")
            if not isinstance(body, dict):
                raise ValueError("body must be a JSON object")
        except Exception as e:
            lang = detect_lang(self.headers.get("Accept-Language", ""), urlparse(self.path).query)
            self._send_json(400, {"ok": False, "msg": t(lang, "m_badreq", e=str(e))})
            return
        lang = detect_lang(self.headers.get("Accept-Language", ""), urlparse(self.path).query)
        if path == "/api/manage":
            unit = str(body.get("unit") or "")
            action = str(body.get("action") or "")
            self.log_message("manage %s %s", unit, action)
            try:
                self._send_json(200, manage.manage_action(unit, action, lang))
            except Exception as e:
                self._send_json(500, {"ok": False, "msg": f"server error: {e}"})
        elif path == "/api/cleanup":
            dry = body.get("dry_run", True) is not False
            action = str(body.get("action") or "")
            items = [str(x) for x in (body.get("items") or [])][:16] if isinstance(body.get("items"), list) else []
            self.log_message("cleanup action=%s dry_run=%s items=%s", action, dry, items)
            try:
                if action == "docker_prune":
                    self._send_json(200, tools.docker_prune())
                elif dry:
                    self._send_json(200, tools.cleanup_scan())
                else:
                    self._send_json(200, tools.cleanup_run(items))
            except Exception as e:
                self._send_json(500, {"ok": False, "msg": f"server error: {e}"})
        elif path == "/api/aicleanup":
            from . import aicleanup
            self.log_message("aicleanup %s", body)
            try:
                ok, msg = aicleanup.aicleanup_start()
                self._send_json(200, {"ok": ok, "msg": msg})
            except Exception as e:
                self._send_json(500, {"ok": False, "msg": f"server error: {e}"})
        elif path == "/api/uservice":
            unit = str(body.get("unit") or "")
            action = str(body.get("action") or "")
            self.log_message("uservice %s %s", unit, action)
            try:
                self._send_json(200, tools.user_service_action(unit, action))
            except Exception as e:
                self._send_json(500, {"ok": False, "msg": f"server error: {e}"})
        elif path == "/api/svcctl":
            port = body.get("port")
            action = str(body.get("action") or "")
            self.log_message("svcctl %s %s", action, port)
            try:
                self._send_json(200, svcctl.svcctl_action(port, action, lang))
            except Exception as e:
                self._send_json(500, {"ok": False, "msg": f"server error: {e}"})
        elif path == "/api/models":
            provider = str(body.get("provider") or "")
            model = str(body.get("model") or "")
            self.log_message("modeltest %s %s", provider, model)
            try:
                ok, msg = runtimes.model_test_start(provider, model)
                self._send_json(200, {"ok": ok, "msg": msg})
            except Exception as e:
                self._send_json(500, {"ok": False, "msg": f"server error: {e}"})
        elif path == "/api/runtimes":
            agent = str(body.get("agent") or "")
            action = str(body.get("action") or "")
            self.log_message("agentctl %s %s", agent, action)
            try:
                ok, msg = runtimes.agentctl_start(agent, action)
                self._send_json(200, {"ok": ok, "msg": msg})
            except Exception as e:
                self._send_json(500, {"ok": False, "msg": f"server error: {e}"})
    def log_message(self, fmt, *args):
        sys_write = __import__("sys").stderr.write
        sys_write("[%s] %s\n" % (time.strftime("%H:%M:%S"), fmt % args))