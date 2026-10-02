# svcdash/tailscale.py — Tailscale 状态、设备拓扑、Serve 代理与诊断
import json
import re
import socket
import subprocess
import time

def _run(cmd, timeout=6):
    """运行外部命令并返回 (rc, stdout, stderr)。"""
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except subprocess.TimeoutExpired:
        return -1, "", f"timeout after {timeout}s"
    except Exception as e:
        return -1, "", str(e)

def _tailscale_cmd(args, timeout=6):
    """尝试以当前用户运行 tailscale，若无权限则免密 sudo 重试。"""
    cmd = ["tailscale"] + args
    rc, out, err = _run(cmd, timeout=timeout)
    if rc != 0 and not out:
        rc2, out2, err2 = _run(["sudo", "-n"] + cmd, timeout=timeout)
        if rc2 == 0 or out2:
            return rc2, out2, err2
    return rc, out, err

def get_tailscale_status():
    """获取 Tailscale 整体状态、本机信息、Peers 列表及 Serve 代理服务。"""
    res = {
        "ok": False,
        "backend_state": "Stopped",
        "version": "",
        "self": None,
        "peers": [],
        "serve": {"enabled": False, "services": []},
        "error": ""
    }

    # 1. 查询 tailscale status --json
    rc, out, err = _tailscale_cmd(["status", "--json"], timeout=6)
    if rc != 0 and not out:
        res["error"] = err or f"tailscale status exited with code {rc}"
        return res

    try:
        data = json.loads(out)
    except Exception as e:
        res["error"] = f"JSON parse error: {e}"
        return res

    res["ok"] = True
    res["backend_state"] = data.get("BackendState", "Unknown")
    res["version"] = data.get("Version", "")

    # 解析本机 Self
    self_data = data.get("Self") or {}
    res["self"] = {
        "hostname": self_data.get("HostName", socket.gethostname()),
        "dns_name": (self_data.get("DNSName") or "").rstrip("."),
        "ips": self_data.get("TailscaleIPs", []),
        "os": self_data.get("OS", "linux"),
        "online": self_data.get("Online", True),
        "node_id": self_data.get("ID", "")
    }

    # 解析已连接 Peers
    peers_raw = data.get("Peer") or {}
    peer_list = []
    now = time.time()

    for pid, p in peers_raw.items():
        hostname = p.get("HostName") or "unknown"
        dns_name = (p.get("DNSName") or "").rstrip(".")
        ips = p.get("TailscaleIPs") or []
        os_name = p.get("OS") or "unknown"
        online = p.get("Online", False)
        active = p.get("Active", False)
        cur_addr = p.get("CurAddr") or ""
        relay = p.get("Relay") or ""
        rx = p.get("RxBytes", 0)
        tx = p.get("TxBytes", 0)
        last_seen = p.get("LastSeen") or ""

        # 是否直连
        is_direct = bool(cur_addr and not relay)

        peer_list.append({
            "id": pid,
            "hostname": hostname,
            "dns_name": dns_name,
            "ips": ips,
            "os": os_name,
            "online": online,
            "active": active,
            "cur_addr": cur_addr,
            "relay": relay,
            "direct": is_direct,
            "rx_bytes": rx,
            "tx_bytes": tx,
            "last_seen": last_seen
        })

    def _peer_ts(p):
        ls = p.get("last_seen") or ""
        if not ls:
            return 0
        try:
            return datetime.fromisoformat(ls.replace("Z", "+00:00")).timestamp()
        except Exception:
            return 0

    # 排序：在线与活跃优先，从新到旧(最近活跃优先)，然后按名称
    peer_list.sort(key=lambda x: (not x["online"], not x["active"], -_peer_ts(x), x["hostname"]))
    res["peers"] = peer_list

    # 2. 查询 tailscale serve status --json
    rc_srv, out_srv, _ = _tailscale_cmd(["serve", "status", "--json"], timeout=4)
    if rc_srv == 0 and out_srv:
        try:
            srv_data = json.loads(out_srv)
            services = []
            web_confs = srv_data.get("Web") or {}
            for host_port, conf in web_confs.items():
                handlers = conf.get("Handlers") or {}
                for path, h in handlers.items():
                    target = h.get("Proxy") or ""
                    # 构造可访问的完整 URL(如果是标准 443 端口则隐藏 :443)
                    disp_host = host_port[:-4] if host_port.endswith(":443") else host_port
                    url = f"https://{disp_host}{path if path != '/' else ''}"
                    if path == "/":
                        url += "/"
                    services.append({
                        "host_port": host_port,
                        "path": path,
                        "target": target,
                        "url": url
                    })
            if services:
                res["serve"]["enabled"] = True
                res["serve"]["services"] = services
        except Exception:
            pass

    return res

def ping_peer(peer):
    """对特定 Peer 进行 Ping 探测。"""
    if not peer:
        return {"ok": False, "msg": "Missing peer target"}

    # 严格校验输入，防止命令注入
    if not re.match(r"^[a-zA-Z0-9.\-_:]+$", peer):
        return {"ok": False, "msg": "Invalid peer address"}

    rc, out, err = _tailscale_cmd(["ping", "--timeout", "3s", "-c", "1", peer], timeout=5)
    # 示例输出：pong from hx90 (100.119.175.56) via 192.168.3.188:41641 in 382ms
    # 或 pong from ... via DERP(tokyo) in 45ms
    if rc != 0 and not out:
        return {"ok": False, "msg": err or f"Ping failed with rc={rc}"}

    m_time = re.search(r"in ([\d.]+)\s*(ms|s)\b", out)
    m_via = re.search(r"via ([^\s]+) in", out)

    rtt = None
    if m_time:
        val = float(m_time.group(1))
        unit = m_time.group(2)
        rtt = round(val * (1000 if unit == "s" else 1), 1)

    via = m_via.group(1) if m_via else ""
    is_direct = bool(via and not via.startswith("DERP"))

    return {
        "ok": bool(rtt is not None),
        "peer": peer,
        "rtt_ms": rtt,
        "via": via,
        "direct": is_direct,
        "raw": out
    }

def run_netcheck():
    """运行 tailscale netcheck 获取网络穿透诊断信息。"""
    rc, out, err = _tailscale_cmd(["netcheck", "--format=json"], timeout=10)
    if rc != 0 and not out:
        # 如果 --format=json 不支持，直接抓常规文本
        rc, out, err = _tailscale_cmd(["netcheck"], timeout=10)
        return {"ok": rc == 0, "raw": out or err}

    try:
        # 截取最后的 JSON 部分（因为 stdout 前面可能有日志输出）
        json_start = out.find("{")
        if json_start >= 0:
            out_json = out[json_start:]
            data = json.loads(out_json)
            # 解析关键指标
            derp_id = data.get("PreferredDERP")
            derp_lat = None
            if derp_id and "RegionLatency" in data:
                raw_lat = data["RegionLatency"].get(str(derp_id))
                if raw_lat:
                    derp_lat = round(raw_lat / 1_000_000, 1) # ns -> ms

            return {
                "ok": True,
                "udp": data.get("UDP", False),
                "ipv4": data.get("IPv4", False),
                "ipv6": data.get("IPv6", False),
                "upnp": data.get("UPnP", False),
                "pmp": data.get("PMP", False),
                "pcp": data.get("PCP", False),
                "mapping_varies": data.get("MappingVariesByDestIP", False),
                "preferred_derp": derp_id,
                "preferred_derp_latency_ms": derp_lat,
                "global_v4": data.get("GlobalV4", ""),
                "global_v6": data.get("GlobalV6", "")
            }
    except Exception as e:
        return {"ok": False, "raw": out, "error": str(e)}

    return {"ok": True, "raw": out}
