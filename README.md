# svc-dashboard

本机监听服务一览表 —— 在浏览器里列出服务器当前后台运行的对外 TCP 服务，并展示系统负载/CPU/内存/磁盘状态、OMP/Codex agent 任务、goal 进度、定时任务、服务管理、文件浏览/健康检查/垃圾清理。

纯 Python 标准库实现，零第三方依赖。访问 `http://<服务器>/` 即可使用（默认监听 80 端口）。

## 项目结构

单文件已拆为 **薄入口 + 后端包 + 静态前端**（保持纯标准库零依赖，`python3 dashboard.py` 直接跑）：

```
dashboard.py          薄入口：参数解析 + 启动（9 行）
svcdash/              后端包（按领域拆分）
  config.py           端口/刷新间隔/版本常量
  i18n.py             三语字典 + t() / detect_lang()
  icons.py            内联 SVG 图标表（前后端共享同一份 path）
  procscan.py          /proc 扫描：监听 socket、PID、cgroup 分类、docker、gather()
  sysinfo.py           负载/CPU/内存/磁盘/top 进程/负载水位
  tasks.py             cron + systemd timer 枚举
  manage.py            systemd 单元 + 手动进程服务启停
  agents.py            OMP / Codex / tmux 状态 + agent 日志
  goals.py             goal_watchdog 解析、上下文体积、事件时间线
  repos.py             agent 改动过的 git 仓库统计
  tools.py             文件浏览 / 健康检查 / 垃圾清理 / 网络速测 / 用户服务
  render.py            壳渲染 + 片段渲染（静态模板 + BOOT 注入）
  handler.py           HTTP 路由（HTTP/1.1 + gzip + ETag）
  selftest.py          离线自检（单测 + 真实数据源 dry-run）
  main.py              ThreadingHTTPServer 启动
static/
  index.html           页面壳（占位符 + BOOT 注入点，~17KB）
  app.css              样式（浏览器可缓存）
  app.js               前端逻辑（从 window.__BOOT__ 取运行时值，浏览器可缓存）
```

## 功能（六页签，移动优先）

- **概要**：状态大字卡 → 指标 2×2 → 需要处理 → 最近活动
- **日志**：agent 选择器 + 事件时间线（默认 24h，同 goal 循环事件折叠）
- **Goal**：omp goal 进度卡片（状态灯/上下文体积警示/Retrying 检测）+ 负载水位
- **服务**：监听端口表 + 分类 chips（用户服务默认）+ 手动进程服务启停按钮
- **模型**：模型可用性检测
- **ツール**：文件浏览 / 健康检查 / 垃圾清理 / 网络速测 / 工具直达 / 快捷复制组

手势：左右滑动切页、触感反馈、safe-area 适配。桌面端用顶部分类条，移动端用底部页签。

## Agent 操作轨迹（设计笔记，复习用）

**灵感来源**：[icesixgod/codex-trajectory](https://github.com/icesixgod/codex-trajectory)（95★，MIT）——
把本地 Codex 任务日志（JSONL）投影成"**事件账本 + 交互时间轴**"的只读查看器：轮次、
近似模型步骤、推理摘要、工具调用耗时、子代理、上下文压缩、token 用量、失败，每类
事件一种颜色块按时间排布；默认隐私模式只给"事件名+时间+状态+有界摘要"，不看对话
全文。核心价值一句话：**不看过程全文，一眼看清一个 agent 任务"做了什么、卡在哪、
花了多久"**。

**映射到本面板**（数据源全是现有日志，零新增采集）：

| 事件账本（JSONL 投影） | ① git log（每仓库 400 条）② `goal-watchdog.log`（gid→workdir→仓库根映射）+ `goal-completed.log` ③ **OMP 会话 JSONL**（`~/.omp/agent/sessions/*/*.jsonl`，172 个/478MB：`tool_execution_start` 每次工具调用含意图、`compaction` 上下文压缩、`session.cwd` 定位仓库） |
| 检查器（点块看详情） | 点仓库卡 → 全屏轨迹详情页（大号色块条 + 图例 + 200 条事件流） |

**颜色语义**（逐日主色，优先级 done > commit > warn > good）：

| 色 | 含义 | 事件来源 |
|---|---|---|
| 🔵 蓝 `tr-commit` | 有提交 | git log |
| 🟠 琥珀 `tr-warn` | watchdog 干预 | nudge（催"继续"）/ pause / restart（进程死亡重启） |
| 🟢 浅绿 `tr-good` | 恢复 | recovered / resumed |
| 🟣 紫 `tr-agent` | agent 工具活动（当日无更高优先级事件时显示） | OMP 会话 `tool_execution_start` + `compaction` |
| 🟩 深绿 `tr-done` | goal 完成 | goal-completed.log |
| ⬜ 灰 `tr-idle` | 当日无活动 | — |

悬停色块显示当日各类计数；cleanup/other 类事件不进色条，只出现在详情页事件流。
实现细节：watchdog/完成台账解析按 60s 共享快照（`_traj_wd_cache`，8 仓库只读一次
日志）；**OMP 会话日志按 (path, mtime, size) 文件级增量缓存**（478MB 只在冷启动
解析一次 ~7s，之后只重读在写的活跃会话；行级子串预筛跳过 80%+ 无关行）；
轨迹数据 60s 缓存；`repos.py` 的 exts 文件类型统计已删除（无信息量）。

- **HTTP/1.1 keep-alive**：旧版 HTTP/1.0 每请求新建 TCP 连接，现复用连接
- **gzip**：HTML/JSON/CSS/JS 全压缩（移动端首屏 ~400KB → ~33KB）
- **静态资产缓存**：CSS/JS 带 ETag + `Cache-Control: immutable`，304 命中免重传；部署变更靠内容哈希 `?v=` 自动失效
- **壳渲染缓存**：HTML 壳按语言永久缓存（旧版每 5s 重渲染 ~400KB 字符串）
- **按需加载**：无人访问时进程完全静默，无后台线程；重面板走 `/api/fragment` 异步填充

## JSON API

| 端点 | 方法 | 说明 |
|---|---|---|
| `/api` | GET | 服务列表 JSON（ip/port/pids/cmdline/cwd/type/unit） |
| `/api/sys` | GET | 负载/CPU/内存/磁盘/开机时长 + 负载水位 + top 进程 |
| `/api/goals?limit=` | GET | goal 状态聚合 + 已完成台账 + 事件时间线 |
| `/api/goaldetail?gid=&session=` | GET | 单个 goal 详情（状态/tmux 画面/活动） |
| `/api/repos?refresh=` | GET | agent 改动过的 git 仓库统计 |
| `/api/trajectory?repo=NAME` | GET | 单仓库 Agent 操作轨迹（14 天逐日色块 + 200 条事件流） |
| `/api/tasks?lang=` | GET | systemd timer + cron 定时任务列表 |
| `/api/omp` | GET | agent 聚合（OMP 会话 + Codex 进程） |
| `/api/tmux` | GET | tmux 窗格列表 |
| `/api/agentlog?sid=&cwd=&tmux=` | GET | agent 会话日志时间线 + 终端画面 |
| `/api/fragment?p=goals\|events\|toolchips` | GET | 渲染好的 HTML 片段（首屏异步填充） |
| `/api/manage?unit=` | GET | 受管单元状态 |
| `POST /api/manage` | POST | `{"unit":id,"action":"start\|stop\|restart\|pause\|resume"}`（免密 sudo） |
| `GET /api/svcctl` | GET | 服务暂停台账 + 暂停/恢复历史 |
| `POST /api/svcctl` | POST | `{"port":N,"action":"pause"\|"resume"}` 任意服务冻结/解冻（容器→docker pause，其余→SIGSTOP；台账持久化，守卫拒绝 dashboard 自身/SSH/受保护进程） |
| `/api/fs/list?path=` | GET | 目录列表（白名单根 + 防穿越 + 敏感文件隐藏） |
| `/api/fs/file?path=&mode=view\|download` | GET | 文件预览（文本/图片）/ 下载 |
| `/api/health` | GET | 一次性健康快检（系统/磁盘趋势/温度/进程/端口/看门狗） |
| `/api/nettest` | GET | 外网延迟 + tailscale 对端 ping |
| `/api/toolports` | GET | 工具直达 chips 端口存活 |
| `/api/uservice` | GET | 用户级 systemd 服务列表 |
| `POST /api/uservice` | POST | 用户级服务重启（前端 I-KNOW 护栏） |
| `POST /api/cleanup` | POST | 垃圾清理扫描/执行（`dry_run` 默认 true） |

## 多语言 (i18n)

界面支持 **中文 / English / 日本語** 三语，按浏览器 `Accept-Language` 自动切换：

- `Accept-Language: ja` → 日语；`en*` → 英语；`zh*` 或无语言头 → 中文（默认）
- 可用 `?lang=en|ja|zh` 查询参数强制覆盖

## 工作原理

非 root 用户无法读取其他用户/root 进程的 `/proc/<pid>/fd`（内核权限限制），因此程序采用两层信息收集：

1. 扫描 `/proc/net/tcp` 与 `/proc/net/tcp6` 找出所有 LISTEN socket，通过 inode 反查进程；
2. 用户访问页面时同步执行一次 `sudo -n ss -H -tlnp` 补齐 root/其他用户服务的 PID、名称、cgroup（失败时降级，页面照常显示）。**无后台线程、无定时刷新** —— 完全按需加载。

## 快速开始

```bash
# 1. 克隆
git clone https://github.com/iamcheyan/svc-dashboard.git
cd svc-dashboard

# 2. 直接运行（前台，Ctrl+C 退出）
python3 dashboard.py

# 3. 浏览器打开
# http://127.0.0.1/
```

命令行参数：

| 参数 | 说明 | 默认 |
|---|---|---|
| `--port <N>` | 监听端口 | `80` |
| `--host <IP>` | 监听地址 | `0.0.0.0` |
| `--scan` | 一次性扫描服务列表并打印 JSON 后退出 | — |
| `--selftest` | 离线自检（单测 + 真实数据源 dry-run） | — |

## 部署为服务

80 是特权端口，需 root 运行。项目内置单元模板 `svc-dashboard.service`：

```bash
# 系统级服务（监听 80，需 root；本机实际部署方式）
sudo cp svc-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now svc-dashboard
sudo systemctl restart svc-dashboard      # 改代码后重启

# 或用户级服务（无需 root，改端口避免 80 冲突）
mkdir -p ~/.config/systemd/user
cp svc-dashboard.service ~/.config/systemd/user/
# 编辑 ExecStart 追加 --port 8080
systemctl --user daemon-reload
systemctl --user enable --now svc-dashboard
loginctl enable-linger $USER               # 登出后仍运行
```

验证：

```bash
systemctl is-active svc-dashboard           # active
curl -s http://127.0.0.1/api/sys | head -c 200
python3 dashboard.py --selftest            # 自检
journalctl -u svc-dashboard -f             # 日志
```

资源限制（unit 文件内置）：`MemoryMax=128M` / `CPUQuota=40%` / `TasksMax=64`（实测空闲 ~17MB、0% CPU）。

## Tailscale 源切换

用户手机经 Tailscale（CGNAT 段 `100.64.0.0/10`）访问时，页面里的服务链接主机会自动从内网 IP 切到 Tailscale IP（服务端检测客户端来源网段，前端 `linkHost()` 切换）。

## 注意事项

- **权限**：需免密 sudo（`sudo -n`）才能完整显示 root/其他用户服务的 PID 与命令；无 sudo 时这些服务的 PID 栏为空，其余功能不受影响
- **端口冲突**：80 被占用时改 `--port 8080`，或编辑单元文件 `ExecStart` 追加 `--port` 后 `daemon-reload && restart`
- **安全**：文件浏览根白名单为 `~/` 与 `/tmp`，realpath 越界/敏感文件（`.env`/`*key*`/`id_rsa`/`.pem`/`.git` 全树）一律 404；垃圾清理 dry_run 默认 true，用户媒体/System.db/git 历史/.env 永不触碰

## 许可证

MIT