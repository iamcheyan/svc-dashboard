# AGENTS.md — svc-dashboard 移动运维中枢（智能体必读）

> 读者假设：你从未见过这个项目。本文告诉你：架构、怎么跑、全部 API、踩过的坑、
> 部署与重启。事实来自实际代码与 git 历史（2026-08-15 核对）。

## 一、这是什么

手机+tailscale 的随身运维中枢：服务列表、系统负载、goal 看板、模型检测、agent 日志、
服务管理、文件浏览/健康检查/垃圾清理。

- **包架构**：薄入口 `dashboard.py`（9 行）+ 后端包 `svcdash/`（13 个领域模块）+
  静态前端 `static/{index.html, app.css, app.js}`。前端 JS/CSS 是**真文件**（不再内嵌
  Python 字符串），浏览器可缓存；运行时值经内联 `window.__BOOT__` 注入。
- **纯 Python 标准库**，零第三方依赖——`python3 dashboard.py` 直接跑。
- 已部署为 **root 级 systemd 服务**（监听 80 特权端口）。

```
dashboard.py          薄入口（参数解析 + 启动）
svcdash/              后端：config/i18n/icons/procscan/sysinfo/tasks/manage/
                      agents/goals/repos/tools/render/handler/selftest/main
static/               前端：index.html(壳+占位) app.css app.js
```

## 二、页面结构（六页签，移动优先）

六页：概要/日志/Goal/服务/模型/ツール（i18n 三语 zh/en/ja，按 Accept-Language 自动切换，
`?lang=` 可强制）。

- **概要**：状态大字卡 → 指标 2×2 → Web 服务磁贴（真身份+资源占用 CPU/内存/时长，
  ≥30%橙/≥80%红高亮 + 迷你暂停/恢复钮，点击直达服务）→ Goal 摘要 → 仓库卡
  （近 14 天 **Agent 操作轨迹条**：提交蓝/干预琥珀/恢复浅绿/完成深绿/OMP 工具活动紫，
  点击进全屏轨迹详情页——设计原理见 README「Agent 操作轨迹」节，灵感 codex-trajectory）
  → 系统指标 → 最近活动。
- **日志**：agent 选择器 + 事件时间线（默认 24h，同 goal 循环事件折叠）。
- **Goal**：omp goal 进度卡片（状态灯/上下文体积警示/Retrying 检测）+ 负载水位。
- **服务**：监听端口表 + 分类 chips（用户服务默认）+ 手动进程服务启停按钮。
- **模型**：模型可用性检测（⚠️ evomap=用户充值仅探活 GET /v1/models **禁发 chat**；
  其余 1-token 实测）。
- **ツール**：文件浏览（`/api/fs/list|file`，白名单根+防穿越+密钥文件 404）/ 健康检查
  （`/api/health`，磁盘趋势外推满盘日期）/ 垃圾清理（`POST /api/cleanup`，dry_run
  默认 true）/ 网络速测 / 工具直达 chips / 快捷复制组。
- 桌面端用顶部分类条 `[data-cat]`，移动端用底部页签 `[data-p=0..5]`；手势：左右滑动切页。

## 三、API 端点表（svcdash/handler.py 路由，均已实现）

| 端点 | 方法 | 说明 |
|---|---|---|
| `/` | GET | HTML 壳（lite 骨架 + BOOT 注入，gzip + ETag） |
| `/static/*` | GET | CSS/JS（ETag + immutable 缓存，304） |
| `/api` | GET | 服务列表 JSON（ip/port/pids/cmdline/cwd/type/unit） |
| `/api/sys` | GET | 负载/CPU/内存/磁盘/开机时长 + 水位 + top 进程 |
| `/api/fragment?p=goals\|events\|toolchips` | GET | 渲染好的 HTML 片段（5s 缓存，首屏异步填充） |
| `/api/goals?limit=` | GET | goal 状态聚合 + 已完成台账 + 事件时间线 |
| `/api/goaldetail?gid=&session=` | GET | 单 goal 详情 |
| `/api/repos?refresh=` | GET | agent 改动过的 git 仓库统计（600s 缓存） |
| `/api/tasks?lang=` | GET | systemd timer + cron 定时任务列表 |
| `/api/omp` | GET | agent 聚合（OMP 会话 + Codex 进程） |
| `/api/tmux` | GET | tmux 窗格列表 |
| `/api/agentlog?sid=&cwd=&tmux=` | GET | agent 会话日志时间线 + 终端画面 |
| `/api/trajectory?repo=NAME` | GET | 单仓库 Agent 操作轨迹（14 天逐日色块 + 200 条事件流；`repos.py:_traj_data`，含 OMP 会话工具调用/压缩事件） |
| `/api/manage?unit=` | GET | 受管单元状态 |
| `POST /api/manage` | POST | `{"unit":id,"action":"start\|stop\|restart\|pause\|resume"}`（免密 sudo） |
| `GET /api/svcctl` | GET | 通用暂停台账 + 历史（`~/.omp/svc-dashboard/{paused.json,actions.log}`） |
| `POST /api/svcctl` | POST | `{"port":N,"action":"pause"\|"resume"}`——任意监听服务冻结/解冻（docker→`docker pause`；其余→SIGSTOP/SIGCONT）；守卫拒绝自身/22/受保护进程；`/api` 条目新增 `res{cpu,mem_mb,up_sec}`/`manageable`/`svcctl_paused` |
| `/api/fs/list?path=` | GET | 目录列表（白名单+防穿越+敏感隐藏） |
| `/api/fs/file?path=&mode=view\|download` | GET | 文件预览/下载 |
| `/api/health` | GET | 健康快检（系统/磁盘趋势/温度/进程/端口/看门狗） |
| `/api/nettest` | GET | 外网延迟 + tailscale ping |
| `/api/toolports` | GET | 工具 chips 端口存活 |
| `/api/uservice` | GET | 用户级 systemd 服务列表 |
| `POST /api/uservice` | POST | 用户级服务重启（I-KNOW 护栏） |
| `POST /api/cleanup` | POST | 垃圾清理扫描/执行（dry_run 默认 true） |

## 四、⚠️ 踩过的坑（改前端必读）

1. ~~**模板字符串 str.replace 改 JS 极易整页崩**~~（commit 85102dc→0b87bee 事故）：
   **已通过 2026-08-15 重构根治**——前端 JS 抽到 `static/app.js` 真文件，不再内嵌
   Python 字符串、不再 str.replace 注入。但历史教训仍适用：**删/改任何 DOM 结构前，
   先 grep 它在 app.js 里的所有引用**；JS 侧取元素一律判空（`el && ...` / `?.`）。
1b. **const 声明顺序 = 求值期地雷（f8df6ef 实战）**：app.js 模块求值期立即执行的 IIFE，
   用到的 `const` 必须声明在它**之前**。TDZ ReferenceError 会**杀死整个主脚本**：
   catbar 不构建、`#cat=` 路由失效、`load()`/`hydrateFragments()` 全不跑（服务表 0 行、
   Goal 卡永久"加载中"）。次生假象：`autoSec before initialization` 刷屏。排查法：
   CDP `Runtime.exceptionThrown` 抓**第一个**异常，别被次生症状带偏。
2. **改前端必须无头浏览器双视口复验**：桌面 1440x900 + 移动 390x844
   （`Emulation.setDeviceMetricsOverride`）逐页导航 + **console pageerror 收集为空**才算过
   ——curl 200 ≠ 界面对。回归验证时用新旧服务同协议对比（见本仓 2026-08-15 重构验证）。
3. 高频移动端坑：固定底部导航必须给滚动容器 `padding-bottom: calc(导航高+24px+safe-area)`
   （实测导航高 ~115-120px）；横向 chips 最后项被截断→容器横向滚动+渐隐；
   页面内容与页签名错位=页签映射 bug。
4. 改完必须真重启服务验证（见 §五），别信"改了就生效"。

## 五、部署与重启（root 级 systemd + cgroup 限制）

```bash
# unit 文件: /etc/systemd/system/svc-dashboard.service（仓库内模板 svc-dashboard.service 同内容）
# 限制: MemoryMax=128M / CPUQuota=40% / TasksMax=64（实测空闲 ~17MB、0% CPU）

sudo systemctl restart svc-dashboard      # 重启
systemctl status svc-dashboard            # 看状态
journalctl -u svc-dashboard -f            # 看日志
curl -s http://127.0.0.1/api/sys | head -c 200   # 验证
python3 dashboard.py --selftest          # 离线自检（单测 + 真实数据源 dry-run）
```

命令行参数：`--port N`（默认 80）`--host IP`（默认 0.0.0.0，tailscale 手机可达必须
0.0.0.0）`--scan`（一次性扫描打印 JSON）`--selftest`（自检）。

HTTP 层：HTTP/1.1 keep-alive + gzip + 静态 ETag/304（svcdash/handler.py）。

## 六、tailscale 源切换机制

用户手机经 Tailscale（CGNAT 段 `100.64.0.0/10`，本机 TS IP=100.76.219.104）访问时，
页面里的服务链接主机要自动从 `192.168.3.82` 切到 TS IP：

- 服务端（svcdash/handler.py `_is_tailscale_client`）：`_client_ip()` 落在
  `100.64.0.0/10` 网段 → BOOT 里 `tsMode=true`。
- 前端（static/app.js）：`const TS_HOST = "100.76.219.104"; linkHost = (h) => (TS_MODE && h === "192.168.3.82") ? TS_HOST : h`。
- 新增带链接的前端功能时**必须走 `linkHost()`**，否则手机端点不通。

## 七、goal_watchdog 集成

- Goal 页数据来自 `/api/goals`，底层读 `~/.omp/agent/sessions/*.jsonl` 与
  `~/.omp/logs/goal-watchdog.log`。
- watchdog 本体在 `~/development/Mir3-Research/scripts/goal_watchdog.sh`（crontab 每 5 分钟）：
  **GOALS 数组** 5 字段 `goal_id|jsonl路径|tmux会话名|workdir|标签`；每 goal 独立
  kill-switch `~/.omp/mir3-goal-watchdog.<前8位>.off`，全局 off 文件停用一切；
  goal 终态自动 kill+回收 tmux 并记 `~/.omp/logs/goal-completed.log`（含 resume_cmd
  可复活）——**会话自动消失是正常回收不是故障**。
- 手动停 goal：kill omp 进程 + touch off 文件 + 删 GOALS 行，三步缺一不可。