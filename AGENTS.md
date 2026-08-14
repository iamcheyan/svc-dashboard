# AGENTS.md — svc-dashboard 移动运维中枢（智能体必读）

> 读者假设：你从未见过这个项目。本文告诉你：架构、怎么跑、全部 API、今天踩过的坑、
> 部署与重启。事实来自 dashboard.py 实际代码与 git 历史（2026-08-14 核对）。
>
> ⚠️ 本文件名暂为 AGENTS.staged.md：写入 AGENTS.md 需用户对"修改智能体指令文件"显式
> 同意（平台保护）。用户确认后 `git mv AGENTS.staged.md AGENTS.md` 即可，内容已定稿。

## 一、这是什么

单文件 Python 服务器监控面板 → 已进化成**手机+tailscale 的随身运维中枢**：服务列表、
系统负载、goal 看板、模型检测、agent 日志、服务管理、文件浏览/健康检查/垃圾清理。

- **单文件架构**：全部逻辑（后端 + HTML/CSS/JS 前端模板）内嵌在 `dashboard.py`
  （约 4500 行）里。前端 JS 是模板字符串，服务端用 `str.replace` 注入运行时值
  （`{{TS_MODE}}`/`{{T_JSON}}` 等）。
- **纯 Python 标准库**，零第三方依赖——`python3 dashboard.py` 直接跑。
- 已部署为 **root 级 systemd 服务**（监听 80 特权端口）。

## 二、页面结构（底部五页签，移动优先）

`N_PAGES = 5`（dashboard.py:3886），页序=概要/日志/Goal/服务/模型（`pageLabels()`
:3888；i18n 三语 zh/en/ja，按 Accept-Language 自动切换，`?lang=` 可强制）。

- **概要**：状态大字卡 → 指标 2×2 → 需要处理（轻告警中心）→ 最近活动（UX 定式：
  状态大字卡 3 秒判断，整屏日志是反模式）。
- **日志**：agent 选择器 + 事件时间线（默认 24h，同 goal 循环事件折叠）。
- **Goal**：omp goal 进度卡片（状态灯/上下文体积警示/Retrying 检测）+ 负载水位
  "还可开 N 个 goal"。
- **服务**：监听端口表 + 分类 chips（用户服务默认）+ 手动进程服务启停按钮。
- **模型**：模型可用性检测（⚠️ evomap=用户充值仅探活 GET /v1/models **禁发 chat**；
  其余 1-token 实测）。
- 手势：左右滑动切页（`setPage`，dashboard.py:3897）、触感反馈、safe-area 适配。
- **svctools goal（019ffeb7，进行中）规划新增第六页签「ツール」**：文件浏览
  （`/api/fs/list|file`，白名单根+防穿越+密钥文件 404）/ 健康检查（`/api/health`，
  磁盘趋势外推满盘日期）/ 垃圾清理（`POST /api/cleanup`，dry_run 默认 true）/
  工具直达 chips / 快捷复制组 / 计划任务页。**截至 2026-08-14 14:30 这些端点尚未
  出现在 dashboard.py（goal 刚启动）——落地后更新本文的 API 表**。

## 三、API 端点表（dashboard.py:4377-4410 分发，均已实现）

| 端点 | 方法 | 说明 |
|---|---|---|
| `/api` | GET | 服务列表 JSON（ip/port/pids/cmdline/cwd/type/unit） |
| `/api/sys` | GET | 负载/CPU/内存/磁盘/开机时长 |
| `/api/goals?limit=` | GET | goal 状态聚合（15s 缓存，概要与日志页共用） |
| `/api/tasks?lang=` | GET | systemd timer + cron 定时任务列表 |
| `/api/omp` | GET | agent 聚合（OMP 会话 + Codex 进程） |
| `/api/tmux` | GET | tmux 窗格列表 |
| `/api/manage?unit=` | GET | 受管单元状态（zircon-server/zircon-bots/tailscaled + wilviewer/mapviewer 进程型，MANAGE_UNITS :1204） |
| `POST /api/manage` | POST | `{"unit":id,"action":"start\|stop\|restart\|pause\|resume"}`（走免密 sudo） |
| `/api/agentlog?sid=&cwd=&tmux=` | GET | 某 agent 会话日志时间线 + 终端画面 |
| `/api/disk`（webclient 侧） | — | （此端点属 webclient:8822，非本服务） |

## 四、⚠️ 今天踩的坑（改前端必读，commit 85102dc→0b87bee 事故）

1. **模板字符串 str.replace 改 JS 极易整页崩**：85102dc 删了 header 的 statusline
   HTML，但 JS 里引用它的代码没判空 → 一个 null 引用让**整页 JS 崩溃、页面完全错乱**
   （0b87bee 修复）。规则：**删/改任何 DOM 结构前，先 grep 它在 JS 里的所有引用**；
   JS 侧取元素一律判空（`el && ...` / `?.`）。
1b. **const 声明顺序 = 求值期地雷（f8df6ef 实战）**：IIFE 在模块求值期立即执行时，
   用到的 `const` 必须声明在它**之前**——`initLogAgentPicker()` 求值期调
   `syncLogAgentPicker` → 用 `escHtml`，但声明在 50 行后 → TDZ ReferenceError
   **杀死整个主脚本**：catbar 不构建、`#cat=` URL 路由失效、`load()`/
   `hydrateFragments()` 全不跑（服务表 0 行、Goal 卡永久"加载中"）。次生假象：
   `autoSec before initialization` 刷屏（死亡前注册的定时器残留）。排查法：
   CDP `Runtime.exceptionThrown` 抓**第一个**异常，别被次生症状带偏。工具：
   `python3 ~/.hermes/scripts/cdp_eval.py watch 8`（Chrome 需
   `--remote-debugging-port=9222`，Xvfb :101 + openbox 起）。
2. **改前端必须无头浏览器双视口复验**：桌面 1440x900 + 移动 390x844
   （`Emulation.setDeviceMetricsOverride`）逐页导航截图 + **console pageerror 收集为空**
   才算过——curl 200 ≠ 界面对（2026-08-14 移动端验收实战三次重复）。
3. 高频移动端坑：固定底部导航必须给滚动容器 `padding-bottom: calc(导航高+24px+safe-area)`
   （实测导航高 ~115-120px）；横向 chips 最后项被截断→容器横向滚动+渐隐；
   页面内容与页签名错位=页签映射 bug。
4. 改完必须真重启服务验证（见 §五），别信"改了就生效"。

## 五、部署与重启（root 级 systemd + cgroup 限制）

```bash
# unit 文件: /etc/systemd/system/svc-dashboard.service（仓库内模板 svc-dashboard.service 同内容）
# 限制: MemoryMax=128M / CPUQuota=10% / TasksMax=64（实测空闲 ~17MB、0% CPU）

sudo systemctl restart svc-dashboard      # 重启
systemctl status svc-dashboard            # 看状态
journalctl -u svc-dashboard -f            # 看日志
curl -s http://127.0.0.1/api/sys | head -c 200   # 验证
```

命令行参数：`--port N`（默认 80）`--host IP`（默认 0.0.0.0，tailscale 手机可达必须 0.0.0.0）。

## 六、tailscale 源切换机制

用户手机经 Tailscale（CGNAT 段 `100.64.0.0/10`，本机 TS IP=100.76.219.104）访问时，
页面里的服务链接主机要自动从 `192.168.3.82` 切到 TS IP：

- 服务端（dashboard.py:4332-4335）：`_client_ip()` 落在 `100.64.0.0/10` 网段 →
  渲染时 `{{TS_MODE}}` 替换为 `"true"`（:2373）。
- 前端（:2996-2997）：`const TS_HOST = "100.76.219.104"; linkHost = (h) => (TS_MODE && h === "192.168.3.82") ? TS_HOST : h`。
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
