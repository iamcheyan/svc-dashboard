# AGENTS.md — svc-dashboard 移动运维中枢（智能体必读）

> 读者假设：你从未见过这个项目。本文告诉你：架构、怎么跑、全部 API、踩过的坑、
> 部署与重启。事实来自实际代码与 git 历史（2026-08-15 核对）。

## 一、这是什么

手机+tailscale 的随身运维中枢：服务列表、系统负载、goal 看板、模型检测、agent 日志、
服务管理、健康检查、垃圾清理与网络巡检。

- **包架构**：薄入口 `dashboard.py`（9 行）+ 后端包 `svcdash/`（13 个领域模块）+
  静态前端 `static/{index.html, app.css, app.js}`。前端 JS/CSS 是**真文件**（不再内嵌
  Python 字符串），浏览器可缓存；运行时值经内联 `window.__BOOT__` 注入。
- **纯 Python 标准库**，零第三方依赖——`python3 dashboard.py` 直接跑。
- 已部署为 **root 级 systemd 服务**（监听 80 特权端口）。

```
dashboard.py          薄入口（参数解析 + 启动）
svcdash/              后端：config/i18n/icons/procscan/sysinfo/tasks/manage/
                      agents/runtimes/goals/repos/tools/render/handler/selftest/main
static/               前端：index.html(壳+占位) app.css app.js
```

## 二、页面结构（四页签，移动优先）

四页：概览/服务/Goal/管理（i18n 三语 zh/en/ja，按 Accept-Language 自动切换，
`?lang=` 可强制）。

- **概览**：状态大字卡、关键资源、常用服务、Goal 摘要、仓库轨迹与少量最近活动；空告警/空 Goal/空事件区块默认隐藏。
- **服务**：监听端口表与服务分类；默认只显示服务名、端口、状态、CPU/内存/时长，命令/工作目录/PID 放入详情。
- **Goal**：运行中、异常、最近完成的 Goal 与详情，原始事件流不铺在首页。
- **管理**：模型检测、Agent 运行时、日志、定时任务、网络/健康检查、垃圾清理、工具直达与偏好设置。
- 桌面端用顶部分类条 `[data-cat]`，移动端用底部页签 `[data-p=0..3]`；手势：左右滑动切页。

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
| `/api/models` | GET | 模型清单+测试结果(密钥只判存在, 值不外传) |
| `POST /api/models` | POST | `{provider,model}` 模型测试(chat 1-token; evomap 禁 chat 仅探活) |
| `/api/runtimes` | GET | Agent 运行时总览(12 agent 注册表: 安装/版本/进程/任务/额度) |
| `GET /api/agentctl` | GET | 装卸动作状态+历史 |
| `POST /api/runtimes` | POST | `{"agent":id,"action":"install\|uninstall\|quota"}` 装卸(runuser 降权跑 ~/dotfiles/agent wrapper)/刷额度 |
| `/api/omp` | GET | agent 聚合（OMP 会话 + Codex 进程） |
| `/api/tmux` | GET | tmux 窗格列表 |
| `/api/trajectory?repo=NAME` | GET | 单仓库轨迹（14 天双行色块 + 500 条事件流；`repos.py:_traj_data`，OMP 会话全信号：工具/失败/压缩/指令/声明/退出/子代理/重规划/模型） |
| `/api/manage?unit=` | GET | 受管单元状态 |
| `POST /api/manage` | POST | `{"unit":id,"action":"start\|stop\|restart\|pause\|resume"}`（免密 sudo） |
| `GET /api/svcctl` | GET | 通用暂停台账 + 历史（`~/.omp/svc-dashboard/{paused.json,actions.log}`） |
| `POST /api/svcctl` | POST | `{"port":N,"action":"pause"\|"resume"}`——任意监听服务冻结/解冻（docker→`docker pause`；其余→SIGSTOP/SIGCONT）；守卫拒绝自身/22/受保护进程；`/api` 条目新增 `res{cpu,mem_mb,up_sec}`/`manageable`/`svcctl_paused` |
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
# 限制: MemoryMax=512M(额度刷新 spawn node, 128M 会 OOM) / CPUQuota=40% / TasksMax=64（实测空闲 ~17MB、0% CPU）

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

## 八、静态公网看板自动发布

公网地址：`https://svc.iamcheyan.com`。静态版不是实时 API，而是本机定期生成的脱敏快照。
自动发布使用本机 systemd **用户级** timer，不依赖 GitHub Actions 访问本机的 tmux、Goal、进程和日志。

### 发布逻辑

```text
本机数据源 → export_static() → Goal/Agent/Tmux/命令/路径二次脱敏
           → 生成 cache-busting CSS/JS 版本
           → 计算整站 hash
           → 与上次已发布 hash 相同则跳过
           → 有变化才 force-push origin/gh-pages
```

- 默认每 10 分钟运行一次；首次启动后约 3 分钟执行。
- `flock` 防止上一次收集或推送未完成时重入。
- 状态 hash 位于 `~/.cache/svc-dashboard-static/last-published.sha256`。
- 默认自定义域名为 `svc.iamcheyan.com`，可用 `SVC_DASHBOARD_CNAME` 覆盖。
- 公开仓库的提交评论、文件变更路径和仓库轨迹按用户要求保留；Goal/Agent 对话、Tmux 标题/路径/终端输出仍脱敏。
- 静态服务页不提供详情弹窗；启动命令显示为 `[命令已隐藏]`，防止公开命令参数和工作目录。
- 静态 Agent 页的模型“测试”不执行真实请求，显示为静态快照提示；真实模型测试只能在需要登录/令牌的私有 dashboard 上执行。
- 活动页事件分两类处理：`kind=commit` 的 Git 提交事件属于公开仓库信号，保留提交说明、文件路径、作者和 Diff 入口；Goal/watchdog 的 `complete`、`cleanup`、`recover`、`nudge` 等事件只保留 Goal ID、事件类型和时间，正文统一显示 `[内容已脱敏]`。
- 因此活动页出现“部分正常、部分 `[内容已脱敏]`”是预期行为，不是导出失败：前者是公开 Git 活动，后者是 Agent/Goal 内部日志。
- 自动发布器产生的 `svc-dashboard` / `Update sanitized static snapshot ...` 维护提交默认从首页、活动页和日志活动流排除，避免周期性发布刷屏；活动页筛选条中的“显示自动发布”可手动恢复查看。其他真实的 `svc-dashboard` Git 提交仍正常显示。
- 只读静态快照顶部的“在线版”入口用于切回实时 dashboard：从内网地址打开时回到当前内网主机，从 Tailscale 地址打开时回到当前 Tailscale 主机，从公网 GitHub Pages 打开时默认回到本机 Tailscale 地址 `100.76.219.104`。该入口只在静态只读版显示。
- 静态快照的负载/CPU 图不依赖访客浏览器的 `localStorage`：发布器把每次快照的系统采样保存到 `~/.cache/svc-dashboard-static/chart.json`，导出最多 24 个点并注入 `BOOT.chartData`；首次发布用当前采样填满窗口，后续定时发布逐步形成真实趋势。在线版仍使用浏览器实时采样。
- 界面语言支持中文、英文、日文：在线版默认遵从浏览器 `Accept-Language`，也可用 `?lang=zh|en|ja` 指定；顶部语言菜单可以选择“自动”或固定语言，选择保存在浏览器 `localStorage` 的 `svc-lang`。静态版同时发布 `index.html`、`index-en.html`、`index-ja.html`，首次打开按浏览器语言自动跳到对应版本；菜单选择在三个静态文件之间切换，并保留当前页面锚点。切回“自动”会重新使用系统/浏览器语言。
- GitHub Pages 的传统分支发布有每小时 10 次构建软上限，因此不要改成每 5 分钟；10 分钟最多 6 次/小时。
- Pages 从推送到公网可见还可能有缓存/构建延迟；静态版适合趋势和状态查看，不适合实时控制。

### 首次安装与启用

```bash
mkdir -p ~/.config/systemd/user
cp systemd/svc-dashboard-static-publish.service ~/.config/systemd/user/
cp systemd/svc-dashboard-static-publish.timer ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now svc-dashboard-static-publish.timer
systemctl --user status svc-dashboard-static-publish.timer
```

用户服务要在没有登录 SSH 时继续运行，可启用 linger（需要管理员权限）：

```bash
loginctl enable-linger "$USER"
```

### 手动运行、查看和停用

```bash
# 立即执行一次（不等待 timer）
systemctl --user start svc-dashboard-static-publish.service

# 查看最近日志
journalctl --user -u svc-dashboard-static-publish.service -n 100 --no-pager

# 查看下次执行时间
systemctl --user list-timers svc-dashboard-static-publish.timer

# 强制重新推送，即使 hash 没变化
SVC_DASHBOARD_FORCE=1 scripts/publish_static_snapshot.sh

# 停用自动发布
systemctl --user disable --now svc-dashboard-static-publish.timer
```

脚本要求当前用户已有 `origin` 的 Git 推送凭据；自动任务不会调用 sudo，也不会修改主服务
`svc-dashboard.service`。如果推送失败，hash 不会写入，下一次 timer 会自动重试。
