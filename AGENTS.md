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

## 二、页面结构（五页签，移动优先）

五页：概览 / 活动 / Tmux / Agent / 服务（i18n 三语 zh/en/ja，按 Accept-Language 自动切换，
`?lang=` 可强制）。

- **概览**：状态大字卡、关键资源、四大中枢直达入口、额度进度、仓库轨迹与最近活动。
- **活动**：聚合提交、远程同步与 Goal 生命周期事件流，支持项目快速过滤与纯净极简流模式。
- **Tmux**：Tmux 活跃会话与终端实时预览、Goal 任务卡片，带「⚡ 唤醒推进」（调用 Hermes 自动推断处理并恢复堵塞任务）与「▶ 恢复运行」。
- **Agent**：Agent 运行时状态、模型检测（1-token 探活）、环境与工具中枢。
- **服务**：监听端口表与分类（用户/Web/Docker/系统/All/Tailscale/看门狗/管理）；移动端导航放最后；内嵌 Tailscale 网络拓扑卡片（连接机器、Serve 代理服务、Ping 延迟测速与网络体检 Netcheck）。
- 桌面端用顶部分类条 `[data-cat]`（概览/活动/Tmux/Agent/服务），移动端用底部页签 `[data-p=0..4]`；支持跟手弹性左右滑动切卡，且横向滑动仅在页首或无内部横滚干扰时生效。

## 三、API 端点表（svcdash/handler.py 路由，均已实现）

| 端点 | 方法 | 说明 |
|---|---|---|
| `/` | GET | HTML 壳（lite 骨架 + BOOT 注入，gzip + ETag） |
| `/static/*` | GET | CSS/JS（ETag + immutable 缓存，304） |
| `/api` | GET | 服务列表 JSON（ip/port/pids/cmdline/cwd/type/unit） |
| `/api/sys` | GET | 负载/CPU/内存/磁盘/开机时长 + 水位 + top 进程 |
| `/api/tailscale` | GET | Tailscale 节点状态、Serve 代理、已连机器与外网检测 |
| `POST /api/tailscale/ping` | POST | `{peer}` Tailscale 节点 ping 延迟测速 |
| `POST /api/tailscale/netcheck` | POST | 触发 Tailscale 完整网络体检（DERP 延迟/UDP 连通） |
| `POST /api/tmux/wake` | POST | `{session,pane}` 一键唤醒推进 Tmux 任务（智能调用 Hermes 探查处理阻塞） |
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
5. **flex/grid 轨道被 nowrap 长文撑宽**（2026-09-26 首页磁贴右圆角被裁）：
   栅格/flex 子项里出现 `white-space:nowrap` 的长文本（如提交信息）时，该子项的
   min-content 会把整条轨道撑宽，移动端超出视口被 `#pages{overflow:hidden}` 裁掉右侧
   圆角。修法是给栅格/flex 子项（`.hp-portal-card`）加 `min-width:0`，让轨道回到
   容器宽、内部 ellipsis 正常截断。凡"某卡右侧被裁/圆角消失"先怀疑此坑。

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

## 六、活动流 Git 采集器

在线活动 API 只读取 `~/.cache/svc-dashboard/events.json`，不在请求过程中遍历仓库。
用户级 `svc-dashboard-activity.timer` 每分钟运行一次 `scripts/collect_activity.py`，扫描 `~/development` 下的 Git 仓库（并补充 `~/.hermes/worktrees`、家目录顶层独立仓库、agent worktree），合并最新提交与 GitHub 动态后原子更新 JSON。新仓库会在下一轮扫描自动纳入；活动页读取新快照无需重启 dashboard。

### 增量采集（#138）

每分钟一次全量 `git log --all -n 30 --name-status` 扫 100+ 仓库太贵（实测 13–18s、峰值 138–512MB）。现在分两层缓存：

- `~/.cache/svc-dashboard/repos-list.json`：仓库清单，10 分钟重扫一次；
- `~/.cache/svc-dashboard/repo-events-cache.json`：逐仓库提交事件 + HEAD 签名。

每轮只对每个仓库跑一次 `git log --all -1 --format=%H%x1f%ct` 取签名；签名未变直接复用缓存事件，只有有新提交的仓库才跑完整的 `--name-status`。稳态约 0.7–1.1s、峰值内存约 58MB。签名集合未变化时不写盘。

### 隐私打码（#138）

- `scripts/check_secrets.py --staged --fix`：pre-commit 时把命中的密钥/内网 IP/Tailscale IP/邮箱/电话就地改成 `******` 并重新 `git add`，不再阻断提交。
- `--commit-msg <file>`：commit message 同样就地打码。
- `--push`：推送无法安全改写历史，命中即阻断（fail closed）。
- 静态导出时 `export.py` 连 `app.js`/`app.css` 一起脱敏，源码里不许再硬编码内网 IP 或真实邮箱。
- 验证：`python3 scripts/verify_static_masking.py`（真实导出 + 逐文件扫描）与
  `--self-test`（注入用例）。

安装/更新：

```bash
install -Dm644 systemd/svc-dashboard-activity.service ~/.config/systemd/user/svc-dashboard-activity.service
install -Dm644 systemd/svc-dashboard-activity.timer ~/.config/systemd/user/svc-dashboard-activity.timer
systemctl --user daemon-reload
systemctl --user enable --now svc-dashboard-activity.timer
systemctl --user start svc-dashboard-activity.service
systemctl --user status svc-dashboard-activity.timer svc-dashboard-activity.service
```

采集日志：`journalctl --user -u svc-dashboard-activity.service -n 30 --no-pager`。验证快照中的 `paths` 包含新项目，`events` 中出现其新提交。


用户手机经 Tailscale（CGNAT 段 `100.64/10`，本机 TS IP=`<TS-IP>`）访问时，
页面里的服务链接主机要自动从 `<LAN-IP>` 切到 TS IP：

- 服务端（svcdash/handler.py `_is_tailscale_client`）：`_client_ip()` 落在
  `100.64/10` 网段 → BOOT 里 `tsMode=true`。
- 前端（static/app.js）：主机地址取自 `BOOT.tl.hosts`（`tailscale` / `lan`），源码不硬编码 IP；`linkHost(h)` 在 tsMode 下把 LAN 主机换成 TS 主机。
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
- 静态任务页（公开）：只发布 issue 标题 + 摘要，且按字段脱敏（`sanitize_text`：密钥/家目录/内网 IP）；
  不采集正文、分支、机器、条目编号与执行日志。页面不渲染任何操作按钮，右侧详情用马赛克占位条，
  不做"发布后 CSS 模糊"——模糊在开发者工具里可一键去掉，不能当隐私边界。带 `private` / `secret` /
  `no-publish` 标签的 issue 直接跳过。列表与详情都不发起任何 API 请求（静态版无 `/api/th/*`）。
- 静态服务页不提供详情弹窗；启动命令显示为 `[命令已隐藏]`，防止公开命令参数和工作目录。
- 静态 Agent 页的模型“测试”不执行真实请求，显示为静态快照提示；真实模型测试只能在需要登录/令牌的私有 dashboard 上执行。
- Agent 详情只在公开静态快照中走安全视图：二进制路径、进程 PID/命令、MCP 命令、个人技能/任务名称、提示词和平台账户标识会隐藏或泛化；版本、模型、资源占用、连接状态与调度状态保留。私有实时 `/api/agentdetail` 保留完整本机详情；`export.py` 生成静态 `BOOT.agentDetails` 时显式使用 `for_public=True`。
- 静态 Agent 总览保留 API 额度名称、水位百分比、重置时间与用量，隐藏额度账号标识；发布器独立刷新额度后再生成快照，避免因进程内缓存隔离导致静态页额度为空。
- 活动页事件分两类处理：`kind=commit` 的 Git 提交事件属于公开仓库信号，保留提交说明、文件路径、作者和 Diff 入口；Goal/watchdog 的 `complete`、`cleanup`、`recover`、`nudge` 等事件只保留 Goal ID、事件类型和时间，正文统一显示 `[内容已脱敏]`。
- 因此活动页出现“部分正常、部分 `[内容已脱敏]`”是预期行为，不是导出失败：前者是公开 Git 活动，后者是 Agent/Goal 内部日志。
- 自动发布器产生的 `svc-dashboard` / `Update sanitized static snapshot ...` 维护提交只保留最新一条作为运行状态，其余历史在首页和活动页折叠；活动页可展开全部自动发布历史。匹配仅针对提交说明以 `Update sanitized static snapshot` 开头的自动构建提交，其他 `svc-dashboard` Git 提交照常显示。
- 只读静态快照顶部的“在线版”入口用于切回实时 dashboard：从内网地址打开时回到当前内网主机，从 Tailscale 地址打开时回到当前 Tailscale 主机，从公网 GitHub Pages 打开时默认回到本机 Tailscale 地址（`BOOT.tl.hosts.tailscale`）。该入口只在静态只读版显示。
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

## TaskHub 集成（活动页 → 任务 / 日志）

「活动」页顶部多了三个子 tab：**记录 / 任务 / 日志**。任务不是另一套系统：它是本机
TaskHub 引擎（`taskhub.service`，只监听 `127.0.0.1:8096`）的能力，经 svc-dashboard 后端
转发后在仪表盘里呈现，界面完全沿用仪表盘样式。

- 后端：`svcdash/taskhub.py` 只做 HTTP 转发与整形（`/api/th/health|hosts|issues|runs|run|log`，
  POST `/api/th/dispatch|state|cancel|resume`），所有失败降级为 `{ok:false,msg}`，不影响仪表盘其它页。
- 前端：`static/app.js` 里的 `TH`/`thRender*` 一组函数；任务卡片显示标题 + 三行摘要 +
  `#编号 · 时间` + 状态/机器 chip，右侧「派发 / 恢复 / 日志」。
- 派发是**弹窗**（`.th-dispatch-modal`，挂 `body`，手机为底部滑层），不再内联插在列表顶部；
  只列**非 hidden** 的 agent（pi / Hermes 分配 / omp）和**在线**机器，选择项是自绘单选（`.th-opt`）。
  上一次选中的执行者/机器存 `localStorage["svc-th-dispatch"]`，下次打开直接复用（值失效才回落引擎默认）。
- 代码仓库不需要选：引擎按 Issue 正文/标签判断，判断不出直接拒绝（不会把 agent 丢进 dotfiles）。
- 任务数据仍由引擎持有（`~/.local/state/taskhub/taskhub.db`）；svc-dashboard 不写任务库。
- 修改后验证：`curl -s localhost/api/th/health`，再在浏览器打开 `/#cat=activity` → 任务，
  确认列表、任务详情、派发弹窗三处都可用（手机 390 宽无横向溢出、弹窗为底部滑层）。

## 页面外壳规范（所有页面统一）

功能越来越多，页面不再各写一套头/筛选/卡片，统一成四段式；改样式只动 `static/app.css`
末尾的「统一页面外壳」块，不要在页面内部临时发明新控件。

1. **页头 `.page-head`**：`h2`（17px/700）+ `.page-hint`（11.5px 灰，最多两行）+ 可选
   `.page-head-actions` 按钮组。不要再把说明塞进 `h2` 里的 `ghint` 硬拼一行。
2. **分段子标签 `.page-subnav` + `.page-subnav-btn`**：一个页面 2–5 个，灰色底槽 + 轻量
   选中块（`--bg-elev` + 1px 边框，不用纯白块压过内容）。窄屏等分、可横向滚动。
3. **工具行 `.filters` / `.page-tools`**：筛选 chip 与搜索框同高（窄屏 26px / 桌面 28px），
   与列表间距 12px。
4. **卡片 `.act-card|.ts-card|.th-card|.mcard|.gcard`**：统一 `--card-radius` + 1px 边框 +
   `--bg-panel`，内边距 12/14。
5. 移动端：`--page-pad-x: 13px`，页面底部留 `72px + safe-area`，固定导航不再压住最后一张卡。

已落地：**活动（单页时间线）**、**任务（任务 / Tmux / 日志 三个子页）**、服务（服务 / 定时任务）、
Agent（4 个运行时子页）、网络页头。新增页面照此四段式接，别再写 `.xxx-header` 私有样式。

任务页在 `#tmux-panel`（render.py 的 `_LITE_TMUX`），划分为两个子页：**智能体任务 (Tasks) / Tmux 终端 (Sessions)**。
- 顶部导航 `.page-subnav` 自由切换任务流与系统 Tmux 总览，右上角常驻「下发新任务」与刷新主操作。
- 任务列表支持「活跃任务 / 运行中 / 待派发 / 已完成 / 全部」Chips 过滤，卡片高度瘦身，单行截断摘要。
- 任务详情包含 5 阶段流水线 Stepper、智能体实时状态横幅、内联人机指令回复卡片（无需 prompt 弹窗）。
- 控制台双模：直连 Tmux 窗格捕获真彩色 ANSI 输出与快捷控制（滚屏开关/Ctrl+C/回车/唤醒/复制），支持切换结构化事件时间线与 Issue 原文。
- Tmux 总览恢复完整的会话列表、窗格信息、进程命令与实时微型终端。

列表按状态分组：**正在跑**（进度条 + 最近事件 + 回话/停止）、**待派发**（一行 + 派发）、
**已完成**（默认折叠）。点卡片进详情，详情页头结构固定为：状态徽标 + `#编号` + GitHub 箭头一行，
标题单独一行，最后一行左「仓库 · 机器 · 分支」右操作区。正文按区块卡片排列：进度（阶段条 +
一句话结论）、会话终端、执行时间线（stage 事件默认折叠，可"展开其余 N 条"）、Issue 正文、
历史执行（点任一条看原始输出）。

`TH` 状态对象必须声明在脚本靠前处（`let autoLocked` 之后），否则 `setCat()` 初始化阶段会踩 TDZ。

## 任务页样式约定

任务页的视觉规则集中在 `static/app.css` 末尾的 `#tmux-panel { --th-* }` 区块，用 token 统一间距
（4/8/12/16/20）与字号（10.5/11/12.5/13.5/14）。新增元素必须复用这些 token，不要再散落 prop 值。

- 左列表每行固定结构：状态小灯+文字 → `#编号 · 机器 · 阶段` → 时间 → 标题 → 最多两行摘要。
  行高目标 ≤100px；超过说明塞了多余的一行 meta。列表**没有搜索框**（用户明确不要），只有右上角
  一个「刷新」按钮 `.th-toolbar`。
- 桌面（≥701px）左列表与右详情**各自独立滚动**：`.th-split` 高度由 `thFitSplit()` 写入
  `--th-split-h`（视口高度 − 面板顶部，并对整页残留溢出再修正一次），两列 `overflow-y:auto` +
  `overscroll-behavior:contain`，页面本身不再滚动。手机仍是单栏整页滚动。
- 详情页头 `.th-head`：一行「状态徽标 + #编号 · 仓库 · 机器 + GitHub 箭头」，标题独占一行
  （21px），操作行在标题下方。桌面下页头 sticky 在右列里。操作区**只有一个主操作**
  （`.th-btn-primary`：实心蓝胶囊；运行中不显示派发，waiting_user 时主操作变成回信），
  其余全部是无边框幽灵按钮（`.th-btn`），停止用 `.th-btn-danger`。不要再给次要动作加描边方块。
- 正文是**文档式分节** `.th-sec`（不套卡片边框，靠 18px 留白 + 1px 细线分节）：状态（阶段轨
  `.th-rail`：点 + 连线，stage 未知时整条隐藏）、会话终端、执行时间线、Issue 正文（`.th-prose`
  74ch / 13px / 1.78，跟随右列滚动，不再单独限高）、历史执行（行列表）。
- 手机（≤700px）左右列必须走单栏：`#tmux-panel .th-split { grid-template-columns: minmax(0,1fr) }`
  在文件末尾兜底，否则桌面双栏规则会把详情压成一条缝（表现为整页空白）。
- 终态（cancelled/failed/succeeded）不显示百分比进度条，只留阶段条，避免"半截进度"误导。
- 轮询（会话预览/日志）必须走 `TH.busy` 互斥并只在活跃 run 上开定时器；否则多个 interval
  叠加会把渲染线程和后端一起拖慢。
- 用浏览器验收时注意静态资源缓存：`Page.reload` 要带 `ignoreCache=True`，否则看到的是旧
  app.js（表现为"改了没生效"）。
