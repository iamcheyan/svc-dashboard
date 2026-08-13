# svc-dashboard 智能化改造（Goal 进度卡片 + 负载水位）— 完整任务目标

## 一、背景

svc-dashboard（~/development/svc-dashboard/dashboard.py，纯 Python 标准库单文件，
systemd 服务 80 端口）目前只有"监听端口列表 + 系统快照"。用户重度使用
Hermes + omp 多 goal 并行工作流（手机遥控、窗口期冲量），需要面板直接回答
"goal 都怎么样了 / 还能不能再开"。

已有资产（先读再写，别重复造）：
- 另一个修复中的小弟可能刚改过 dashboard.py 的 agent 分类（deleg_16d9659f，
  做了 git pull 再动手，若有冲突以它的 agent 分类逻辑为基础叠加本次功能）
- ~/.omp/logs/goal-watchdog.log — 每5分钟 watchdog 状态日志（nudge/restart/complete 记录）
- ~/.omp/logs/goal-completed.log — 新增的完成 goal 台账（含 resume_cmd）
- ~/.omp/agent/sessions/*/*.jsonl — goal 转录（尾部时间戳=活跃度）
- tmux 会话 = 每个 goal 一个（omd/yomu/fudoki 等，pane 里 omp TUI 头部显示
  `Goal 45K` 上下文体积和进度清单 `├─ II. Phase 1 · 0/3`）

## 二、功能需求

### A. Goal 进度卡片（替代/增强现有 agent 分类）

每个在跑 goal 一张卡片：

1. **标题行**：goal 名（tmux 会话名或 watchdog GOALS 数组第5字段 LABEL）+ 状态灯
   （🟢 active / 🟡 paused / 🟠 Retrying / ✅ completed）
2. **上下文体积**：从 tmux pane 抓 omp TUI 头部 `Goal 45K` 字样解析
   （>800K 黄色警示、>1.2M 红色"建议停止"，用户踩过 1.6M 的坑）
3. **最近活动**：对应 session jsonl 的 mtime（"42 秒前 / 5 分钟前"），
   >10 分钟标灰（可能 STALLED，watchdog 会处理）
4. **API 重试检测**：tmux pane 文本含 `Retrying (\d+)/10` 时状态灯变 🟠
   并显示重试次数（接口抖动 ≠ 卡死，用户要知道区别）
5. **进度清单**（尽力而为）：pane 文本里的 `├─/└─ II. Phase 1 · 0/3` 行抓出来
   显示最近 1-2 条；抓不到就不显示，不要报错
6. **操作**：`复制 resume 命令` 按钮（clipboard，无鉴权不做杀/停操作）
7. **已完成 goal 折叠区**：解析 goal-completed.log，按时间倒序列出
   （goal 名 + 完成时间 + transcript 名），默认折叠点开可见

数据获取方式：复用现有 dashboard 的进程扫描框架，新增
`subprocess tmux capture-pane -p -t <session>` + jsonl mtime + 日志解析，
全部每次请求时实时采集（无后台线程，保持零依赖与静默设计）。

### B. 负载水位线（"还能开几个 goal"）

系统信息卡片区加一行：

```
建议并发：还可开 0 个 goal（load 12.4 / 4核 → 🟣 过载）
```

规则：load15 < 6 → 绿"还可开 1-2 个"；6-10 → 黄"满载"；>10 → 红"先别开"。
旁边列 **CPU/内存 top5 进程**（一行一个：`86% godot-mono`、`40% bun omp`），
让用户一眼看到该杀谁。

### C. 快捷工具入口

顶部（系统卡片下方）加一排工具链接 chips（检测端口存活才显示）：
dbeditor:8810 / dbviewer:8800 / wilviewer:8765 / mapviewer:8899。
样式沿用现有分类 chips。

### D. 事件时间线（简版）

新分区"最近事件"：解析 goal-watchdog.log 最后 20 条 + goal-completed.log
全部，合并按时间倒序，一行一条（`08:25 [zdocs] ✅ 完成`、
`08:15 [botgoal] watchdog 重启`）。样式与 agent 卡片分区一致。

## 三、技术约束

- **纯 Python 标准库**（http.server/psutil 都不许加——psutil 本来就没用，
  CPU/内存用现有 dashboard.py 里的 /proc 解析方式）
- 单文件 dashboard.py 内追加；无后台线程/定时器（保持"没人访问零消耗"）
- 移动端适配：卡片单列、chips 可横向滚动（现有 CSS 已是深色移动端风格，
  沿用；新增区块都要在 390px 宽下可读）
- tmux capture-pane 失败/goal 不存在时优雅降级（显示"会话丢失"而不是崩）
- 日志解析加 try/except，格式不对显示原始行

## 四、验收标准（全部满足才算完成）

1. ✅ 手机 390px 视角：goal 卡片区显示当前全部在跑 goal（至少 omd/yomu/fudoki
   3 个），每张含状态灯+上下文体积+最近活动时间
2. ✅ 上下文体积 >800K 的 goal 卡片显示黄色警示（用 fudoki 测试，它 400K+；
   如实显示即可，黄灯逻辑用单测或 dry 检查证明）
3. ✅ 负载水位行显示"还可开 N 个 goal"+ top5 进程列表
4. ✅ 已完成 goal 折叠区至少列出 zdocs（今天完成的，goal-completed.log 有记录）
5. ✅ 事件时间线显示 watchdog 最近动作（重启/nudge/完成各至少能出现一类）
6. ✅ 工具入口 chips：dbeditor(8810) 存活时显示且点击直达
7. ✅ 桌面 1280 与手机 390 视口截图各一张，无布局破碎、无 Python 报错
   （/tmp/svc_dash_desktop.png、/tmp/svc_dash_mobile.png，
   用无头浏览器截图：DISPLAY=:100 有 Xvfb+openbox）
8. ✅ 服务重启后 80 端口正常响应（curl 首页 200 且含"Goal"字样区块）
9. ✅ git commit + push 到 iamcheyan/svc-dashboard（中文信息）；
   dashboard.py 改动前先备份为 dashboard.py.bak-<date>

## 五、边界

- 只改 ~/development/svc-dashboard/ 仓库
- 不动 ~/.omp/ 配置与 goal 会话本身（只读采集）
- 不引入任何第三方依赖
- 若 agent 分类修复小弟的改动已在 master，基于它叠加；若还没 push，
  在本地 master 上叠加并注明两者关系
