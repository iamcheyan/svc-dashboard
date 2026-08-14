# svc-dashboard 运维全家桶（文件浏览/健康检查/垃圾清理/新页签「ツール」）— 完整任务目标

## 一、背景

用户手机+tailscale 随身管理这台服务器。之前 svcmobile goal 计划过文件浏览但未落地。
本 goal 补齐三大功能 + 新增「工具」页签聚合。**注意：另一个修复任务正在处理
"页面错乱"回归——先 git pull 最新再动手，若它的修复还没 push，基于当前 HEAD 做
但不要动它改的区域（topbar/JS 模板字符串）。**

## 二、新页签「ツール」（底部第六页签：概要/日志/Goal/服务/模型/ツール）

### F1 文件浏览（核心）
- 端点（纯标准库）：
  - `GET /api/fs/list?path=...` 目录列表（名称/大小/mtime/类型）
  - `GET /api/fs/file?path=...&mode=view|download` 文件预览/下载
- 根白名单：`~/development`、`~/NAS`、`/tmp`、`~/.omp/logs`（只读浏览+下载）
- **安全**：os.path.realpath 后必须以白名单根开头（防穿越）；`.env`/`*key*`/`*secret*`/
  `id_rsa*`/`*.pem` 文件名模式直接 404；符号链接跟随一层并复检 realpath
- 预览类型：图片（png/jpg/webp/gif→直接显示）、文本（md/py/js/ts/json/log/txt/yaml/
  toml/cs/rs→文本渲染，>1MB 只给下载）、其他→下载按钮
- 前端 UI：面包屑路径+目录列表（文件夹优先）+点击进入+文件点开（图片 lightbox/
  文本面板/下载）；文件名过滤框（前端）；隐藏文件开关；目录大小不自动算
  （可选「计算大小」按钮单目录 du，5s 超时放弃）

### F2 服务器健康检查
- 端点 `GET /api/health`：一次性快检，返回 JSON：
  - 负载/CPU/内存/磁盘/swap（复用现有 sys_info）
  - **磁盘趋势**：读 /tmp/svc-disk-history.json（每次检查追加当天一条，保留 30 天），
    无历史则记基线；按 日增速线性外推「预计满盘日期」
  - 温度（若 /sys/class/thermal 可读）
  - 关键进程存活：dotnet(ServerCore)/syncthing/tailscale/immich 系（可配置列表）
  - 端口心跳：对已注册服务端口逐个 TCP connect（500ms 超时）标 up/down
  - 最近 1h watchdog 异常计数（解析 goal-watchdog.log）
- UI：「ツール」页顶部健康卡：总体 ✅/⚠/❌ + 分项列表（每项一行+状态灯+关键数值）；
  「跑一次检查」按钮（不做自动轮询）

### F3 垃圾清理（安全优先，只清无争议项）
- 端点 `POST /api/cleanup`（dry_run 默认 true！先扫后清）：
  - 扫描项（每项算出可释放量，列表展示，用户勾选后才真清）：
    1. journal 超过 200M 的部分（vacuum-size）
    2. apt 缓存（/var/cache/apt/archives/*.deb）
    3. /tmp 超 7 天的旧文件（排除 in-use：godot-mono/dbeditor/map_links/当天文件）
    4. ~/.hermes/cache/terminal-output 超 3 天
    5. ~/.omp 30 天前会话 jsonl
    6. 各仓库 bin/obj（列出来但默认不勾——会触发重建）
    7. docker：docker system df 结果展示（prune 按钮单独，需二次确认）
  - 真清执行：逐项跑+记录释放量；**任何一项失败不影响其他项**；结果表展示
  - 红线：不碰用户媒体（nas_album/music）、System.db、git 历史、~/.env、
    白名单目录外的一切
- UI：扫描按钮 → 项目列表（勾选框+大小+说明）→「执行清理」→ 结果

### F4 快速复制组（小）
- 健康卡下方：ssh 命令（tetsuya@<host>）/ tailscale IP / 局域网 IP，点击复制

## 三、还能加的（用户问"还能再增加什么"——全部实现，小而美）
- **G1 快捷启动**：「ツール」页常驻工具直达 chips（dbeditor:8810/mapviewer:8899/
  wilviewer:8765/uieditor:8820/dbviewer:8800/webclient:8822/yomu:8830/fudoki:8831
  —— 检测端口存活才亮，点击新窗打开；tailscale 来源自动切主机）
- **G2 服务重启快捷**（可选开关）：对 systemd 用户级服务（svc-dashboard 自身除外）
  显示 systemctl --user restart 按钮——**默认隐藏**，localStorage 输入确认字符串
  `I-KNOW` 后开启（无鉴权面板的写操作护栏）
- **G3 网络速测**：按钮触发 curl 本机→外网一个大文件头（如 GitHub release HEAD）测
  延迟；tailscale ping（tailscale status 解析）显示对端延迟
- **G4 计划任务一览**：crontab -l 解析展示（只读）

## 四、验收
1. 文件浏览：浏览 development/NAS 成功；图片预览+文本查看+下载各一截图；
   `?path=../../etc/passwd` 404；`.env` 404（日志证明）
2. 健康检查：跑一次返回全项；磁盘趋势基线落盘；端口心跳有 up/down 区分（截图）
3. 清理：dry-run 扫描列表含 ≥5 项各带大小；勾选执行后 df 对比释放量展示；
   失败项不影响其他项
4. ツール页签在底部六页签中；桌面 ≥768 布局正常
5. G1 chips 存活检测正确（拔掉一个服务端口验证变灰）；G3 速测出数
6. py_compile/重启/双视口/console 零报错/占位符零残留
7. commit+push（中文）

## 五、边界
- 纯标准库；单文件；无鉴权不做破坏性写（清理有 dry-run+勾选双闸）
- 与"错乱修复"任务的改动合并时以 pull 最新为基底
- du/清理扫描要单线程+超时保护（负载敏感，还有 goal 在跑）
