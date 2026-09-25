# svc-dashboard 精简与删除文件浏览功能 Goal

## 目标

在现有仓库 `/home/tetsuya/development/svc-dashboard` 的分支 `feature/simplify-dashboard` 上，完成一次可验证的 svc-dashboard 功能精简，并彻底删除“文件浏览”功能。

## 当前背景

- 这是本机服务器状态面板，生产实例由 root systemd 单元 `svc-dashboard.service` 提供，默认监听 `0.0.0.0:80`。
- 当前仓库已有用户未提交改动：`AGENTS.md`、`README.md`、`static/app.js`、`svcdash/agents.py`、`svcdash/runtimes.py`。这些改动属于用户资产，必须先查看并保留；禁止 reset、clean、stash、覆盖或回滚。
- 当前工作分支必须保持为 `feature/simplify-dashboard`，不要创建副本仓库或切换到其他分支。
- 项目是 Python 标准库后端 + 静态 HTML/CSS/JS 前端，无构建依赖。

## 设计方向

将主导航和首页收敛为：

1. **概览**：只回答服务器是否正常、是否有告警、关键资源、常用服务、Goal 摘要、少量最近事件。
2. **服务**：紧凑展示服务名、端口、状态、资源占用、运行时间；低频命令/工作目录/PID 等放详情或隐藏，不在默认列表堆叠。
3. **Goal**：默认聚焦运行中、异常、最近完成的 Goal；保留详情能力，但不要在首页铺满原始事件流。
4. **管理**：承载模型、Agent、日志、定时任务、网络/健康检查、清理等低频功能。

移动端和桌面端都要遵守现有设计规范：简洁、少框、无原生弹窗/原生下拉/原生可见 checkbox；移动端 390×844，桌面端至少 1280×900。

## 必须完成：删除文件浏览功能

“文件浏览”必须是彻底删除，而不是仅从导航隐藏：

- 删除前端文件浏览入口、页面、按钮、文案、事件处理、状态和相关 CSS。
- 删除后端 `/api/fs/list`、`/api/fs/file` 路由及其专用实现、白名单/路径浏览逻辑；如果某个 helper 只服务于文件浏览，也一并删除。
- 更新 README、AGENTS 或 API 文档中关于文件浏览的说明；不要误改用户已有内容，合并时只改必要行。
- 全仓库残留检索：`fs/list`、`fs/file`、`api/fs`、文件浏览相关中文/英文标识不得仍作为可用功能存在。历史文档如必须保留，明确标记为已删除，优先删除过时说明。
- 不删除健康检查、服务控制、Goal 详情、模型检测、Agent 运行时等其他能力。

## 安全边界

- 不改动生产数据库、NAS 数据、用户认证、Telegram、Hermes 配置或其他服务。
- 不删除其他项目文件。
- 不改变 `svc-dashboard.service` 的端口，仍以 80 为生产验证目标。
- 不删除后端 API，只因“看起来低频”而删除；只有文件浏览 API 按上述要求删除，其他低频能力可从主导航移入管理区。
- 不把密码、Token、Cookie、私有日志或完整环境变量写入仓库、截图或总结。

## 实施要求

1. 先读取项目 `AGENTS.md`、README、`git status` 和用户当前 diff，绘制现有页面/路由/初始化引用关系。
2. 删除文件浏览前，对相关符号做全仓库引用清单，避免删 HTML 后遗留 JS 初始化异常。
3. 首页减法优先复用现有 API 和刷新路径，不新增重复网络请求；空告警/空 Goal/空事件区块默认隐藏。
4. 桌面端利用横向空间；移动端保持单列、底部导航和安全区适配，不能把桌面布局简单压缩成手机布局。
5. 静态 JS/CSS 发生修改时按仓库既有方式更新缓存版本号，避免手机继续读旧资源。
6. 代码中禁止新增 `alert`、`confirm`、`prompt` 或 emoji UI。

## 验证要求

必须实际执行并记录结果：

- `python3 -m py_compile dashboard.py svcdash/*.py`
- 相关后端模块 import/smoke test，避免包拆分后的运行时 NameError。
- 全仓库残留搜索，确认文件浏览 API/入口没有可用残留。
- `git diff --check`。
- `sudo systemctl restart svc-dashboard` 后确认 `systemctl is-active svc-dashboard`。
- `curl` 验证 `/`、`/api`、`/api/sys`、`/api/health` 等仍返回 200；确认删除的 `/api/fs/list` 和 `/api/fs/file` 不再提供原功能。
- 通过浏览器/CDP 或项目现有截图脚本验证 390×844 与 1280×900：页面可加载、无 console exception、主导航和精简首页可用、服务/Goal/管理入口可进入。
- 检查服务日志，没有因本次改动新增异常。

## Git 交付

- 只提交本目标相关文件；用户原有未提交改动不得被覆盖、回滚或混入无关重排。
- 在 `feature/simplify-dashboard` 上形成一个或多个清晰提交；提交前复核 `git diff`。
- 如果远端允许，推送该分支并核对远端 SHA；如果推送受阻，准确报告阻塞原因，不伪称已推送。
- 最终总结必须列出：删除了哪些文件浏览入口/API、首页/导航改了什么、验证命令真实输出、服务是否重启、提交/推送 SHA、剩余风险。
