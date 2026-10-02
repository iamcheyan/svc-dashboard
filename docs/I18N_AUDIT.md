# svc-dashboard 全界面文案三语完整性审计报告

- **审计对象**：`svc-dashboard`（纯 Python 标准库 + 静态原生 JS/CSS，root systemd 服务监听 80）
- **审计日期**：2026-10-02 ~ 2026-10-03（JST）
- **审计范围**：zh / en / ja 三语全部用户可见文本
- **最终状态**：**已完成并通过验证**，修复已推送 `origin/main`

---

## 1. 结论摘要

| 项目 | 结果 |
|---|---|
| 字典键数 | zh / en / ja 各 **656 键**（审计前 524，新增/复用 132） |
| 键集合一致性 | 三语完全一致（parity = true） |
| 占位符一致性 | 同键 `{var}` 集合三语一致，0 差异 |
| 空值 / 重复键 | 0 / 0 |
| 已确认 ISSUE | **全部修复**（详见 §4） |
| 自动化测试 | `python3 dashboard.py --selftest` → **16/16 通过**（11 原有 + 5 项新增 i18n 守卫） |
| 浏览器验证 | 3 语 × 桌面 1440×900 / 移动 390×844 × 5 页签 + 弹窗：原始键 **0**、console/pageerror **0**、横向溢出 **0** |
| 静态导出 | 三语产物 en/ja 页中文残留 **0**；密钥 / 内网 IP / 家目录路径残留 **0** |
| 附带修复 | `HOME_DIR` 未定义导致 3 项清理扫描恒失败的既有缺陷 |
| 提交 | `7681383`（agy 在途保全）→ `6808404` → `ab826cf` → `3b1fea9` |
| 远端 SHA | `3b1fea91a429ebe6333b8470e2ad5bd0e402337d`（`git ls-remote origin refs/heads/main` 已核对） |

**覆盖声明**：本报告覆盖实际检查到的全部界面与渲染路径（见 §2、§6）。机器标识/服务名/命令/专有名词/用户数据等按 §5 明确列为合理保留（EXEMPT），非遗漏。

---

## 2. 扫描方法与覆盖范围

多路交叉验证，不依赖单一手段（不只搜 `t()` 调用、不只比字典长度）：

1. **字典结构校验**：AST 解析 `L10N`，比对三语键集合、占位符集合、空值、重复键。
2. **引用反查**：全量提取 `index.html` 的 `{{T:key}}`、`app.js` 的 `t("key")`、Python 的 `t(lang, "key")`，与字典求差集，定位「引用但未定义」的键。
3. **硬编码字面量扫描**：AST 扫描 Python 字符串常量（排除 docstring/注释）；自研 **多行感知 JS tokenizer**（正确处理模板串 `${}` 嵌套、正则字面量、注释）扫描 `app.js`/`index.html` 字符串字面量中的 CJK。
4. **渲染路径覆盖**：Python 生成 HTML（`render.py`）、服务端片段（`/api/fragment`）、API 内嵌标签、静态导出三语产物、CSS 伪元素。
5. **运行时验证**：`?lang=zh|en|ja` 逐页；无头浏览器桌面 1440×900 + 移动 390×844 × 5 页签 + 各弹窗/浮层/筛选器；采集 console/pageerror 与横向溢出。
6. **语言传递验证**：切换语言后动态加载（fragment/API）是否跟随；POST 动作返回消息的语言一致性。
7. **安全门禁**：`scripts/check_secrets.py` 全仓 + 静态导出产物 `scan_for_secrets`。

### 覆盖的界面清单

概览 / 活动 / Tmux / Agent / 服务 五页签（桌面分类条 + 移动底部页签）；服务详情弹窗、Goal 详情弹窗、Agent 详情滑层、Tmux 全屏查看器、轨迹浮层、AI 清理弹层、uiConfirm/uiNotice；服务分类筛选、活动筛选、Agent 筛选；空/加载/错误/权限状态；静态只读快照三语页面。

---

## 3. 审计基线（修复前）

- `L10N` 三语各 524 键，结构本身健康（键集合、占位符一致，无空值/重复键）。
- 但存在 **4 个被引用却未定义的键**，界面直接渲染原始键文本（三语皆然）。
- 前端 `app.js` 有大量硬编码中文 UI 文案（en/ja 页面实测泄漏）。
- 后端约 46 处 `msg` 硬编码中文/英文，且多数路由未接收 `lang`。
- 静态导出 en/ja 页面混入中文脱敏占位符与原始键。
- 附带：`tools.py` 引用未定义的 `HOME_DIR`，致 `/api/cleanup` 三项扫描恒失败。

---

## 4. ISSUE 清单与修复（全部已完成）

### P0 — 引用但未定义的键（界面直显原始键）

| 键 | 引用位置 | 影响 | 修复 |
|---|---|---|---|
| `agent_refresh_quota` | `static/index.html` Agent 页刷新额度按钮 | 三语均显示 `agent_refresh_quota` | 复用既有 `rt_refresh` |
| `g_refresh` | `static/index.html` Tailscale 页刷新按钮 | 三语均显示 `g_refresh` | 复用既有 `refresh` |
| `g_resume` | `static/app.js` 活动流 resume 按钮 | 有条件显示原始键 | 新增 `g_resume` |
| `g_retrying` | `svcdash/render.py` Goal 卡片 API 重试行 | 有条件显示原始键 | 新增 `g_retrying` |

### P1 — 前端硬编码 UI 文案（`static/app.js` / `static/index.html`）

全部改走 `t()`，修复后 `app.js` 字符串字面量 CJK 为 **0**：

- 时间后缀双 bug：`agoStr(...) + "前"`（4 处）→ 实测 `46d ago前`、`5 分前前`；`"刚刚"`。
- 表格/按钮：`操作`、`活跃时间`、`立即触发一次`/`触发`、`Hermes 智能唤醒推进`/`推进`、`预览终端输出`/`预览`、`唤醒推进`。
- 标题副文本：`最新活跃在最前`、`最新活跃优先`、`最近执行优先`。
- 服务管理：`Zircon WS 网关`、`随主服起停`。
- 冻结台账：`当前无被冻结的服务…`、表头、`暂无操作记录`、`通用冻结服务台账`、`最近管理记录`、`Audit History (最新在最前)`。
- Tailscale：`代理至`、`诊断穿透与 DERP 节点中…`、`UDP 穿透`、`正常 (OK)/受限`、`UPnP 打洞`、`支持 (Yes)/未启用`、`最优 DERP 中继`、`诊断失败`、`超时 / 失败`、`错误`。
- Tmux：`活跃窗口`、`后台 Tmux 唤醒恢复该任务`、`Attached/Detached`、`(no terminal output captured)`、`${s.activity_ago}s ago`。
- Agent：`暂无外部接入平台`、`{n} 条设定`。
- 按钮瞬时态：`⚡ 分析推进中…`、`已推进`、`推进失败`、`已触发`、`失败`、`错误`。
- Tmux 预览错误：`无法获取终端输出:`、`未知`、`获取失败:`。
- 配额桶名：`额度`、`GPT 储备`、`周额度`、`Gemini 周`、`Claude/3P 周`。
- 活动页日期标题：`Commits on … (Today/Yesterday)` 等分支。
- 静态版终端占位：`[公网静态只读视图：终端屏幕输出已安全屏蔽]`。
- aria-label：`返回首页`、`Lines`。
- 时间格式：`toLocaleString()` 未带 locale → 引入 `LOCALE_TAG`（zh-CN/en-US/ja-JP）。

### P1 — 语言传递缺陷

`apiPost()`/`tlPost()` 未携带 lang，后端按 `Accept-Language` 回落 → 界面语言与 POST 返回消息不一致（实测 ja 界面下 `/api/svcctl` 返回英文）。修复：POST/GET 统一附加 `lang`，各路由按该语言生成消息。

### P1 — 后端消息硬编码（约 46 处）

`handler.py`（tasks/run、token、goaldetail、trajectory、commitdiff、agentdetail、nettest 等）、`agents.py`（tmux 唤醒）、`goals.py`（goal resume/detail）、`runtimes.py`（模型测试/装卸）、`aicleanup.py`、`tools.py`（清理/用户服务/网络测速）、`svcctl.py`、`repos.py` — 全部接入 `lang` 并走字典（`mm_*`）。

### P1 — 服务端生成文案

`render.py`（`tmux sessions/panes`、`暂无 tmux session`）、`manage.py`（6 个受管单元 label/desc 与动作名）、`procscan.py`（暂停行 `(已暂停)`）、`tools.py`（清理项 detail）。

### P1 — 静态导出脱敏占位符

`privacy.py` 的 12 类中文占位符（`[内容已脱敏]` 等）→ 新增 `red(kind, lang)`，导出按语言分别脱敏（services/tmux/runtimes/tools/agentDetails）。

### 附带修复（审计中发现的非 i18n 缺陷）

`svcdash/tools.py` 引用的 `HOME_DIR` 从未定义（历史遗留），致 `/api/cleanup` 的 `hermes_cache`/`omp_jsonl`/`binobj` 三项恒返回 `name 'HOME_DIR' is not defined`、清理面板显示为空。已按仓库既有约定补上定义；修复后三语 detail 正常。

---

## 5. 合理保留（EXEMPT）及理由

以下**不属于**缺译，按任务要求显式说明：

| 类别 | 示例 | 理由 |
|---|---|---|
| 机器标识 | `systemd`、`docker`、`tmux`、`unit` 名、容器 ID、PID、端口 | 技术标识，翻译会破坏可用性 |
| 服务名 / 命令 / 路径 | 服务进程名、`cmdline`、`cwd` | 数据内容，非 UI 标签 |
| 技术缩写 | `API`、`CPU`、`UDP`、`UPnP`、`DERP`、`IPv4/IPv6`、`JSONL`、`Context`、`Retry` | 通用技术缩写（周边说明已翻译） |
| 专有名词 | `Mikata`、`Hermes`、`OMP`、`Gemini`、`Claude`、`GPT`、`Tailscale`、`Zircon`、`Docker` | 品牌/产品名 |
| 语言自称 | 语言菜单中的 `简体中文`、`日本語`、`English`、`AUTO` | 语言选择器惯用自称 |
| 用户数据 | Goal 标题、提交信息、终端输出、记忆内容、审计历史行 | 自动生成内容，不翻译 |
| 开发者日志 | `console.log`/`stderr` 的 `[svc-dashboard] theme -> …` 等 | 非用户界面 |
| CLI 输出 | 启动/导出脚本的终端打印 | 命令行，非页面 |
| 测试断言 | `selftest.py` 内部字符串 | 测试代码 |

---

## 6. 验证证据

### 6.1 自动化测试

```
$ python3 dashboard.py --selftest
Ran 16 tests in 0.381s
OK
```

新增 5 项 i18n 守卫（`I18nParityTest`），并已双向验证有效性：

- **负向**：故意注入未定义键引用 + 硬编码 CJK → 守卫准确报错。
- **正向**：故意删除 en 字典 1 个键 → `test_same_key_sets` 立即报错。

### 6.2 浏览器（真实服务，重启后复验）

| 语言 | 视口 | 页签 | 原始键 | console 错误 | 横向溢出 |
|---|---|---|---|---|---|
| zh | 1440×900 / 390×844 | 5 | 0 | 0 | 0 |
| en | 1440×900 / 390×844 | 5 | 0 | 0 | 0 |
| ja | 1440×900 / 390×844 | 5 | 0 | 0 | 0 |

en 页残留 CJK 全部为用户数据（提交信息）；ja 页命中均为合法日文（如 `概要`、`活動`、`最終活動`）。

### 6.3 语言传递与动态加载

- 语言菜单切换 zh↔en↔ja：URL、`BOOT.lang`、导航、动态面板（定时任务、状态卡）即时跟随。
- 「自动」选项正确回到浏览器语言；`?lang=fr` 等非法值回退默认语言，无原始键。
- POST 动作消息按界面语言返回（ja：`停止不可(自身/SSH/保護対象)`、`resume コマンドが空です`、`未対応の操作`）。
- `/api/manage`、`/api/cleanup` 三语 label/desc/detail 实测本地化。

### 6.4 静态导出三语

| 文件 | 中文脱敏占位符残留 | 密钥/IP/家目录残留 |
|---|---|---|
| `index.html`（zh） | 正常（中文） | 0 |
| `index-en.html` | **0** | 0 |
| `index-ja.html` | **0** | 0 |

### 6.5 安全门禁

`scripts/check_secrets.py` 全仓通过；静态导出三语经 `scan_for_secrets` 全部 CLEAN。

---

## 7. 提交与远端核对

| # | SHA | 说明 |
|---|---|---|
| 1 | `7681383` | 经用户授权，原样保全 agy 在途的 14 个未提交文件（零改写），单独提交 |
| 2 | `6808404` | `fix(i18n): 补齐三语字典缺键并本地化前端硬编码文案`（i18n.py + app.js + index.html） |
| 3 | `ab826cf` | `fix(i18n): 后端消息与脱敏占位符按请求语言生成`（13 个后端模块） |
| 4 | `3b1fea9` | `test(i18n): 增加三语一致性与硬编码守卫测试`（selftest.py） |

每次 push 后均以 `git ls-remote origin refs/heads/main` 核对：

```
本地 HEAD  = 3b1fea91a429ebe6333b8470e2ad5bd0e402337d
远端 main  = 3b1fea91a429ebe6333b8470e2ad5bd0e402337d   ✅ 一致
```

服务已 `systemctl restart svc-dashboard` 并确认 active、`/api/sys` 返回 200。

---

## 8. 边界与风险

- **已覆盖**：本报告 §2 列出的全部界面、渲染路径与语言维度均已实测；三语字典完整且有一致性守卫。
- **未做/超范围**：未改动 root systemd 服务定义与部署配置（除按流程重启目标服务）；未推送 gh-pages（公网静态站需独立发布流程，本任务仅验证导出产物正确性）。
- **风险**：
  1. 本次 `git apply` 的补丁体量较大（17 文件），已通过 `node --check`、`py_compile`、selftest、双视口浏览器复验，但**仅覆盖自动化与人工抽查范围**；未经逐行人工复核的极端边界（如并发语言切换竞态）未专项压测。
  2. 动态数据的语言由请求 `lang` 决定；若未来新增 API 路由未透传 `lang`，可能重现本次的语言传递缺陷 —— 已通过「引用键必须存在」与「前端硬编码守卫」测试拦截主要回归，但**新增路由的 lang 透传仍依赖开发者自觉**（建议后续在 handler 层统一注入）。
  3. `HOME_DIR` 修复恢复了既有扫描能力；首次扫描在大目录上可能略慢（属预期）。
