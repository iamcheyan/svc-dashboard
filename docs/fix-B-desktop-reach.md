# svc-dashboard P0+P1 整改 · Goal B（桌面可达性 + 桌面布局）

## 背景
`docs/ui-audit-full.md` 是唯一事实依据（编号沿用）。仓库 `/home/tetsuya/development/svc-dashboard`（main，单文件 dashboard.py ~7580 行）。服务 root systemd svc-dashboard (:80)，改完 `sudo systemctl restart svc-dashboard` + curl 验证。

## 你的范围
- **P0-3 日志页桌面可达**（L1）：桌面 CATS（:6402-6405）只有 home/goal/svc/tools；把日志页做成桌面可达——CATS 加 `["log", "tab_log"]`，CAT_SELS 加 `log: ["#logpage"]`，`#logpage` 桌面 `hidden` 控制（现在 :6297 附近 `$("logpage").hidden = true` 硬锁）。`initLogPage`（:5125 附近）首行 `if (!isMobile()) return;` 改为双端可用（内部 mobile 专属逻辑保留判断）。桌面布局：agent 选择器 + 事件时间线用横向空间（桌面双栏：左 agent 列表/右时间线，或全宽时间线均可，参考 web-dashboard-enhancement skill 的"桌面=横向多列"原则）。
- **P0-4 模型页桌面可达 + 名实修正**（M1/M2）：同上把 `#agents-page`（initAgentsPage :5321 `if (!isMobile()) return;`）开给桌面；页签名实问题（叫"模型"实为 agent 任务卡）：CATS 项用 "agent" 文案（i18n 三语同步），或在该页补真正的模型检测区块——选前者（轻量、诚实）。
- **P0-5 桌面 Goal 首屏空白**（G1）：桌面 cat=goal 时 Goal 卡区加载前是两行字+726px 空白——复用 `mobileSkelDiv`（:5233）做骨架占位。
- **P1-1 概览页桌面多列**（H1）：`#hp-grid`（CAT_SELS.home :6407）桌面改 `grid-template-columns: 2fr 1fr`（Web 服务磁贴左、Goal 摘要右），指标 5 卡一行 `repeat(5, 1fr)` 铺满，仓库卡保持全宽。
- **P1-4 横滚容器渐隐 mask**（L3/S6）：横向 chips 容器（服务分类、日志筛选、主题三选）加 CSS `mask-image` 左右渐隐（一处公用 class 全站生效）。
- **P1-7 表头胶囊改列名**（S5）：服务表桌面表头的胶囊样式改回正常列名样式（30min 顺手项）。

## 硬性纪律（同 AGENTS.md §四）
1. 改 DOM 前 grep JS 全部引用并判空；删除任何元素必须全量 grep。
2. const 声明顺序在求值期 IIFE 之前（TDZ 事故 f8df6ef）。
3. py_compile + 重启 + CDP 双视口复验（1280×900 + 390×844，console 零异常；Emulation.setDeviceMetricsOverride 有粘性，切视口显式 set + 断言 innerWidth；Network.setCacheDisabled 防缓存毒害）。工具：`python3 ~/.hermes/scripts/cdp_eval.py`。
4. 移动端 6 页签结构不许破坏（#track 分页、手势、tabbar 高度都是现网行为——改完移动端逐页过一遍）。
5. 禁 emoji；禁原生 alert/select；深浅双主题截图。
6. git 分小 commit（中文 message，`fix:/feat:/ui:` 前缀），push origin main。

## 验收
- 桌面 1280：catbar 出现 log/agent 新分类，点击进入对应页面截图（各 1）+ console 零异常。
- 概览桌面 2fr/1fr 布局截图；Goal 桌面骨架→填充过程截图。
- 移动端 6 页签回归截图（s0 各页）+ 无遮挡无错位。
- 截图存 screenshots/fixB/。
