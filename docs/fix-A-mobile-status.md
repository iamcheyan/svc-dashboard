# svc-dashboard P0+P1 整改 · Goal A（移动端遮挡 + 状态色语义）

## 背景
`docs/ui-audit-full.md` 是本整改的唯一事实依据（P0/P1 编号沿用文档）。
仓库：`/home/tetsuya/development/svc-dashboard`（分支 main，单文件 dashboard.py ~7580 行）。
服务：root systemd `svc-dashboard`（:80）。改动后必须 `sudo systemctl restart svc-dashboard` 并 curl 验证。

## 你的范围（只做这些，别碰别人的编号）
- **P0-1 移动端底部遮挡**（审计 H2/L4/T4）：`#track > .pg` padding-bottom（dashboard.py:3439）存在但实测遮挡——异步 fragment（/api/fragment: goals/events/toolchips）落地后 track 高度按 scrollHeight 重测的时机（:5193 附近）没兑现。修法：fragment hydrate 完成回调 + 图片/字体加载后触发重测；四个页面（概览最近活动/日志末条/服务末卡/工具页端口列表尾行）逐一滚动到底验证末条完整露出。
- **P0-2 Swap 状态色**（T2）：:5766 `row("", ...)` → `row(sw.percent >= 90 ? "bad" : sw.percent >= 50 ? "warn" : "", ...)`，与相邻内存行（:5763）阈值风格一致。顺带 T8：CPU 行（:5761）`>90 ? "warn"` 保持，不动。
- **P0-6 服务行运行状态色**（S1）：服务表行首加状态点（接 /api/manage 状态或 paused/badge 数据渲染），红=paused/异常 绿=正常 灰=历史，遵守全站状态色语义。
- **P1-2 指标条状态色**（H3）：概览 sysbar 指标（CPU/内存/磁盘）数值按 阈值 >90 红 / ≥75 黄 / 否则默认 上色，复用 renderHealth 阈值逻辑（:5762-5769）。
- **P1-3 日志筛选 chips 状态色 + 事件行色条**（L2）：成功=绿/告警=黄/失败=红/恢复=蓝 色点或色条。
- **P1-9 模型页秒数分级 + markdown 剥离**（M3/M4）：`a_ago` 秒数直灌（:686 i18n 定义 + :5338 附近调用）改为 秒/分/时 分级格式化；agent 卡最近活动文本剥离 markdown 记号（`**`、反引号、标题#）。

## 硬性纪律（AGENTS.md §四，全部真实踩过）
1. 改 DOM/删元素前 grep JS 全部引用并判空（85102dc 事故）。
2. const 声明必须在求值期 IIFE 之前（escHtml TDZ 事故 f8df6ef）。
3. 改完 `python3 -m py_compile dashboard.py` + 重启 + curl 200 ≠ 界面对：必须 CDP 双视口复验（桌面 1280×900 + 移动 390×844，console exception 收集为空）。工具：`python3 ~/.hermes/scripts/cdp_eval.py watch 8`（Chrome: Xvfb :101 + openbox + `google-chrome --no-sandbox --disable-gpu --user-data-dir=/tmp/chrome-gA --remote-debugging-port=9222`，视口用 Emulation.setDeviceMetricsOverride，注意视口覆写有粘性、切视口必须显式 set 并断言 innerWidth；截图前 Network.setCacheDisabled）。
4. 禁 emoji（全用现有内联 SVG icon 系统）；禁原生 alert/confirm/prompt/select。
5. 深浅双主题都要截图验证（状态色走 CSS 变量不得硬编码 hex）。
6. git：按功能分小 commit（message 中文、格式 `fix:/feat:/ui:`），最后 push origin main。

## 验收（写进最终汇报）
- 每项：修改行号 + 双视口截图路径（存 screenshots/fixA/）+ console 无异常。
- P0-1 需四页滚动到底截图各 1 张（末条完整露出）。
- P0-2 需 Swap 行特写（当前机器 swap 100% 正好是活证据）。
- 完成清单勾选 + 未完成项原因。
