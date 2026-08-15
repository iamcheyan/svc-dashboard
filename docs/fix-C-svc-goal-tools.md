# svc-dashboard P0+P1 整改 · Goal C（服务表 + Goal 卡 + 工具页重排）

## 背景
`docs/ui-audit-full.md` 是唯一事实依据（编号沿用）。仓库 `/home/tetsuya/development/svc-dashboard`（main，单文件 dashboard.py ~7580 行）。服务 root systemd svc-dashboard (:80)，改完重启 + curl 验证。

## 你的范围
- **P1-5 服务表命令列**（S2/S3）：桌面命令列改等宽字体 + 单行省略 + 点"详情"popover 展全（svc-detail 弹层已存在 :5227 附近，复用）；长命令把端口号视觉拆成 `88/00` 的问题随之消失。操作列固定不挤压内容列。
- **P1-6 移动服务卡命令折叠**（S4）：移动端卡片里长命令默认折叠 2 行（-webkit-line-clamp），点展开。
- **P1-8 Goal 卡行集恒定 + 异常处置**（G2/G3）：每张 goal 卡渲染恒定行集（缺值显 `—`，杜绝高低卡参差——卡内 flex column + footer margin-top:auto 已有基建）；paused/lost 状态的卡给"复制 resume 命令"之外的处置动作（如"标记忽略"接现有 ignoredSet 机制）。
- **P1-10 工具页分组重排**（T1）：9 区块（:3962-4040）重组为 4 组：「巡检」（健康检查+网络速测+计划任务）→「运维」（文件浏览+垃圾清理+服务重启）→「直达」（工具 chips+复制组）→「偏好」（主题，移到最后或折叠）。组标题用现有 gpanel 视觉语言，组内间距统一。
- **P1-11 工具页桌面 2 列**（T5）：cat=tools 时桌面 2 列 grid（巡检左 / 运维右，直达+偏好全宽收尾）。
- **P1-12 健康检查去重**（T3）：大字告警头（:5784-5785）与下方 tl_h_ports/tl_h_wd 行二选一——保留大字头（3 秒判断原则），删下方两行重复；或行内合并。注意端口心跳明细行保留。
- **P1-13 按钮风格收敛**（T6）：四套交互语言（顶栏胶囊/chips/蓝字链/tl-run 描边钮）收敛为 primary（描边胶囊）+ ghost（文字链）两级；gcopy 保持。逐处替换后全站过一遍视觉一致。

## 硬性纪律（同 AGENTS.md §四）
1. 改 DOM 前 grep JS 全部引用并判空。
2. const 声明顺序在求值期 IIFE 之前。
3. py_compile + 重启 + CDP 双视口复验（1280×900 + 390×844，console 零异常；工具 `~/.hermes/scripts/cdp_eval.py`；Xvfb :101 起 Chrome --remote-debugging-port=9223 避开他人端口）。
4. 工具页 G2 服务重启的 I-KNOW 护栏逻辑不许放松；清理 dry_run 默认 true 不许改。
5. 禁 emoji；禁原生控件；深浅双主题截图。
6. git 分小 commit（中文 message），push origin main。

## 验收
- 服务表长命令单行省略 + popover 展全截图（桌面）；移动卡折叠/展开截图。
- 工具页 4 分组桌面 2 列 + 移动单列截图（深浅主题各 1）。
- 健康检查去重后截图。
- console 零异常；截图存 screenshots/fixC/。
