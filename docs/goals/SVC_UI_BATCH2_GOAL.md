# svc-dashboard UI 深度改造第二批（emoji→SVG + 明暗主题 + topbar 重设计 + 曲线增项）— 完整任务目标

## 一、背景与现状

单文件 `dashboard.py`（约 5900 行，纯标准库，前端内嵌模板字符串）。今天已完成：
每页独立高度（track 跟随当前页 scrollHeight，见 applyPagesX）、禁止双指缩放
（viewport maximum-scale=1 user-scalable=no）、负载曲线已加内存%/Swap% 两线
（CPU 蓝 #6ea8dc / load 绿 #6ec89a / mem 橙 #e0a84c / swap 紫 #b48ead，
图例显示当前值；mem_info() 已输出 swap_total/swap_used/swap_percent）。

**部署**：`sudo systemctl restart svc-dashboard`，验证 `curl http://127.0.0.1/`。
**改前端纪律（AGENTS.md §四）**：改 DOM/JS 前先 grep 全部引用；判空取元素；
改完必须无头浏览器 390x844 + 1280 双视口复验 + console 零报错（85102dc 事故教训）。

## 二、任务 1：topbar 重设计（用户拍板原话）

- 左边：**服务器名字**（HOSTNAME）
- 右边（右对齐）：**一个刷新按钮**
  - 点击 = 立即刷新
  - **长按 = 锁定/解锁自动刷新**：锁定时不自动刷新（当前有 30s 自动刷新开关）
  - 锁定状态要在按钮上可视（图标变化/描边/角标），点按仍可手动刷新
- 移除 topbar 里其他杂项（保留 GitHub 链接可选移到页脚或概要页）
- 现有「自动刷新」开关与新按钮合并（长按即切换，开关 UI 可移除）
- 触感反馈用现有 haptic()

## 三、任务 2：全局去 Emoji，改 SVG 图标（用户拍板）

**UI 里不允许出现 Emoji**。需要图标的地方一律用**内联 SVG**（不用图标库 CDN，
零依赖）：

1. 先盘点：`grep -nP '[\x{1F300}-\x{1FAFF}\x{2600}-\x{27BF}\x{2B00}-\x{2BFF}\x{FE0F}]' dashboard.py`
   （当前 65 处，含 ✅❌⚠️ 等状态符号和各 section 标题的 emoji）
2. 设计一套统一风格的 SVG 图标（16-20px 线性风格，stroke=currentColor，
   1.5px stroke-width，round linecap——与现有深色极简风一致）：
   - 状态：成功/错误/警告/运行中/暂停（可用于 goal 卡/健康检查/端口心跳）
   - 工具页 section：文件浏览/健康检查/垃圾清理/速测/计划任务/工具直达
   - 系统：CPU/内存/磁盘/负载/swap
   - 操作：刷新/锁定/复制/关闭/展开
   - 实现：JS 里一个 `icon(name, size)` 函数返回 SVG 字符串，或 `<svg><use>` sprite
     （模板字符串里嵌入；注意 str.replace 注入不破坏——用占位符方式）
3. 替换全部 emoji（JS 生成 + Python 端 sysbar/健康检查等模板里的）；
   状态色沿用现有 --c-green/--c-red/--c-amber CSS 变量
4. ⚠️ 图例/文本对齐:emoji 换 SVG 后行高会变，检查列表行/卡片标题不错位

## 四、任务 3：明暗双主题自动切换（用户拍板）

现在只有深色。要求：**主题跟随系统**（prefers-color-scheme），所有元素适配：

1. CSS 变量化：把散落的颜色收敛进 `:root`（现有 --c-* 基础上补 --bg/--card/
   --border/--text/--text-dim 等），`@media (prefers-color-scheme: light)` 提供
   亮色值（亮色：bg #f5f5f5 / 卡片 #fff / 文字 #1a1a1a / 边框 #e0e0e0，状态色
   调深到 AA 对比度）
2. **全部硬编码颜色清理**：canvas 图表颜色（drawChart 里 6 个色值→读 CSS 变量
   `getComputedStyle(document.documentElement).getPropertyValue`）、
   header 背景 rgba(10,10,10,.9)、table sticky 背景 #0a0a0a、骨架屏 shimmer、
   theme-color meta、状态灯等——**不许有漏网的深色硬编码**
3. 手动覆盖：设置里加「跟随系统/深色/浅色」三选（localStorage 记住，
   html[data-theme] 属性 + `color-scheme` 属性同步，meta theme-color JS 动态改）
4. 亮色下视觉验收：截图确认所有页面（六页签+ツール子面板）无对比度崩坏

## 五、验收（全部必须）

1. 390x844 手机 + 1280x800 桌面双视口逐页截图，console 零报错
2. `grep -c` emoji 模式 = 0
3. 系统切亮色→页面全部元素跟随（截图对比深/浅两套）
4. topbar：点刷新生效；长按锁定后 30s 自动刷新停（Network 面板验证无 /api 请求），
   再长按恢复；锁定态可视
5. 曲线四线（CPU/load/mem/swap）+ 图例正常
6. py_compile 通过 + 服务重启后回归（每页高度仍独立、缩放仍禁止）
7. git commit（中文）+ push

## 六、边界

- 不改后端 API 语义；不加新功能页
- SVG 手写不引外部库；亮色主题下 statusline/告警/图表对比度 ≥4.5:1
- 别动 #track 高度逻辑和手势代码（今天刚修好）
