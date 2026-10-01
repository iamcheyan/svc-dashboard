# svc-dashboard 移动端下拉刷新重构审计与验证报告

- **日期**：2026-10-02
- **测试环境**：Debian Linux / Chrome 150.0.7871.24 (Headless CDP) / Bun 1.x / svc-dashboard 1.0 (Python 3.13)
- **基线分支**：`main` (HEAD: `4d68edd`)
- **工作区边界保护**：保留工作树中既有未提交改动（13 个 tracked 文件 + `svcdash/tailscale.py` 未跟踪），只提交下拉刷新相关改动与专属证据。

---

## 一、当前刷新架构审计与根因分析

在本次重构前，对 `dashboard.py`、`svcdash/handler.py`、`static/index.html`、`static/app.css`、`static/app.js` 进行了全链路只读审计，确认了如下核心缺陷与失效机理：

1. **页面位移导致层叠上下文与包含块破坏（最严重视觉隐患）**：
   - 旧实现对 `<main>` 应用了 `main.style.transform = translateY(...)`。
   - 移动端 `<header>` 被重载至 `<main>` 顶部内部，当 `<main>` 获得非 `none` 的 `transform` 时，根据 CSS 规范会强制创建新的包含块（Containing block），导致所有 `position: fixed` 的悬浮控件（如顶栏、模态框）失位或跳动；
   - 回弹动画通过 `setTimeout(..., 350)` 清除 `transform`，若在回弹期间发生手势中断或异常，页面将永久卡在下沉偏移位。
2. **`touchcancel` 缺失导致状态死锁**：
   - 旧实现仅注册 `touchstart`, `touchmove`, `touchend`，未注册 `touchcancel`；
   - 当遭遇系统来电、多指手势或控制中心唤出时，浏览器派发 `touchcancel`，旧实现 `tracking` 未清除，页面卡在 `translateY(58.16px)` 且指示器一直亮起（已通过自动化测试实锤复现）。
3. **缺少全局刷新互斥锁（Refresh Mutex）**：
   - 旧实现没有统一的互斥机制，PTR 触发与顶栏按钮点击、后台 30s `autoTick` 存在竞态条件，会发起并发重复的 `/api` 抓取（单次冷扫描耗时 ~9.7s），导致服务器负载激增与状态闪烁。
4. **方向判定过于生硬，容易误杀正常下拉手势**：
   - 旧代码在手指微小位移时直接比较 `Math.abs(dx) > Math.abs(distance)`，并在不满足时直接将 `tracking` 设为 `false` 并 `resetPull`；
   - 用户手指刚触碰屏幕的微小抖动极易过早判定为失效，导致用户感知“下拉经常拉不动、拉一半失效”。
5. **子滚动容器与多级滚动判定失效**：
   - 仅检查 `(main.scrollTop > 0) || window.scrollY > 0`；
   - 当用户在弹窗、代码框或具有内部局部滚动的面板内向上滚动时，旧实现粗暴接管手势并 `preventDefault`，破坏了内部容器的原生滚动。
6. **桌面端与触屏设备混淆**：
   - 仅依赖 `("ontouchstart" in window) || navigator.maxTouchPoints > 0`；
   - 在带触控板或外接触屏显示器的桌面视口（1440×900）下错误安装了 touch 监听器。

---

## 二、重构设计与状态机实现要点

1. **统一全站刷新调度器（Shared Refresh Coordinator）**：
   - 在 `static/app.js` 中建立具备 Promise 互斥保护的 `load(alsoSys)` 与 `triggerSharedRefresh(opts)`；
   - 当任意刷新在处理中时，后续请求复用当前 inflight Promise，绝不发起重复并发 fetch；
   - `triggerSharedRefresh` 统一联动当前页数据刷新（活动页 `renderActivityPage`、Tmux 页 `renderTmuxPage`、Agent 页 `initAgentsPage`、Tailscale 面板 `renderNetworkPage`）；
   - 顶栏刷新按钮与下拉手势完全接入同一刷新入口，按钮 spinning 态与 PTR 旋转态视觉互通。
2. **模块化控制器 `PullToRefreshController`**：
   - 单一初始化、具备严谨状态机：`STATE_IDLE (0)` -> `STATE_PENDING (1)` -> `STATE_PULLING (2)` -> `STATE_REFRESHING (3)`；
   - 只有同时满足支持触控且视口为移动端（`touchCapable && isMobile()`，<= 768px）才激活；桌面端完全放行；
   - **判定死区（7px）**：位移小于 7px 时处于 pending 状态，不拦截事件，放行轻微轻触；
   - **垂直主方向锁定**：超过死区后，要求 `dy > 0 && dy > Math.abs(dx) * 1.25` 才确认为 PTR，此时才调用 `e.preventDefault()` 阻止过度滚动；横向滑动平滑放行给切卡 swipe；
   - **单指强制校验**：`e.touches.length === 1`，多指接入立即取消，防止跳变抖动；
   - **安全区域与子容器检测**：检查 `main.scrollTop`、`window.scrollY` 以及目标祖先滚动链，存在非顶端滚动或文本输入控件时放行原生手势；
   - **全面取消保障**：完善的 `touchcancel`、切页（`setPage`）及 `visibilitychange` 复位机制，确保 `finally` 阶段可靠释放，绝不卡死。
3. **指示器独立悬浮架构与物理阻尼**：
   - 彻底废除对 `<main>` 的 `translateY` 操纵，页面布局零位移零撕裂；
   - 指示器采用 GPU 硬件加速定位 `translate3d(-50%, ${pullY}px, 0)`，居中更稳固；
   - 物理对数阻尼公式：`pullY = Math.min(78, Math.pow(rawDistance, 0.82) * 1.55)`；
   - 阈值 `THRESHOLD = 56px`，拉满触发 `haptic(10)` 就绪震动，松手悬停在 `HOLD_Y = 46px` 处平滑旋转；
   - 刷新完成触发 `haptic(12)`，平滑过渡退场；
   - 适配 `env(safe-area-inset-top)`、`prefers-reduced-motion` 与明暗主题毛玻璃效果。

---

## 三、真实自动化验证结果

通过基于 Puppeteer / CDP 的双视口自动化测试套件（`.artifacts/pull-to-refresh-2026-10-02/verify_all.js`），在真实服务（`http://127.0.0.1:80`）下执行全面复验：

```text
=====================================================
  Verification Summary
=====================================================
┌───┬─────────────────────────┬────────────────────────────────────────────────────────────────────────┬────────┐
│   │ phase                   │ aspect                                                                 │ passed │
├───┼─────────────────────────┼────────────────────────────────────────────────────────────────────────┼────────┤
│ 0 │ Desktop Viewport        │ Indicator hidden, topbar refresh button functional with spinning state │ true   │
│ 1 │ Mobile Gestures         │ Partial Pull & Smooth Cancel (< threshold without request)             │ true   │
│ 2 │ Mobile Gestures         │ Full Pull -> Ready -> Loading -> Settle Recovery                       │ true   │
│ 3 │ Mobile Gestures         │ TouchCancel Recovery (no stuck state, no layout shift)                 │ true   │
│ 4 │ Mobile Gestures         │ Scrolled down page放行 (no PTR trigger when scrollTop > 0)             │ true   │
│ 5 │ Mobile Gestures         │ Horizontal swipe smoothly switches page without triggering PTR         │ true   │
│ 6 │ Multi-page Coordination │ PTR operates seamlessly on Activity page (page 1)                      │ true   │
│ 7 │ Mutex & Concurrency     │ Simultaneous refresh calls safely deduplicated via mutex               │ true   │
└───┴─────────────────────────┴────────────────────────────────────────────────────────────────────────┴────────┘
Total page errors recorded: 0
ALL TESTS PASSED: true
```

### 生成的真实截图证据
截图保存在本仓 `.artifacts/pull-to-refresh-2026-10-02/` 目录下：
- `v1_desktop_idle.png`：桌面视口（1440×900）无悬挂指示器，顶栏刷新正常；
- `v2_mobile_01_idle.png`：移动视口（390×844）初始待机态；
- `v2_mobile_02_partial.png`：下拉 35px 展开中（未达阈值）；
- `v2_mobile_03_cancelled.png`：短拉释放后平滑复位，未发起请求；
- `v2_mobile_04_ready.png`：下拉 110px 就绪高亮态（达到阈值）；
- `v2_mobile_05_loading.png`：释放进入悬停加载旋转态；
- `v2_mobile_06_settled.png`：刷新完成，平滑退场，页面无残留位移；
- `v2_mobile_07_swipe_page1.png`：横向滑动手势正常切至活动页，未误触发 PTR。

### 命令行自检与服务状态
- `python3 dashboard.py --selftest`：11 项单元测试全过（`Ran 11 tests ... OK`，live dry-run 正常）；
- `systemctl status svc-dashboard`：`active (running)`，静态资源 ETag 与哈希自动更新为最新版（`app.css?v=b14f8936`, `app.js?v=09f49f29`）；
- 页面控制台与 CDP pageerror：0 错误。

---

## 四、保留的非本任务文件清单（资产保护严格核对）

本次提交完全遵循隔离纪律，以下文件中的既有修改完全保护在工作树中，未做任何覆盖、revert 或提入当前 commit：
- `AGENTS.md`
- `static/index.html`
- `svcdash/agents.py`
- `svcdash/goals.py`
- `svcdash/handler.py`
- `svcdash/i18n.py`
- `svcdash/icons.py`
- `svcdash/render.py`
- `svcdash/runtimes.py`
- `svcdash/selftest.py`
- `svcdash/tasks.py`
- `svcdash/tailscale.py` (untracked)
- `static/app.css`（仅提取了 `#ptr-indicator` 样式，其后 tailscale 与 manage 样式未提交）
- `static/app.js`（仅提取了 `load` mutex 与 `ptrController` 模块，其他功能未提交）
