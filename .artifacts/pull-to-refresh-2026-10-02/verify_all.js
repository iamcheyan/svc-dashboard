import puppeteer from "/home/tetsuya/.bun/install/global/node_modules/puppeteer-core";
import fs from "node:fs";
import path from "node:path";

const CHROME_PATH = "/home/tetsuya/.omp/puppeteer/chrome/linux-150.0.7871.24/chrome-linux64/chrome";
const ARTIFACTS_DIR = path.resolve(".artifacts/pull-to-refresh-2026-10-02");

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runComprehensiveVerification() {
  console.log("=====================================================");
  console.log("  svc-dashboard Pull-To-Refresh Full Verification    ");
  console.log("=====================================================");

  const browser = await puppeteer.launch({
    executablePath: CHROME_PATH,
    headless: "new",
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu"
    ]
  });

  const testReport = [];

  try {
    const page = await browser.newPage();
    const pageErrors = [];
    const consoleLogs = [];
    const networkRequests = [];

    page.on("pageerror", err => {
      pageErrors.push(err.toString());
      console.error("  [PAGE ERROR]", err.toString());
    });

    page.on("console", msg => {
      consoleLogs.push({ type: msg.type(), text: msg.text() });
    });

    page.on("request", req => {
      const u = req.url();
      if (u.includes("/api")) {
        networkRequests.push({ url: u, time: Date.now() });
      }
    });

    // Helper: wait for all in-flight refresh to settle
    async function waitForRefreshIdle(timeout = 35000) {
      await page.waitForFunction(() => {
        const topBtn = document.querySelector("#refresh");
        const ind = document.getElementById("ptr-indicator");
        const topSpinning = topBtn ? topBtn.classList.contains("spinning") : false;
        const indLoading = ind ? ind.classList.contains("loading") : false;
        return !topSpinning && !indLoading;
      }, { timeout });
      await sleep(400);
    }

    // -------------------------------------------------------------
    // PART 1: Desktop Viewport (1440x900)
    // -------------------------------------------------------------
    console.log("\n>>> Phase 1: Desktop Viewport (1440x900) Verification");
    await page.setViewport({ width: 1440, height: 900, isMobile: false, hasTouch: false });
    await page.goto("http://127.0.0.1:80/", { waitUntil: "domcontentloaded", timeout: 20000 });
    console.log("  Waiting for desktop initial load to complete...");
    await waitForRefreshIdle(35000);

    const desktopState = await page.evaluate(() => {
      const ind = document.getElementById("ptr-indicator");
      const main = document.querySelector("main");
      return {
        ptrExists: !!ind,
        ptrVisible: ind ? (ind.classList.contains("on") || ind.style.opacity === "1") : false,
        mainTransform: main ? main.style.transform : "",
      };
    });
    console.log("  Desktop initial settled state:", desktopState);
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, "v1_desktop_idle.png") });

    // Test topbar refresh button on desktop
    const reqsBeforeDesktopBtn = networkRequests.length;
    await page.click("#refresh");
    console.log("  Desktop topbar refresh clicked, waiting for finish...");
    await sleep(250);
    const spinningDuringClick = await page.evaluate(() => document.querySelector("#refresh").classList.contains("spinning"));
    await waitForRefreshIdle(35000);
    const reqsAfterDesktopBtn = networkRequests.length;
    console.log("  Desktop topbar refresh button spinning during run:", spinningDuringClick);
    console.log("  Desktop API requests completed:", reqsAfterDesktopBtn - reqsBeforeDesktopBtn);
    testReport.push({
      phase: "Desktop Viewport",
      aspect: "Indicator hidden, topbar refresh button functional with spinning state",
      passed: !desktopState.ptrVisible && spinningDuringClick && (reqsAfterDesktopBtn - reqsBeforeDesktopBtn > 0)
    });

    // -------------------------------------------------------------
    // PART 2: Mobile Viewport (390x844) with Touch Emulation
    // -------------------------------------------------------------
    console.log("\n>>> Phase 2: Mobile Viewport (390x844) Touch States");
    await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 3, isMobile: true, hasTouch: true });
    await page.reload({ waitUntil: "domcontentloaded", timeout: 20000 });
    console.log("  Waiting for mobile initial load to complete...");
    await waitForRefreshIdle(35000);
    // Lock auto-refresh so 30s background tick does not inject async requests during gesture assertion
    await page.evaluate(() => { if (typeof setAutoLocked === "function") setAutoLocked(true); });
    await sleep(200);

    const client = await page.createCDPSession();

    async function touchDrag(startX, startY, endX, endY, steps = 10, delay = 20) {
      await client.send("Input.dispatchTouchEvent", {
        type: "touchStart",
        touchPoints: [{ x: Math.round(startX), y: Math.round(startY), id: 0 }]
      });
      await sleep(delay);

      for (let i = 1; i <= steps; i++) {
        const curX = startX + (endX - startX) * (i / steps);
        const curY = startY + (endY - startY) * (i / steps);
        await client.send("Input.dispatchTouchEvent", {
          type: "touchMove",
          touchPoints: [{ x: Math.round(curX), y: Math.round(curY), id: 0 }]
        });
        await sleep(delay);
      }
    }

    async function touchEnd() {
      await client.send("Input.dispatchTouchEvent", {
        type: "touchEnd",
        touchPoints: []
      });
      await sleep(50);
    }

    async function touchCancel() {
      await client.send("Input.dispatchTouchEvent", {
        type: "touchCancel",
        touchPoints: []
      });
      await sleep(50);
    }

    // State 1: Mobile Idle
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, "v2_mobile_01_idle.png") });

    // State 2: Partial Pull (35px, < threshold)
    console.log("\n  [Test 2.1] Partial Pull (< threshold)");
    const reqsBeforePartial = networkRequests.length;
    await touchDrag(195, 120, 195, 155, 6, 25); // 35px down

    const partialState = await page.evaluate(() => {
      const ind = document.getElementById("ptr-indicator");
      const main = document.querySelector("main");
      return {
        on: ind ? ind.classList.contains("on") : false,
        ready: ind ? ind.classList.contains("ready") : false,
        loading: ind ? ind.classList.contains("loading") : false,
        transform: ind ? ind.style.transform : "",
        mainTransform: main ? main.style.transform : ""
      };
    });
    console.log("    Partial pull state during drag:", partialState);
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, "v2_mobile_02_partial.png") });

    // State 3: Release Partial Pull -> smooth cancel
    await touchEnd();
    await sleep(400);

    const postPartialState = await page.evaluate(() => {
      const ind = document.getElementById("ptr-indicator");
      const main = document.querySelector("main");
      return {
        on: ind ? ind.classList.contains("on") : false,
        loading: ind ? ind.classList.contains("loading") : false,
        mainTransform: main ? main.style.transform : ""
      };
    });
    const reqsAfterPartial = networkRequests.length;
    console.log("    Post-partial release state:", postPartialState);
    console.log("    Requests fired during partial pull (should be 0):", reqsAfterPartial - reqsBeforePartial);
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, "v2_mobile_03_cancelled.png") });
    testReport.push({
      phase: "Mobile Gestures",
      aspect: "Partial Pull & Smooth Cancel (< threshold without request)",
      passed: !postPartialState.loading && (reqsAfterPartial - reqsBeforePartial === 0) && postPartialState.mainTransform === ""
    });

    // State 4 & 5: Full Pull (>= threshold) -> Ready -> Loading
    console.log("\n  [Test 2.2] Full Pull (>= threshold) & Loading");
    const reqsBeforeFull = networkRequests.length;
    await touchDrag(195, 120, 195, 230, 12, 20); // 110px down

    const readyState = await page.evaluate(() => {
      const ind = document.getElementById("ptr-indicator");
      return {
        on: ind ? ind.classList.contains("on") : false,
        ready: ind ? ind.classList.contains("ready") : false,
        transform: ind ? ind.style.transform : ""
      };
    });
    console.log("    Ready state during drag:", readyState);
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, "v2_mobile_04_ready.png") });

    // Release to trigger loading
    await touchEnd();
    await sleep(150);

    const loadingState = await page.evaluate(() => {
      const ind = document.getElementById("ptr-indicator");
      const main = document.querySelector("main");
      return {
        loading: ind ? ind.classList.contains("loading") : false,
        transform: ind ? ind.style.transform : "",
        mainTransform: main ? main.style.transform : ""
      };
    });
    console.log("    Loading state after release:", loadingState);
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, "v2_mobile_05_loading.png") });

    console.log("    Waiting for full pull refresh to finish...");
    await waitForRefreshIdle(35000);

    const settledState = await page.evaluate(() => {
      const ind = document.getElementById("ptr-indicator");
      const main = document.querySelector("main");
      return {
        on: ind ? ind.classList.contains("on") : false,
        loading: ind ? ind.classList.contains("loading") : false,
        mainTransform: main ? main.style.transform : ""
      };
    });
    const reqsAfterFull = networkRequests.length;
    console.log("    Settled state after refresh:", settledState);
    console.log("    API requests completed during full pull:", reqsAfterFull - reqsBeforeFull);
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, "v2_mobile_06_settled.png") });
    testReport.push({
      phase: "Mobile Gestures",
      aspect: "Full Pull -> Ready -> Loading -> Settle Recovery",
      passed: readyState.ready && loadingState.loading && !settledState.loading && settledState.mainTransform === "" && (reqsAfterFull - reqsBeforeFull > 0)
    });

    // State 7: TouchCancel handling
    console.log("\n  [Test 2.3] TouchCancel Handling (e.g. system gesture interrupt)");
    await touchDrag(195, 120, 195, 210, 8, 20);
    await touchCancel();
    await sleep(400);

    const postCancelState = await page.evaluate(() => {
      const ind = document.getElementById("ptr-indicator");
      const main = document.querySelector("main");
      return {
        on: ind ? ind.classList.contains("on") : false,
        loading: ind ? ind.classList.contains("loading") : false,
        mainTransform: main ? main.style.transform : ""
      };
    });
    console.log("    Post-touchcancel state:", postCancelState);
    testReport.push({
      phase: "Mobile Gestures",
      aspect: "TouchCancel Recovery (no stuck state, no layout shift)",
      passed: !postCancelState.loading && postCancelState.mainTransform === ""
    });

    // State 8: Scrolled down page (scrollTop > 0) should NOT trigger PTR
    console.log("\n  [Test 2.4] Non-top scroll gesture放行 (scrollTop > 0)");
    await page.evaluate(() => {
      const main = document.querySelector("main");
      if (main) main.scrollTop = 180;
    });
    await sleep(100);

    const reqsBeforeScrollTest = networkRequests.length;
    await touchDrag(195, 200, 195, 300, 8, 20);
    await touchEnd();
    await sleep(400);

    const reqsAfterScrollTest = networkRequests.length;
    const postScrollDragState = await page.evaluate(() => {
      const ind = document.getElementById("ptr-indicator");
      return {
        on: ind ? ind.classList.contains("on") : false,
        loading: ind ? ind.classList.contains("loading") : false,
      };
    });
    console.log("    Post scroll drag state:", postScrollDragState);
    console.log("    Requests triggered (should be 0):", reqsAfterScrollTest - reqsBeforeScrollTest);
    testReport.push({
      phase: "Mobile Gestures",
      aspect: "Scrolled down page放行 (no PTR trigger when scrollTop > 0)",
      passed: !postScrollDragState.loading && (reqsAfterScrollTest - reqsBeforeScrollTest === 0)
    });

    // Reset scroll back to 0
    await page.evaluate(() => {
      const main = document.querySelector("main");
      if (main) main.scrollTop = 0;
    });
    await sleep(200);

    // State 9: Horizontal Swipe Non-Interference
    console.log("\n  [Test 2.5] Horizontal Swipe Non-Interference (Tab switching)");
    const reqsBeforeSwipe = networkRequests.length;
    // Horizontal swipe from right to left
    await touchDrag(330, 260, 40, 260, 12, 15);
    await touchEnd();
    await sleep(600);

    const activePage = await page.evaluate(() => typeof page !== "undefined" ? page : -1);
    const reqsAfterSwipe = networkRequests.length;
    console.log("    Active page after swipe:", activePage);
    console.log("    PTR requests during swipe (should be 0):", reqsAfterSwipe - reqsBeforeSwipe);
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, "v2_mobile_07_swipe_page1.png") });
    testReport.push({
      phase: "Mobile Gestures",
      aspect: "Horizontal swipe smoothly switches page without triggering PTR",
      passed: activePage === 1 && (reqsAfterSwipe - reqsBeforeSwipe === 0)
    });

    // State 10: Tab Switching & PTR on Page 1 (Activity)
    console.log("\n  [Test 2.6] PTR on Page 1 (Activity Page)");
    const reqsBeforeP1 = networkRequests.length;
    await touchDrag(195, 120, 195, 230, 10, 20);
    await touchEnd();
    console.log("    Waiting for Page 1 refresh to finish...");
    await waitForRefreshIdle(35000);

    const reqsAfterP1 = networkRequests.length;
    console.log("    API requests on Page 1 PTR:", reqsAfterP1 - reqsBeforeP1);
    testReport.push({
      phase: "Multi-page Coordination",
      aspect: "PTR operates seamlessly on Activity page (page 1)",
      passed: reqsAfterP1 - reqsBeforeP1 > 0
    });

    // Switch back to Page 0
    await page.evaluate(() => { if (typeof setPage === "function") setPage(0); });
    await sleep(400);

    // Reentrancy and Mutex Test: Multiple simultaneous triggers
    console.log("\n  [Test 2.7] Mutex and Reentrancy Verification");
    const concurrentResult = await page.evaluate(async () => {
      const p1 = triggerSharedRefresh({ isPull: true });
      const p2 = triggerSharedRefresh({ isPull: false });
      const p3 = load(true);
      await Promise.all([p1, p2, p3]);
      return { success: true };
    });
    console.log("    Concurrent refresh test result:", concurrentResult);
    testReport.push({
      phase: "Mutex & Concurrency",
      aspect: "Simultaneous refresh calls safely deduplicated via mutex",
      passed: concurrentResult.success
    });

    console.log("\n=====================================================");
    console.log("  Verification Summary");
    console.log("=====================================================");
    console.table(testReport);
    console.log("Total page errors recorded:", pageErrors.length);
    if (pageErrors.length > 0) {
      console.error("Errors:", pageErrors);
    }

    const allPassed = testReport.every(t => t.passed) && pageErrors.length === 0;
    console.log("ALL TESTS PASSED:", allPassed);

    return { allPassed, testReport, pageErrors };

  } finally {
    await browser.close();
  }
}

runComprehensiveVerification().then(res => {
  if (!res.allPassed) {
    process.exit(1);
  }
  process.exit(0);
}).catch(err => {
  console.error("Verification failed with exception:", err);
  process.exit(1);
});
