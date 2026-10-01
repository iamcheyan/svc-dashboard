import puppeteer from "/home/tetsuya/.bun/install/global/node_modules/puppeteer-core";
import fs from "node:fs";
import path from "node:path";

const CHROME_PATH = "/home/tetsuya/.omp/puppeteer/chrome/linux-150.0.7871.24/chrome-linux64/chrome";
const ARTIFACTS_DIR = path.resolve(".artifacts/pull-to-refresh-2026-10-02");

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function runReproduction() {
  console.log("=== Running Comprehensive PTR Diagnostics & Reproduction ===");
  const results = [];

  const browser = await puppeteer.launch({
    executablePath: CHROME_PATH,
    headless: "new",
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu"
    ]
  });

  try {
    const page = await browser.newPage();
    const consoleLogs = [];
    const pageErrors = [];
    const requests = [];

    page.on("console", msg => consoleLogs.push(msg.text()));
    page.on("pageerror", err => pageErrors.push(err.toString()));
    page.on("request", req => {
      const url = req.url();
      if (url.includes("/api") || url.includes("/static/")) {
        requests.push({ url, time: Date.now() });
      }
    });

    // --- TEST 1: Desktop Viewport (1440x900) ---
    console.log("\n[Test 1] Desktop Viewport (1440x900) verification");
    await page.setViewport({ width: 1440, height: 900, isMobile: false, hasTouch: false });
    await page.goto("http://127.0.0.1:80/", { waitUntil: "networkidle2" });
    await sleep(500);

    const desktopIndicatorVisible = await page.evaluate(() => {
      const el = document.getElementById("ptr-indicator");
      if (!el) return false;
      const style = window.getComputedStyle(el);
      return style.display !== "none" && style.opacity !== "0" && el.classList.contains("on");
    });
    console.log("  Desktop PTR indicator visible initially:", desktopIndicatorVisible);
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, "desktop_1440x900.png") });

    // --- SWITCH TO MOBILE (390x844) ---
    console.log("\n[Test 2] Mobile Viewport (390x844) Touch Setup");
    await page.setViewport({ width: 390, height: 844, deviceScaleFactor: 3, isMobile: true, hasTouch: true });
    await page.reload({ waitUntil: "networkidle2" });
    await sleep(600);

    // Helper for touch gesture via CDP Input.dispatchTouchEvent
    const client = await page.createCDPSession();

    async function cdpTouchDrag(startX, startY, endX, endY, steps = 10, stepDelay = 20) {
      await client.send("Input.dispatchTouchEvent", {
        type: "touchStart",
        touchPoints: [{ x: startX, y: startY, id: 0 }]
      });
      await sleep(stepDelay);

      for (let i = 1; i <= steps; i++) {
        const curX = startX + (endX - startX) * (i / steps);
        const curY = startY + (endY - startY) * (i / steps);
        await client.send("Input.dispatchTouchEvent", {
          type: "touchMove",
          touchPoints: [{ x: Math.round(curX), y: Math.round(curY), id: 0 }]
        });
        await sleep(stepDelay);
      }
    }

    async function cdpTouchEnd(x, y) {
      await client.send("Input.dispatchTouchEvent", {
        type: "touchEnd",
        touchPoints: []
      });
      await sleep(50);
    }

    async function cdpTouchCancel() {
      await client.send("Input.dispatchTouchEvent", {
        type: "touchCancel",
        touchPoints: []
      });
      await sleep(50);
    }

    // --- TEST 2A: Short pull cancel (< threshold) ---
    console.log("\n[Test 2A] Short pull cancel (< threshold)");
    const reqCountBefore2A = requests.filter(r => r.url.includes("/api")).length;
    await cdpTouchDrag(195, 120, 195, 150, 6, 20); // 30px down
    const indicatorDuringShort = await page.evaluate(() => {
      const el = document.getElementById("ptr-indicator");
      const main = document.querySelector("main");
      return {
        on: el ? el.classList.contains("on") : false,
        ready: el ? el.classList.contains("ready") : false,
        indicatorTransform: el ? el.style.transform : "",
        mainTransform: main ? main.style.transform : ""
      };
    });
    console.log("  During short pull:", indicatorDuringShort);
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, "mobile_short_pull.png") });

    await cdpTouchEnd(195, 150);
    await sleep(400);

    const indicatorAfterShort = await page.evaluate(() => {
      const el = document.getElementById("ptr-indicator");
      const main = document.querySelector("main");
      return {
        on: el ? el.classList.contains("on") : false,
        ready: el ? el.classList.contains("ready") : false,
        loading: el ? el.classList.contains("loading") : false,
        mainTransform: main ? main.style.transform : ""
      };
    });
    const reqCountAfter2A = requests.filter(r => r.url.includes("/api")).length;
    console.log("  After short pull released:", indicatorAfterShort);
    console.log("  Requests triggered by short pull (should be 0):", reqCountAfter2A - reqCountBefore2A);
    results.push({
      test: "Short Pull Cancel",
      success: !indicatorAfterShort.loading && (reqCountAfter2A - reqCountBefore2A === 0)
    });

    // --- TEST 2B: Full pull to refresh (>= threshold) ---
    console.log("\n[Test 2B] Full pull to refresh (>= threshold)");
    const reqCountBefore2B = requests.filter(r => r.url.includes("/api")).length;
    await cdpTouchDrag(195, 120, 195, 230, 10, 20); // 110px down

    const stateDuringFull = await page.evaluate(() => {
      const el = document.getElementById("ptr-indicator");
      const main = document.querySelector("main");
      return {
        on: el ? el.classList.contains("on") : false,
        ready: el ? el.classList.contains("ready") : false,
        indicatorTransform: el ? el.style.transform : "",
        mainTransform: main ? main.style.transform : ""
      };
    });
    console.log("  During full pull:", stateDuringFull);
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, "mobile_full_pull_ready.png") });

    await cdpTouchEnd(195, 230);
    await sleep(100);

    const stateDuringLoading = await page.evaluate(() => {
      const el = document.getElementById("ptr-indicator");
      const main = document.querySelector("main");
      return {
        loading: el ? el.classList.contains("loading") : false,
        indicatorTransform: el ? el.style.transform : "",
        mainTransform: main ? main.style.transform : ""
      };
    });
    console.log("  Immediately after release (loading state):", stateDuringLoading);
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, "mobile_loading.png") });

    // Wait for refresh to settle
    await sleep(1500);

    const stateAfterLoading = await page.evaluate(() => {
      const el = document.getElementById("ptr-indicator");
      const main = document.querySelector("main");
      return {
        loading: el ? el.classList.contains("loading") : false,
        on: el ? el.classList.contains("on") : false,
        mainTransform: main ? main.style.transform : "",
        mainTransition: main ? main.style.transition : ""
      };
    });
    const reqCountAfter2B = requests.filter(r => r.url.includes("/api")).length;
    console.log("  After loading settles:", stateAfterLoading);
    console.log("  API requests triggered:", reqCountAfter2B - reqCountBefore2B);
    results.push({
      test: "Full Pull Refresh",
      success: (reqCountAfter2B - reqCountBefore2B > 0) && !stateAfterLoading.loading
    });

    // --- TEST 2C: TouchCancel handling ---
    console.log("\n[Test 2C] TouchCancel handling");
    await cdpTouchDrag(195, 120, 195, 200, 8, 20);
    await cdpTouchCancel();
    await sleep(400);

    const stateAfterCancel = await page.evaluate(() => {
      const el = document.getElementById("ptr-indicator");
      const main = document.querySelector("main");
      return {
        on: el ? el.classList.contains("on") : false,
        loading: el ? el.classList.contains("loading") : false,
        mainTransform: main ? main.style.transform : ""
      };
    });
    console.log("  After touch cancel:", stateAfterCancel);
    results.push({
      test: "TouchCancel Recovery",
      success: !stateAfterCancel.loading
    });

    // --- TEST 2D: Horizontal swipe non-interference ---
    console.log("\n[Test 2D] Horizontal swipe non-interference");
    const reqCountBefore2D = requests.filter(r => r.url.includes("/api")).length;
    // Swipe horizontally from right to left (page switch)
    await cdpTouchDrag(320, 300, 50, 300, 10, 20);
    await cdpTouchEnd(50, 300);
    await sleep(500);

    const activePageAfterSwipe = await page.evaluate(() => {
      return typeof page !== "undefined" ? page : -1;
    });
    const reqCountAfter2D = requests.filter(r => r.url.includes("/api")).length;
    console.log("  Page index after horizontal swipe:", activePageAfterSwipe);
    console.log("  Accidental PTR requests during horizontal swipe:", reqCountAfter2D - reqCountBefore2D);
    results.push({
      test: "Horizontal Swipe",
      success: activePageAfterSwipe === 1
    });

    // --- TEST 2E: Scrolled down page should NOT trigger PTR ---
    console.log("\n[Test 2E] Scrolled down page should NOT trigger PTR");
    // Switch back to page 0
    await page.evaluate(() => { if (typeof setPage === "function") setPage(0); });
    await sleep(300);

    // Scroll main down by 200px
    await page.evaluate(() => {
      const main = document.querySelector("main");
      if (main) main.scrollTop = 200;
    });
    await sleep(100);

    const reqCountBefore2E = requests.filter(r => r.url.includes("/api")).length;
    // Attempt pull down while scrolled
    await cdpTouchDrag(195, 200, 195, 300, 8, 20);
    await cdpTouchEnd(195, 300);
    await sleep(400);

    const reqCountAfter2E = requests.filter(r => r.url.includes("/api")).length;
    console.log("  PTR requests when scrolled down:", reqCountAfter2E - reqCountBefore2E);
    results.push({
      test: "Scrolled Down No PTR",
      success: (reqCountAfter2E - reqCountBefore2E === 0)
    });

    console.log("\n=== Test Results Summary ===");
    console.log(JSON.stringify(results, null, 2));
    console.log("Page errors recorded:", pageErrors);

  } finally {
    await browser.close();
  }
}

runReproduction().catch(err => {
  console.error("Diagnostic error:", err);
  process.exit(1);
});
