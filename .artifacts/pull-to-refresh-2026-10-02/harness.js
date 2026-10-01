import puppeteer from "/home/tetsuya/.bun/install/global/node_modules/puppeteer-core";
import fs from "node:fs";
import path from "node:path";

const CHROME_PATH = "/home/tetsuya/.omp/puppeteer/chrome/linux-150.0.7871.24/chrome-linux64/chrome";
const ARTIFACTS_DIR = path.resolve(".artifacts/pull-to-refresh-2026-10-02");

async function runAudit() {
  console.log("=== Starting Pull-to-Refresh Audit & Reproduction ===");
  const browser = await puppeteer.launch({
    executablePath: CHROME_PATH,
    headless: "new",
    args: [
      "--no-sandbox",
      "--disable-dev-shm-usage",
      "--disable-gpu",
      "--window-size=390,844"
    ]
  });

  try {
    const page = await browser.newPage();
    const consoleLogs = [];
    const errors = [];

    page.on("console", msg => {
      consoleLogs.push({ type: msg.type(), text: msg.text() });
    });
    page.on("pageerror", err => {
      errors.push(err.toString());
      console.error("PAGE ERROR:", err.toString());
    });

    // 1. Mobile Viewport (390 x 844) with Touch Emulation
    await page.setViewport({
      width: 390,
      height: 844,
      deviceScaleFactor: 3,
      isMobile: true,
      hasTouch: true,
    });

    console.log("Loading http://127.0.0.1:80/ in mobile mode...");
    await page.goto("http://127.0.0.1:80/", { waitUntil: "networkidle2" });

    // Check indicator element
    const indicatorExists = await page.evaluate(() => {
      const el = document.getElementById("ptr-indicator");
      return !!el;
    });
    console.log("PTR indicator DOM exists:", indicatorExists);

    // Take screenshot of mobile initial state
    await page.screenshot({ path: path.join(ARTIFACTS_DIR, "01_mobile_idle.png") });

    // Inspect main scrolling element and state
    const scrollInfo = await page.evaluate(() => {
      const main = document.querySelector("main");
      return {
        mainScrollTop: main ? main.scrollTop : -1,
        mainScrollHeight: main ? main.scrollHeight : -1,
        mainClientHeight: main ? main.clientHeight : -1,
        windowScrollY: window.scrollY,
        bodyOverflow: window.getComputedStyle(document.body).overflow,
        mainOverflowY: main ? window.getComputedStyle(main).overflowY : null
      };
    });
    console.log("Initial scroll layout info:", scrollInfo);

    console.log("=== Initial audit check completed ===");
    console.log("Console errors collected:", errors.length);

  } finally {
    await browser.close();
  }
}

runAudit().catch(err => {
  console.error("Harness error:", err);
  process.exit(1);
});
