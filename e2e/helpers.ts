import { Page } from "@playwright/test";

export const BASE = "http://127.0.0.1:5000";
export const TEST_USER = "e2e_tester_" + Date.now();

export function collectErrors(page: Page) {
  const errors: string[] = [];
  page.on("console", (msg) => {
    if (msg.type() === "error") {
      const text = msg.text();
      if (!text.includes("favicon") && !text.includes("net::ERR"))
        errors.push(text.substring(0, 300));
    }
  });
  page.on("pageerror", (err) =>
    errors.push(`UNCAUGHT: ${err.message.substring(0, 300)}`)
  );
  return errors;
}

export async function login(page: Page, username?: string) {
  const user = username || TEST_USER;
  await page.goto(BASE);
  // Clear any existing user to force login screen
  await page.evaluate((u) => {
    localStorage.setItem("ctf-username", "");
    localStorage.removeItem("ctf-username");
  }, user);
  await page.reload();
  // Should see login overlay
  const loginInput = page.locator("#login-username");
  await loginInput.waitFor({ state: "visible", timeout: 5000 });
  await loginInput.fill(user);
  await page.locator("#login-btn").click();
  // Wait for nav to appear
  await page.locator("#main-nav").waitFor({ state: "visible", timeout: 5000 });
}

export async function loginIfNeeded(page: Page, username?: string) {
  const user = username || TEST_USER;
  await page.goto(BASE);
  // Check if already logged in
  const nav = page.locator("#main-nav");
  const isVisible = await nav.isVisible().catch(() => false);
  if (!isVisible) {
    await login(page, user);
  }
}

export async function goToTab(page: Page, tabName: string) {
  await page.locator(`#nav-${tabName}`).click();
  await page.waitForTimeout(800);
}
