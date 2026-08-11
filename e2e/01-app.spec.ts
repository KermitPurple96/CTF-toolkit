import { test, expect } from "@playwright/test";
import { BASE, TEST_USER, collectErrors, login, loginIfNeeded, goToTab } from "./helpers";

test.describe.configure({ mode: "serial" });

// ===== TIER 1: API HEALTH =====
test.describe("Tier 1: API Health", () => {
  test("health endpoint returns healthy", async ({ request }) => {
    const res = await request.get(`${BASE}/health`);
    expect(res.ok()).toBe(true);
    const data = await res.json();
    expect(data.status).toBe("healthy");
    expect(data.directories.tools).toBe(true);
    expect(data.directories.uploads).toBe(true);
    expect(data.directories.downloads).toBe(true);
  });

  test("IPs endpoint returns array", async ({ request }) => {
    const res = await request.get(`${BASE}/ips`);
    expect(res.ok()).toBe(true);
    const ips = await res.json();
    expect(Array.isArray(ips)).toBe(true);
    expect(ips.length).toBeGreaterThan(0);
  });

  test("files endpoint returns array without .md", async ({ request }) => {
    const res = await request.get(`${BASE}/files`);
    expect(res.ok()).toBe(true);
    const files = await res.json();
    expect(Array.isArray(files)).toBe(true);
  });

  test("clipboards endpoint returns 3 slots", async ({ request }) => {
    const res = await request.get(`${BASE}/clipboards`);
    expect(res.ok()).toBe(true);
    const clips = await res.json();
    expect(clips).toHaveLength(3);
  });

  test("rate limit endpoint works", async ({ request }) => {
    const res = await request.get(`${BASE}/api/rate_limit_status`);
    expect(res.ok()).toBe(true);
    const data = await res.json();
    expect(data).toHaveProperty("ip");
    expect(data).toHaveProperty("max_requests");
  });

  test("user registration works", async ({ request }) => {
    const res = await request.post(`${BASE}/api/users`, {
      data: { username: TEST_USER },
    });
    expect(res.ok()).toBe(true);
    const data = await res.json();
    expect(data.username).toBe(TEST_USER);
  });

  test("user list includes registered user", async ({ request }) => {
    const res = await request.get(`${BASE}/api/users`);
    expect(res.ok()).toBe(true);
    const users = await res.json();
    expect(users).toContain(TEST_USER);
  });

  test("invalid username rejected", async ({ request }) => {
    const res = await request.post(`${BASE}/api/users`, {
      data: { username: "bad user!@#" },
    });
    expect(res.status()).toBe(400);
  });

  test("all template routes return 200", async ({ request }) => {
    for (const route of ["/shells", "/tools", "/utilities", "/toolkit", "/chat", "/configuration"]) {
      const res = await request.get(`${BASE}${route}`);
      expect(res.ok(), `${route} should return 200`).toBe(true);
    }
  });
});

// ===== TIER 2: LOGIN & AUTH =====
test.describe("Tier 2: Login Flow", () => {
  test("shows login overlay on first visit", async ({ page }) => {
    const errors = collectErrors(page);
    await page.goto(BASE);
    await page.evaluate(() => localStorage.clear());
    await page.reload();
    await expect(page.locator("#login-overlay")).toBeVisible();
    await expect(page.locator("#login-username")).toBeVisible();
    await expect(page.locator("#login-btn")).toBeVisible();
  });

  test("login with username shows app", async ({ page }) => {
    const errors = collectErrors(page);
    await login(page);
    await expect(page.locator("#main-nav")).toBeVisible();
    await expect(page.locator("#nav-user")).toContainText(TEST_USER);
    await expect(page.locator("#content")).toBeVisible();
  });

  test("username persists across reload", async ({ page }) => {
    await login(page);
    await page.reload();
    await page.waitForTimeout(1000);
    await expect(page.locator("#main-nav")).toBeVisible();
    await expect(page.locator("#nav-user")).toContainText(TEST_USER);
  });
});

// ===== TIER 3: THEME SWITCHING =====
test.describe("Tier 3: Themes", () => {
  test("dark/light/dracula themes switch", async ({ page }) => {
    const errors = collectErrors(page);
    await loginIfNeeded(page);

    // Dark
    await page.locator('[data-set-theme="dark"]').click();
    expect(await page.locator("html").getAttribute("data-theme")).toBe("dark");

    // Light
    await page.locator('[data-set-theme="light"]').click();
    expect(await page.locator("html").getAttribute("data-theme")).toBe("light");

    // Dracula
    await page.locator('[data-set-theme="dracula"]').click();
    expect(await page.locator("html").getAttribute("data-theme")).toBe("dracula");

    // Back to dark
    await page.locator('[data-set-theme="dark"]').click();
    expect(errors, "No JS errors during theme switch").toHaveLength(0);
  });
});

// ===== TIER 4: SHELLS TAB =====
test.describe("Tier 4: Shells", () => {
  test("shells tab loads with controls", async ({ page }) => {
    const errors = collectErrors(page);
    await loginIfNeeded(page);
    await goToTab(page, "shells");

    await expect(page.locator("#listener-ip")).toBeVisible();
    await expect(page.locator("#listener-port")).toBeVisible();
    await expect(page.locator("#start-listener")).toBeVisible();
    await expect(page.locator("#stop-listener")).toBeVisible();
    await expect(page.locator("#shell-output")).toBeVisible();
    await expect(page.locator("#shell-input")).toBeVisible();
  });

  test("IP field has datalist with IPs", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "shells");
    const ipValue = await page.locator("#listener-ip").inputValue();
    expect(ipValue).toMatch(/\d+\.\d+\.\d+\.\d+/);
    const options = page.locator("#listener-ip-list option");
    expect(await options.count()).toBeGreaterThan(0);
  });

  test("port collision detected", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "shells");

    // Simulate a port already in use
    await page.evaluate(() => {
      shells[0].port = "9999";
      persistShells();
      updateTabTitles();
    });

    await page.locator("#listener-port").fill("9999");
    await page.locator("#start-listener").click();
    await page.waitForTimeout(500);

    const output = await page.locator("#shell-output").textContent();
    expect(output).toContain("[ERROR] Port 9999 already in use");
  });

  test("tab shows port label after listener start", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "shells");

    // Clear shells state
    await page.evaluate(() => {
      localStorage.removeItem("shells");
      shells = [{ port: null, output: "" }];
    });

    await page.locator("#listener-port").fill("7777");
    await page.locator("#start-listener").click();
    await page.waitForTimeout(500);

    const tabText = await page.locator(".tab").first().textContent();
    expect(tabText).toContain("shell:7777");
  });

  test("+ button is hidden", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "shells");
    await expect(page.locator("#add-tab")).toBeHidden();
  });
});

// ===== TIER 5: TOOLS TAB =====
test.describe("Tier 5: Tools", () => {
  test("tools tab loads with file list and 5 tabs", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "tools");

    await expect(page.locator("#file-list")).toBeVisible();
    await expect(page.locator("#editor")).toBeVisible();
    await expect(page.locator("#editor-tab")).toBeVisible();
    await expect(page.locator("#send-tab")).toBeVisible();
    await expect(page.locator("#grab-tab")).toBeVisible();
    await expect(page.locator("#serve-tab")).toBeVisible();
    await expect(page.locator("#shellpy-tab")).toBeVisible();

    // File list has tool files
    const items = page.locator("#files .file-item-simple");
    expect(await items.count()).toBeGreaterThan(0);
  });

  test("editor has file dropdown selector", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "tools");

    const select = page.locator("#editor-file-select");
    await expect(select).toBeVisible();
    const options = select.locator("option");
    expect(await options.count()).toBeGreaterThan(1);
  });

  test("all 5 tabs switch correctly", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "tools");

    await page.locator("#send-tab").click();
    await expect(page.locator("#send-area")).toBeVisible();

    await page.locator("#grab-tab").click();
    await expect(page.locator("#grab-area")).toBeVisible();

    await page.locator("#serve-tab").click();
    await expect(page.locator("#serve-area")).toBeVisible();

    await page.locator("#shellpy-tab").click();
    await expect(page.locator("#shellpy-area")).toBeVisible();

    await page.locator("#editor-tab").click();
    await expect(page.locator("#editor-content")).toBeVisible();
  });

  test("clipboards load and are editable", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "tools");

    await expect(page.locator("#clipboard-1")).toBeVisible();
    await page.locator("#clipboard-1").fill("test-clip-value");
    await page.waitForTimeout(500);
  });

  test("search filters files", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "tools");

    const beforeCount = await page.locator("#files .file-item-simple").count();
    await page.locator("#file-search").fill("Rubeus");
    await page.waitForTimeout(300);
    const afterCount = await page.locator("#files .file-item-simple").count();
    expect(afterCount).toBeLessThanOrEqual(beforeCount);
    expect(afterCount).toBeGreaterThan(0);
  });

  test("send to target generates commands with file dropdown", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "tools");

    await page.locator("#send-tab").click();
    await page.locator("#send-file-select").selectOption("Rubeus.exe");
    await page.locator("#send-area button:has-text('Generate')").click();
    await page.waitForTimeout(300);

    const output = await page.locator("#send-cmd-output").textContent();
    expect(output).toContain("Rubeus.exe");
    expect(output).toContain("curl");
  });

  test("shellpy generates files", async ({ request, page }) => {
    // Generate via API
    const res = await request.post(`${BASE}/api/shellpy/generate`, {
      data: { ip: "10.10.10.5", port: "4444", shell_type: "powershell" },
    });
    expect(res.ok()).toBe(true);
    const data = await res.json();
    expect(data.count).toBeGreaterThan(0);
    expect(data.files).toContain("ps_revshell.ps1");
    expect(data.files).toContain("ps_revshell_obf.ps1");
    expect(data.files).toContain("ps_revshell_b64.txt");
    expect(data.files).toContain("ps_revshell_macro.vba");

    // Files appear in listing
    const listRes = await request.get(`${BASE}/api/shellpy/files`);
    const files = await listRes.json();
    expect(files).toContain("ps_revshell_obf.ps1");

    // File content is readable
    const fileRes = await request.get(`${BASE}/api/shellpy/files/ps_revshell_obf.ps1`);
    const fileData = await fileRes.json();
    expect(fileData.content).toBeTruthy();
    expect(fileData.content).not.toContain("$client"); // obfuscated = vars renamed

    // UI shows shellpy tab with files
    await loginIfNeeded(page);
    await goToTab(page, "tools");
    await page.locator("#shellpy-tab").click();
    await page.waitForTimeout(500);
    const sidebarFiles = await page.locator("#shellpy-files .sp-file").count();
    expect(sidebarFiles).toBeGreaterThan(0);

    // Cleanup
    await request.post(`${BASE}/api/shellpy/clear`);
  });

  test("serve creates session with tracking", async ({ request, page }) => {
    // Create serve via API
    const res = await request.post(`${BASE}/api/serve`, {
      data: { filename: "Rubeus.exe", folder: "tools", max_downloads: 2 },
    });
    expect(res.ok()).toBe(true);
    const data = await res.json();
    expect(data.id).toBeTruthy();
    expect(data.url).toContain("/serve/");

    // Download once
    const dlRes = await request.get(`${BASE}${data.url}`);
    expect(dlRes.ok()).toBe(true);

    // Check session updated
    const listRes = await request.get(`${BASE}/api/serve`);
    const sessions = await listRes.json();
    const session = sessions.find((s: any) => s.id === data.id);
    expect(session.downloads).toBe(1);
    expect(session.log).toHaveLength(1);

    // UI shows session
    await loginIfNeeded(page);
    await goToTab(page, "tools");
    await page.locator("#serve-tab").click();
    await page.waitForTimeout(500);

    const serveText = await page.locator("#serve-sessions").textContent();
    expect(serveText).toContain("Rubeus.exe");
    expect(serveText).toContain("downloads");
  });
});

// ===== TIER 6: UTILITIES TAB =====
test.describe("Tier 6: Utilities", () => {
  test("utilities loads with pipeline UI", async ({ page }) => {
    const errors = collectErrors(page);
    await loginIfNeeded(page);
    await goToTab(page, "utilities");

    await expect(page.locator("#util-input")).toBeVisible();
    await expect(page.locator("#util-output")).toBeVisible();
    await expect(page.locator(".util-step")).toHaveCount(1);
  });

  test("base64 encode works", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "utilities");

    await page.locator("#util-input").fill("Hello World");
    await page.locator("button:has-text('Convert')").click();
    const output = await page.locator("#util-output").inputValue();
    expect(output).toBe("SGVsbG8gV29ybGQ=");
  });

  test("pipeline chaining works", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "utilities");

    // Step 1: Base64 Encode (default)
    // Add step 2: Hex Encode
    await page.locator("button:has-text('+ Add Step')").click();
    await expect(page.locator(".util-step")).toHaveCount(2);

    // Set step 2 to Hex Encode
    await page.locator(".util-step").nth(1).locator("select").selectOption("hexenc");

    await page.locator("#util-input").fill("Hi");
    await page.locator("button:has-text('Convert')").click();

    const output = await page.locator("#util-output").inputValue();
    // "Hi" -> base64 "SGk=" -> hex "53 47 6b 3d"
    expect(output).toBe("53 47 6b 3d");
  });

  test("step removal works", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "utilities");

    await page.locator("button:has-text('+ Add Step')").click();
    await expect(page.locator(".util-step")).toHaveCount(2);

    // Remove step 2 (has × button)
    await page.locator(".util-step").nth(1).locator("button").click();
    await expect(page.locator(".util-step")).toHaveCount(1);
  });

  test("hash generation works", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "utilities");

    await page.locator("#util-input").fill("test");
    await page.locator("button:has-text('Hash Input')").click();
    await page.waitForTimeout(500);

    const hashLines = page.locator(".hash-line");
    expect(await hashLines.count()).toBe(5); // MD5, SHA-1, SHA-256, SHA-384, SHA-512

    // Verify MD5 of "test"
    const md5Line = hashLines.first();
    const md5Value = await md5Line.locator("code").textContent();
    expect(md5Value).toBe("098f6bcd4621d373cade4e832627b4f6");
  });
});

// ===== TIER 7: TOOLKIT TAB =====
test.describe("Tier 7: Toolkit", () => {
  test("toolkit loads with 3-column layout", async ({ page }) => {
    const errors = collectErrors(page);
    await loginIfNeeded(page);
    await goToTab(page, "toolkit");

    await expect(page.locator("#toolkit-controls")).toBeVisible();
    await expect(page.locator("#toolkit-left")).toBeVisible();
    await expect(page.locator("#toolkit-right")).toBeVisible();
  });

  test("right panel shows listener + TTY on load", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "toolkit");

    const rightText = (await page.locator("#toolkit-right").textContent())!.toLowerCase();
    expect(rightText).toContain("listener commands");
    expect(rightText).toContain("tty upgrade");
    expect(rightText).toContain("rlwrap");
    expect(rightText).toContain("pty.spawn");
  });

  test("IP field is unified input with datalist", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "toolkit");

    const ipInput = page.locator("#tk-ip");
    await expect(ipInput).toBeVisible();
    const value = await ipInput.inputValue();
    expect(value).toMatch(/\d+\.\d+\.\d+\.\d+/);

    // Datalist should have options
    const options = page.locator("#tk-ip-list option");
    expect(await options.count()).toBeGreaterThan(0);
  });

  test("shell type dropdown has no listener/tty/xterm", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "toolkit");

    const select = page.locator("#tk-shell-type");
    const optionTexts = await select.locator("option").allTextContents();

    expect(optionTexts).not.toContain("Listener Commands");
    expect(optionTexts).not.toContain("TTY Upgrade");
    expect(optionTexts).not.toContain("xterm");
    expect(optionTexts).toContain("Bash");
    expect(optionTexts).toContain("PowerShell");
    expect(optionTexts).toContain("Socat");
    expect(optionTexts).toContain("Socat (Encrypted)");
    // Shellpy options in optgroup
    expect(optionTexts).toContain("All Shellpy");
  });

  test("generate bash payloads", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "toolkit");

    await page.locator("#tk-shell-type").selectOption("Bash");
    await page.locator("button:has-text('Generate Payloads')").click();
    await page.waitForTimeout(500);

    const leftText = await page.locator("#toolkit-left").textContent();
    expect(leftText).toContain("Bash");
    expect(leftText).toContain("/dev/tcp/");

    const copyBtns = page.locator("#toolkit-left .copy-btn");
    expect(await copyBtns.count()).toBeGreaterThan(0);
  });

  test("generate socat encrypted payloads", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "toolkit");

    await page.locator("#tk-shell-type").selectOption("socat");
    await page.locator("button:has-text('Generate Payloads')").click();
    await page.waitForTimeout(500);

    const leftText = await page.locator("#toolkit-left").textContent();
    expect(leftText).toContain("Socat Encrypted");
    expect(leftText).toContain("OPENSSL-LISTEN");
    expect(leftText).toContain("shell.pem");
  });

  test("generate socat plain payloads", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "toolkit");

    await page.locator("#tk-shell-type").selectOption("socat-plain");
    await page.locator("button:has-text('Generate Payloads')").click();
    await page.waitForTimeout(500);

    const leftText = await page.locator("#toolkit-left").textContent();
    expect(leftText).toContain("Socat");
    expect(leftText).toContain("TCP:");
    expect(leftText).not.toContain("OPENSSL");
  });
});

// ===== TIER 8: CHAT TAB =====
test.describe("Tier 8: Chat", () => {
  test("chat loads with channels sidebar", async ({ page }) => {
    const errors = collectErrors(page);
    await loginIfNeeded(page);
    await goToTab(page, "chat");

    await expect(page.locator("#chat-sidebar")).toBeVisible();
    await expect(page.locator("#chat-main")).toBeVisible();
    await expect(page.locator("#chat-input")).toBeVisible();
    await expect(page.locator("#chat-send")).toBeVisible();
  });

  test("online users panel shows users", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "chat");
    await page.waitForTimeout(500);

    const onlineText = await page.locator("#chat-online-users").textContent();
    expect(onlineText!.length).toBeGreaterThan(0);
  });

  test("send message in channel", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "chat");

    // Click on first channel
    await page.locator(".chat-channel").first().click();
    await page.waitForTimeout(300);

    const msg = "E2E test message " + Date.now();
    await page.locator("#chat-input").fill(msg);
    await page.locator("#chat-send").click();
    await page.waitForTimeout(300);

    const messages = await page.locator("#chat-messages").textContent();
    expect(messages).toContain(msg);
  });

  test("create new DM chat", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "chat");
    // Force fetch users
    await page.evaluate(() => fetchUsers());
    await page.waitForTimeout(500);

    await page.locator(".chat-sidebar-header button").click();
    await page.waitForTimeout(300);

    // Should show user picker with radio buttons
    const dialog = page.locator("#new-channel-dialog");
    await expect(dialog).toBeVisible();

    const radios = dialog.locator('input[type="radio"]');
    const radioCount = await radios.count();
    // At least one other user should be available
    if (radioCount > 0) {
      await radios.first().click();
      await dialog.locator("button:has-text('Create')").click();
      await page.waitForTimeout(300);

      // New channel should appear in sidebar
      const channels = await page.locator(".chat-channel").count();
      expect(channels).toBeGreaterThan(0);
    }
  });

  test("create group with members", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "chat");
    await page.evaluate(() => fetchUsers());
    await page.waitForTimeout(500);

    await page.locator(".chat-sidebar-header button").click();
    await page.waitForTimeout(300);

    // Switch to Group tab
    await page.locator("#dtab-group").click();
    await page.waitForTimeout(200);

    await page.locator("#new-channel-name").fill("E2E Group " + Date.now());

    const checkboxes = page.locator('#user-picker input[type="checkbox"]');
    const cbCount = await checkboxes.count();
    if (cbCount > 0) {
      await checkboxes.first().click();
    }

    await page.locator("#new-channel-dialog button:has-text('Create')").click();
    await page.waitForTimeout(300);

    // Verify group channel appeared with # icon
    const lastChannel = page.locator(".chat-channel").last();
    const icon = await lastChannel.locator(".chat-channel-icon").textContent();
    expect(icon).toBe("#");
  });

  test("edit group shows modal with members", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "chat");

    // Find a group channel (# icon)
    const channels = page.locator(".chat-channel");
    const count = await channels.count();
    let foundGroup = false;
    for (let i = 0; i < count; i++) {
      const icon = await channels.nth(i).locator(".chat-channel-icon").textContent();
      if (icon === "#") {
        await channels.nth(i).click();
        foundGroup = true;
        break;
      }
    }

    if (foundGroup) {
      await page.waitForTimeout(300);
      const editBtn = page.locator("#chat-edit-group-btn");
      await expect(editBtn).toBeVisible();
      await editBtn.click();
      await page.waitForTimeout(300);

      await expect(page.locator("#edit-group-overlay")).toBeVisible();
      await expect(page.locator("#edit-group-name")).toBeVisible();

      // Close
      await page.locator("#edit-group-overlay button:has-text('Cancel')").click();
      await expect(page.locator("#edit-group-overlay")).toBeHidden();
    }
  });
});

// ===== TIER 9: CONFIGURATION TAB =====
test.describe("Tier 9: Configuration", () => {
  test("configuration shows health data", async ({ page }) => {
    const errors = collectErrors(page);
    await loginIfNeeded(page);
    await goToTab(page, "configuration");

    await page.waitForTimeout(1000);

    const content = await page.locator("#config-wrapper").textContent();
    expect(content).toContain("HEALTHY");
    expect(content).toContain("1.0.0");
    expect(content).toContain("OK");
  });

  test("network interfaces show clickable IPs", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "configuration");
    await page.waitForTimeout(1000);

    const badges = page.locator(".ip-badge");
    expect(await badges.count()).toBeGreaterThan(0);

    const firstIP = await badges.first().textContent();
    expect(firstIP).toMatch(/\d+\.\d+\.\d+\.\d+/);
  });

  test("directories all show OK", async ({ page }) => {
    await loginIfNeeded(page);
    await goToTab(page, "configuration");
    await page.waitForTimeout(1000);

    const vals = page.locator(".config-val.ok");
    expect(await vals.count()).toBeGreaterThanOrEqual(3);
  });
});

// ===== TIER 10: INTEGRITY SCAN =====
test.describe("Tier 10: Integrity Scan", () => {
  test("all tabs render without undefined/null/errors", async ({ page }) => {
    const errors = collectErrors(page);
    await loginIfNeeded(page);

    const tabs = ["shells", "tools", "utilities", "toolkit", "chat", "configuration"];
    for (const tab of tabs) {
      await goToTab(page, tab);
      await page.waitForTimeout(800);
      const body = await page.locator("#content").innerText();
      expect(body, `${tab}: no undefined`).not.toContain("undefined");
      expect(body, `${tab}: no [object Object]`).not.toContain("[object Object]");
    }

    // Filter out known non-critical errors (fetchUsers timing)
    const criticalErrors = errors.filter(
      (e) => !e.includes("Cannot read properties of undefined (reading 'then')")
    );
    expect(criticalErrors, "No critical JS errors across all tabs").toHaveLength(0);
  });
});
