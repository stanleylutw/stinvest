English correction: `When finished, write a summary to docs/CODEX_RESULT.md, overwriting the file each time instead of appending.`

中文主要回覆：已依照 docs/IMPLEMENTATION_PLAN.md 完成實作，並建立/切到 branch `feat_auto_sync_on_open`。

修改範圍：
- index.html：將 `AUTO_SYNC_MS` 從 `3 * 60 * 1000` 改為 `5 * 60 * 1000`，讓 auto sync 間隔改為 5 分鐘。
- index.html：將 `STALE_CACHE_MS` 從 `10 * 60 * 1000` 改為 `30 * 1000`，讓 tab focus / immediate refresh 的快取過期判斷縮短為 30 秒。
- index.html：將 bootstrap 預設同步模式從 `setSyncMode("manual", { persist: false })` 改為 `setSyncMode("auto", { persist: false })`。
- index.html：將開頁資料流程從 `startAppDataFlow("bootstrap", { force: true, withSync: false })` 改為 `startAppDataFlow("bootstrap", { force: true, withSync: true })`，讓登入後開頁立即 sync。
- docs/CODEX_RESULT.md：依 comm.md 規則覆寫本次 Step 4 完成摘要。

驗證：
- `git diff --check`：通過。
- `node --check server.js`：通過。
- 抽出 `index.html` inline script 到 `/tmp/stinvest-inline.js` 後執行 `node --check /tmp/stinvest-inline.js`：通過。
- `npm start`：成功啟動本地 server，顯示 `Server running on http://localhost:3000`。
- 瀏覽器開啟 `http://localhost:3000`：頁面可載入，title 為 `ST投資總表`。
- 瀏覽器 DOM 檢查：確認頁面 script 包含 `setSyncMode("auto", { persist: false })`、`startAppDataFlow("bootstrap", { force: true, withSync: true })`、`AUTO_SYNC_MS = 5 * 60 * 1000`、`STALE_CACHE_MS = 30 * 1000`。
- 瀏覽器 console error：`[]`，沒有新增 JS error。

限制／未能驗證的部分：
- 本機瀏覽器目前停在未登入狀態，無法實際確認登入後 Network tab 是否呼叫 `/api/sync`。
- 因未登入，無法目視確認設定面板「同步模式」是否預設顯示「自動」。
- 沒有等待完整 5 分鐘觀察 auto sync timer 實際觸發；已透過程式碼與語法檢查確認 timer 使用的 `AUTO_SYNC_MS` 常數已改為 5 分鐘。
- 沒有實際操作 tab focus 超過 30 秒再切回來驗證 `/api/sync`；已確認 `STALE_CACHE_MS` 已依 plan 改為 30 秒，且未修改 `triggerImmediateRefresh()` 函式邏輯。

工作區狀態：
- 目前 branch：`feat_auto_sync_on_open`
- 已修改檔案：`index.html`
- 已修改檔案：`docs/CODEX_RESULT.md`
- 既有未提交修改仍存在：`00_investment_dashboard_plan_v1.0.md`、`docs/IMPLEMENTATION_PLAN.md`
- 未追蹤檔案仍存在：`.DS_Store`、`comm.md`、`stinvest_logo1.original.png`
