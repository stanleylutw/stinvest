English correction: `Please create an implementation plan and follow it. Claude Code is not working right now.`

中文主要回覆：已建立並依照 `docs/IMPLEMENTATION_PLAN.md` 完成本階段實作，並建立／切換至 branch `fix_security_and_sync_safety`。

修改範圍：
- `docs/IMPLEMENTATION_PLAN.md`：覆寫為安全性與同步完整性修正計畫，明確區分本 branch 與後續 transaction、UI、效能 branches。
- `server.js`：Google OAuth client 改為每次操作獨立建立，避免並行 credentials race condition。
- `server.js`：OAuth state 改為 HMAC-SHA256 簽章、含 purpose／期限／nonce 的 stateless token，移除 Render 記憶體 Map 相依。
- `server.js`：`#N/A` 有快取時只回填錯誤 cell；沒有快取時保留原 row，不再從 `payload_json` 刪除；無效 price 仍不寫入 `portfolio_items`。
- `server.js`：Google 授權失效及其他同步錯誤均會把既有 sync log 標記為 `failed`。
- `server.js`：移除整個 repository 的 Express static exposure，只 allowlist `index.html`、logo 與設定圖示。
- `server.js`：支援 `NODE_ENV=test` 匯入 helper 而不啟動 listener，供單元級驗證。
- `index.html`：新增 `escapeHtml()`，保護 Sheet 表頭、帳戶、持股值與 SVG 標籤的 XSS 輸出邊界。
- `index.html`：數字 `0` 不再被顯示成 `--`；名稱欄支援「股票/ETF」及「標的」。
- `index.html`：auto sync 預設與提示統一為每 5 分鐘。
- `package.json` / `package-lock.json`：套用非 breaking 安全更新，並將 `qs` 固定為 `6.16.0`。

驗證：
- `git diff --check`：通過。
- `node --check server.js`：通過。
- 編譯 `index.html` inline script：通過。
- OAuth state 測試：有效 state 通過；竄改與過期 state 均被拒絕。
- `#N/A` 合併測試：舊 price／錯誤 cell 正確回填，新的有效數量保留；無 cache 的新標的 row 保留。
- HTML escaping 與數字 `0` 測試：通過。
- `npm start`：成功啟動；`/`、`/health`、`/stinvest_logo3.png` 均為 `200`。
- 靜態檔案限制：`/server.js`、`/supabase/schema.sql`、`/comm.md`、`/package.json` 均為 `404`。
- `npm audit --omit=dev`：由 6 個漏洞降至 4 個 moderate；剩餘項目來自 `googleapis@144` 的 `uuid` 依賴鏈，需要 breaking major upgrade，未使用 `--force`。

限制／未能驗證的部分：
- 未使用真實 Google OAuth callback 與個人 Sheet 做登入後端到端測試，避免在測試流程變更使用者授權狀態。
- 尚未處理 PostgreSQL transaction／distributed sync lock、`user_google_tokens` RLS、KPI baseline、負報酬圖表與大型載入效能改造；已列入 plan 的後續 branches。
- Render production 仍需在本 branch 通過 review、合併並部署後，才能驗證線上 `/server.js` 不再公開及 OAuth 行為。

工作區狀態：
- branch：`fix_security_and_sync_safety`
- 已修改：`docs/IMPLEMENTATION_PLAN.md`、`docs/CODEX_RESULT.md`、`server.js`、`index.html`、`package.json`、`package-lock.json`
- 未追蹤且未加入：`.DS_Store`、`stinvest_logo1.original.png`
- 尚未 commit、merge 或 push。
