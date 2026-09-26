English correction: `Please proceed with the next branch.`

中文主要回覆：已先將上一階段 commit 為 `7468409 fix: correct dashboard baselines and negative chart values`，再依照新的 `docs/IMPLEMENTATION_PLAN.md` 完成快取刷新效能改善，並建立／切換至 stacked branch `perf_cache_refresh_pipeline`。

修改範圍：
- `docs/IMPLEMENTATION_PLAN.md`：覆寫為快取刷新管線效能計畫，明確保留既有開頁同步、5 分鐘 auto sync 與 60 秒 cache refresh 行為。
- `index.html`：將底層載入拆為 `performLoadData()`，並由 `loadData()` single-flight wrapper 共用進行中的 Promise，避免 timer、focus 與同步 fallback 重複請求。
- `index.html`：保存最後渲染的 `syncLogId`／同步時間，後續快取請求送出 `If-None-Match`；HTTP 304 時沿用目前畫面，不下載、解析或重繪 payload。
- `index.html`：HTTP 200 但 `syncLogId` 相同時略過 dashboard 完整 parse/render，只更新快取狀態與相對時間。
- `index.html`：解除綁定、登出／切換使用者或切換 Sheet 時清除最後渲染版本；refresh interval 改用明確 callback。
- `server.js`：CORS 允許 `If-None-Match` 並 expose `ETag`。
- `server.js`：`/api/portfolio-cached` 以最新成功 `sync_logs.id` 作為 ETag；版本相同回 304，初次或版本更新回原有 200 payload。
- `server.js`：有 ETag 的輪詢先只查最新 log metadata；只有版本更新才額外讀 `payload_json`。指定 `sheet_id` 時，Sheet ownership 與 log metadata 查詢平行執行，但回應前仍強制驗證 ownership。
- `docs/CODEX_RESULT.md`：覆寫為本階段實作結果。

驗證：
- `git diff --check`：通過。
- `node --check server.js`：通過。
- `index.html` inline script 編譯：通過。
- 前端 single-flight 隔離測試：兩個同時 `loadData()` 呼叫共用同一 Promise，底層僅執行一次；完成後的新呼叫可正常啟動下一次載入。
- Mock Supabase integration：首次讀取回 200、完整 payload 與 ETag；相同 ETag 回 304 且不讀 payload；新 log ID 回 200 且只讀一次新 payload；無 Sheet ownership 時回 400 `NoLinkedSheet`。
- Mock integration 以 deferred ownership query 驗證 `user_sheets` 與 `sync_logs` 查詢確實平行啟動。
- `npm start`：成功啟動於 `http://localhost:3000`，測試後已停止。
- HTTP smoke test：`/` 回 200、`/health` 回 200、`/server.js` 回 404、CORS preflight 回 204。

限制／未能驗證的部分：
- 本機沒有真實 Supabase 登入 session 與大型 `payload_json`，無法在 production network 面板量測節省的傳輸位元組與重繪時間；200／304 與查詢次數已由 mock integration 驗證。
- 第一次 integration test 因受限沙箱禁止臨時 loopback listener 而收到 `EPERM`；以核准的本機 loopback 執行環境重跑相同測試後全部通過。
- 本階段未修改 Supabase schema、RLS 或 migration，不需要執行新 SQL。
- 尚未 commit、merge、push 或部署，需先 review 此 stacked branch。

工作區狀態：
- branch：`perf_cache_refresh_pipeline`
- parent commit：`7468409 fix: correct dashboard baselines and negative chart values`
- 已修改：`index.html`、`server.js`、`docs/IMPLEMENTATION_PLAN.md`、`docs/CODEX_RESULT.md`
- 未追蹤且未加入：`.DS_Store`、`stinvest_logo1.original.png`
- 未修改 plan 範圍外的檔案。
