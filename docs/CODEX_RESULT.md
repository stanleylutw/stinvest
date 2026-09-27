English correction: `Let's implement them step by step.`

中文主要回覆：已完成第 1 步，並建立／切換至 stacked branch `v1.0.5_direct_supabase_cache_read`。Parent branch 為 `v1.0.4_perf_cache_refresh_pipeline`，commit `23e2cfd`。

修改範圍：
- `docs/IMPLEMENTATION_PLAN.md`：覆寫為 v1.0.5 前端直讀 Supabase cache 與 SELECT-only RLS 計畫。
- `index.html`：新增 `loadCachedPortfolioFromSupabase()`；首次直接查詢目前 user／sheet 最新成功 `sync_logs` 與 `payload_json`，正常首屏不再經過 Render。
- `index.html`：已有畫面版本時先只查 metadata；`syncLogId` 相同則略過 payload 下載，版本改變才讀取該筆 `payload_json`。
- `index.html`：新增 `loadPreferredCachedPortfolio()`；direct query 成功或無 cache 時不呼叫 Render，只有 Supabase query error／exception 才使用原有 `/api/portfolio-cached` ETag fallback。
- `index.html`：保留 legacy Google session/API token 路徑、single-flight、相同版本免重繪與原有同步策略。
- `supabase/migration_sync_logs_select_only.sql`：新增 migration，將 authenticated client 的 `sync_logs` 權限限制為 owner SELECT-only，撤銷 anon 與 authenticated 寫入權限，保留 service role 後端寫入權限。
- `supabase/schema.sql`：同步更新 `sync_logs_owner_select` policy 與 grants，確保新環境 schema 一致。
- `docs/CODEX_RESULT.md`：覆寫為本階段實作結果。

驗證：
- `git diff --check`：通過。
- `node --check server.js`：通過。
- `index.html` inline script 編譯：通過。
- Supabase direct reader 隔離測試：5 組通過，涵蓋首次完整讀取、無 cache、不變 metadata、新版本 metadata + payload，以及 query error 才 fallback。
- 查詢條件驗證：包含 `user_id`、`sheet_id`、`status=success`、`finished_at/created_at` 降冪排序、`limit=1`；版本更新時 payload query 額外限制最新 log `id`。
- direct read 成功時測試中的 Render fetch 與 token getter 均設定為直接拋錯，測試仍通過，確認正常路徑不依賴 Render。
- `supabase/schema.sql` 與 migration 靜態檢查：SELECT-only policy、anon revoke、authenticated SELECT grant、authenticated write revoke 與 service role grants 均存在；schema 已移除舊的 owner-all policy 建立語句。
- `npm start`：成功啟動於 `http://localhost:3000`，測試後已停止。
- HTTP smoke test：`/` 回 200、`/health` 回 200、`/server.js` 回 404。

限制／未能驗證的部分：
- 本機沒有真實 Supabase 登入 session，無法量測 production direct query latency，也無法在真實 RLS session 下執行 SELECT／拒絕寫入測試。
- 尚未在 Supabase 執行 migration。部署前應先執行 `supabase/migration_sync_logs_select_only.sql`，再確認 authenticated 使用者只能 SELECT 自己的 sync logs。
- 本輪未實作 IndexedDB（v1.0.6）或 bootstrap RPC/view（v1.0.7）。
- 尚未 commit、merge、push 或部署，需先 review 此 stacked branch。

工作區狀態：
- branch：`v1.0.5_direct_supabase_cache_read`
- parent commit：`23e2cfd perf: optimize cached portfolio refresh pipeline`
- 本輪修改：`index.html`、`supabase/schema.sql`、`supabase/migration_sync_logs_select_only.sql`、`docs/IMPLEMENTATION_PLAN.md`、`docs/CODEX_RESULT.md`
- 外部修改、未由本輪 Codex 編輯：`docs/REVIEW_REPORT.md`、`00_investment_dashboard_plan_v1.0.md`（Claude 對 v1.0.1～v1.0.4 的 review／永久文件更新；不得誤納入 v1.0.5 commit，除非使用者另行指定）
- 未追蹤且未加入：`.DS_Store`、`stinvest_logo1.original.png`
