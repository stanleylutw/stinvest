English correction: `Let's do the next branhc.` -> `Let's proceed with the next branch.`

中文主要回覆：已依照 `docs/IMPLEMENTATION_PLAN.md` 完成實作，並建立／切換至 stacked branch `v1.0.7_bootstrap_query_consolidation`。Parent branch 為 `v1.0.6_indexeddb_stale_while_revalidate`，commit `6ae110e`。

修改範圍：
- `docs/IMPLEMENTATION_PLAN.md`：覆寫為 v1.0.7 bootstrap query consolidation 計畫，記錄 RPC 安全邊界、前端 fallback、部署順序與驗證項目。
- `supabase/migration_dashboard_bootstrap.sql`：新增無參數 `public.get_dashboard_bootstrap()`；以 `auth.uid()`、`security invoker` 及既有 RLS，一次回傳目前使用者的 active Sheet、money mask 設定與該 Sheet 最新成功 cache payload。
- `supabase/migration_dashboard_bootstrap.sql`：撤銷 `public`／`anon` EXECUTE，只授權 `authenticated`，並通知 PostgREST reload schema。
- `supabase/schema.sql`：同步加入完全相同的 bootstrap function 與 grants，確保新環境 schema 一致。
- `index.html`：抽出 `applyLinkedSheetRow()` 與 `applyCloudSettingsRow()`，供 RPC 與原有 direct queries 共用同一套 UI／state 套用邏輯。
- `index.html`：新增 `loadDashboardBootstrap()`；登入 session 確認後以單次 RPC 載入 Sheet、設定與最新 cache。RPC 未部署或失敗時，自動回退至既有 `loadLinkedSheet()`／`loadCloudSettings()` 平行查詢。
- `index.html`：bootstrap cache 只消費一次；IndexedDB 已顯示同一 `syncLogId` 時不重繪，新版本則直接渲染並持久化，之後 refresh 恢復使用 v1.0.5 direct metadata reader。
- `index.html`：登出、無 session 與切換使用者時清除 pending bootstrap state；無 active Sheet 時直接顯示綁定提示，不再用空 Sheet ID 查 cache。
- `docs/CODEX_RESULT.md`：覆寫為本階段實作結果。

驗證：
- `git diff --check`：通過；新增 migration 另以 trailing-whitespace 掃描確認無問題。
- `node --check server.js`：通過。
- `index.html` inline script 編譯：通過（1 個 inline script）。
- bootstrap 前端隔離測試：7 個情境通過，涵蓋 RPC success 單次呼叫、RPC error、`ensureSupabaseAuth()` success 不呼叫 legacy queries、RPC error 回退兩個 legacy queries、同版 cache 不重繪、新版 cache render + IndexedDB write，以及 bootstrap 消費後恢復 direct reader。
- SQL 一致性檢查：從 `supabase/schema.sql` 與 migration 擷取 `get_dashboard_bootstrap()` 到 grant 的內容執行 `diff`，結果完全一致。
- SQL 安全性靜態檢查：migration 與 schema 均包含 `security invoker`、三處 `auth.uid()` owner filter、public／anon revoke 與 authenticated grant。
- `npm start`：成功啟動於 `http://localhost:3000`，測試後已停止。
- HTTP smoke test：`/` 回 200、`/health` 回 200、`/server.js` 回 404。

限制／未能驗證的部分：
- 本機沒有連接 production Supabase／真實登入 session，因此未實際執行 RPC、驗證 production RLS 隔離或量測合併後 latency；前端行為使用隔離 mock 驗證。
- 部署前必須在 Supabase SQL Editor 執行 `supabase/migration_dashboard_bootstrap.sql`。若前端先部署，RPC error 會自動回退舊查詢，不會阻斷 dashboard。
- 本輪未移除 direct Supabase reader 或 Render fallback，也未修改 Google Sheets 同步、background sync、Realtime、圖表或持股計算。
- v1.0.7 尚未 commit、merge、push 或部署，需先 review 此 stacked branch。

工作區狀態：
- branch：`v1.0.7_bootstrap_query_consolidation`
- parent commit：`6ae110e perf: add IndexedDB stale-while-revalidate cache`
- 本輪修改／新增：`index.html`、`supabase/schema.sql`、`supabase/migration_dashboard_bootstrap.sql`、`docs/IMPLEMENTATION_PLAN.md`、`docs/CODEX_RESULT.md`
- 外部修改、未由本輪 Codex 編輯：`docs/REVIEW_REPORT.md`、`00_investment_dashboard_plan_v1.0.md`（保留原狀，不應誤納入 v1.0.7 commit，除非使用者另行指定）
- 未追蹤且未加入：`.DS_Store`、`stinvest_logo1.original.png`
