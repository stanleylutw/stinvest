English correction: `Okay, proceed to the next branch.`

中文主要回覆：已完成第二階段原子化同步實作，並建立／切換至 stacked branch `fix_atomic_portfolio_sync`。Parent branch 為 `fix_security_and_sync_safety`，commit `3ffab64`。

修改範圍：
- `docs/IMPLEMENTATION_PLAN.md`：覆寫為 atomic portfolio sync 計畫，記錄 branch 相依、部署順序與驗證方式。
- `supabase/migration_atomic_portfolio_sync.sql`：新增 atomic sync RPC、advisory transaction lock、較新同步優先保護、sync log retention、cache indexes，以及 `user_google_tokens` backend-only 權限。
- `supabase/schema.sql`：同步加入 migration 的 RPC、indexes、RLS policy 移除與 grant/revoke，確保新環境 schema 一致。
- `server.js`：新增 `userId + sheetId` process-local single-flight；重複 request 回 HTTP 202。
- `server.js`：以單次 `/rest/v1/rpc/apply_portfolio_sync` 取代 `portfolio_items` delete/insert 與兩個 final PATCH。
- `server.js`：RPC 若判定舊 request 已被較新同步 supersede，回傳 `data: null`，讓前端重新讀最新 cache。
- `server.js`：只有實際取得 local lock 的 request 能在 `finally` 釋放該 lock。

驗證：
- `git diff --check`：通過。
- `node --check server.js`：通過。
- `index.html` inline script 編譯：通過。
- Mock Supabase atomic integration：`/api/sync` 僅呼叫一次 `apply_portfolio_sync` RPC，沒有呼叫 `portfolio_items` DELETE/INSERT，回傳 `applied: true` 與正確 row count。
- Concurrent sync integration：第一個 request 持有 lock 時，第二個同 key request 回 HTTP 202 `SyncInProgress`；第一個結束後才釋放自己的 lock。
- `supabase/schema.sql` 與 migration 的 RPC 定義逐字比對一致。
- 靜態驗證 migration 包含 advisory lock、superseded guard、50/20 log retention、composite indexes、token table revoke 與 service-role-only grants。
- `npm start`：成功；`/` 與 `/health` 回 `200`，`/server.js` 回 `404`。

限制／未能驗證的部分：
- 本機沒有 `psql` 或 Supabase CLI，無法在本機 PostgreSQL 實際執行 migration；SQL 已做結構與一致性檢查，但必須先在 Supabase SQL Editor 執行。
- 未在真實 Supabase 資料上觸發兩個跨 instance RPC；資料庫 advisory lock 與 superseded 判斷依 PostgreSQL 原生 transaction semantics 實作。
- 必須先套用 `supabase/migration_atomic_portfolio_sync.sql`，再部署本 branch；順序顛倒會讓 `/api/sync` 因 RPC 尚不存在而失敗。

工作區狀態：
- branch：`fix_atomic_portfolio_sync`
- parent commit：`3ffab64 fix: harden OAuth and sync data handling`
- 已修改：`docs/IMPLEMENTATION_PLAN.md`、`docs/CODEX_RESULT.md`、`server.js`、`supabase/schema.sql`
- 新增：`supabase/migration_atomic_portfolio_sync.sql`
- 未追蹤且未加入：`.DS_Store`、`stinvest_logo1.original.png`
- 第二階段尚未 commit、merge 或 push。
