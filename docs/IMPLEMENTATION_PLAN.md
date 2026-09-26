# IMPLEMENTATION_PLAN - 原子化投資組合同步

Last updated: 2026-09-26 23:42:00 [Codex]

## Branch

本次實作使用 stacked branch：

```text
fix_atomic_portfolio_sync
```

Parent branch：`fix_security_and_sync_safety`（commit `3ffab64`）

合併順序：先合併 parent branch，再合併本 branch；本階段不直接 merge `main`。

## 1. 目標

1. 將 `portfolio_items` delete/insert、`user_sheets.last_synced_at` 與 `sync_logs` success update 放進同一個 PostgreSQL transaction。
2. 防止同一使用者／Sheet 的同步在單一 Node instance 內重疊執行。
3. 使用 PostgreSQL advisory transaction lock，避免不同 Render instance 同時寫入相同 Sheet。
4. 較早開始但較晚完成的 request 不得覆蓋已完成的新同步。
5. 禁止瀏覽器端讀取 `user_google_tokens` refresh token。
6. 增加最新成功 cache 查詢需要的索引，並限制 sync log 持續膨脹。

## 2. 修改範圍

### 2.1 `supabase/migration_atomic_portfolio_sync.sql`

- 新增 `public.apply_portfolio_sync(...)` RPC。
- RPC 先取得 `user_id + sheet_id` advisory transaction lock。
- 驗證傳入的 sync log 屬於相同使用者與 Sheet。
- 若已有 `started_at` 較新的成功同步，將目前 log 標記為 `superseded`，不覆寫資料。
- 否則在同一 transaction 中：
  - delete 該 Sheet 舊的 `portfolio_items`；
  - 由 JSONB items insert 新 snapshot；
  - 更新 `user_sheets.last_synced_at`；
  - 將 sync log 更新為 success 並寫入 payload。
- 每個 Sheet 保留最近 50 筆 success 與最近 20 筆 failed/superseded log；不清除仍為 running 的 log。
- 新增成功 cache 與同步先後比較所需 composite indexes。
- 移除 `user_google_tokens_owner_all` policy，撤銷 anon/authenticated 權限，只授權 service role。

### 2.2 `supabase/schema.sql`

- 同步加入 RPC、index、grant/revoke 與最新 RLS 定義，確保新環境 schema 與 migration 一致。

### 2.3 `server.js`

- 新增 process-local `activeSyncKeys`。
- 同一 `userId + sheetId` 已同步中時回傳 HTTP 202，不再啟動第二次 Google/Supabase sync。
- 用 `apply_portfolio_sync` RPC 取代分離的 delete、insert 與 final PATCH calls。
- 依 RPC 回傳的 `applied` 狀態決定是否直接回傳本次 payload；superseded request 讓前端重新讀最新 cache。
- route 結束時在 `finally` 釋放 process-local sync key。
- 不改變 `/api/sync` request contract。

### 2.4 `docs/CODEX_RESULT.md`

- 依 `comm.md` 覆寫本階段結果。

## 3. 部署順序

1. 先在 Supabase SQL Editor 執行 `supabase/migration_atomic_portfolio_sync.sql`。
2. 確認 function 與 indexes 建立成功。
3. 再部署包含本 branch 的 Render 後端。

若未先套 migration，新的 `/api/sync` 會因 RPC 不存在而失敗；不得顛倒順序。

## 4. 驗證

1. `git diff --check`、`node --check server.js`。
2. 以 local mock Supabase server 驗證 `/api/sync` 只呼叫一次 atomic RPC，不再呼叫 portfolio delete/insert。
3. 驗證兩個同 key request 時，第二個回 HTTP 202。
4. 靜態檢查 migration：transaction function、advisory lock、superseded guard、RLS revoke、indexes 與 retention 都存在。
5. `npm start` 與 `/health` smoke test。

## 5. 不在本階段處理

- Google APIs breaking major upgrade。
- KPI baseline 與負報酬率圖表。
- logo、bootstrap、history payload、IndexedDB 等載入效能改造。
- 實際執行 Supabase migration 或部署 Render；需要使用者的外部環境操作授權與部署順序確認。
