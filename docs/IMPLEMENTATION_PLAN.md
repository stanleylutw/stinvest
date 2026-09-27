# Bootstrap query consolidation 實作計畫 v1.0

Last updated: 2026-09-27 10:47:25 [Codex]

## Revision History

| Version | Date Time | Summary | Who | Branch |
|---|---|---|---|---|
| v1.0 | 2026-09-27 10:47:25 | 以單一 authenticated RPC 合併 active Sheet、設定與最新 cache 查詢 | Codex | `v1.0.7_bootstrap_query_consolidation` |

## Branch

本階段已建立並切換至：

```bash
git switch -c v1.0.7_bootstrap_query_consolidation
```

Parent branch：`v1.0.6_indexeddb_stale_while_revalidate`（commit `6ae110e`）

本 branch 為 stacked branch；本輪完成後需單獨 review、commit，尚不合併至 `main`。

## 目標

將登入後分開讀取 active Sheet、`user_settings` 與最新成功 `sync_logs` 的多次 Supabase round trip 合併為一個 bootstrap RPC。保留既有 direct queries 作為 migration 尚未部署或 RPC 發生錯誤時的 fallback，並沿用 v1.0.6 IndexedDB stale-while-revalidate 流程。

## 修改範圍

### `supabase/migration_dashboard_bootstrap.sql`

1. 新增無參數 `public.get_dashboard_bootstrap()`：
   - 使用 `auth.uid()`，不接受 client 傳入 user ID。
   - 以 `security invoker` 與既有 RLS／table grants 執行。
   - 一次回傳目前使用者最新 active Sheet、money mask 設定，以及該 Sheet 最新成功 sync cache 與 payload。
2. 撤銷 `public`／`anon` EXECUTE，只授權 `authenticated`。
3. 通知 PostgREST reload schema。

### `supabase/schema.sql`

同步加入 bootstrap function 與 grants，確保新環境 schema 和 migration 一致。

### `index.html`

1. 將 linked Sheet 與 cloud setting 的 UI 套用邏輯抽成可由 direct query 和 RPC 共用的 helper。
2. 新增 `loadDashboardBootstrap()`，登入 session 確認後只呼叫一次 RPC，套用 Sheet／設定並暫存最新 cache。
3. `ensureSupabaseAuth()` 優先使用 bootstrap RPC；RPC error 時記錄 warning 並回退到原本 `loadLinkedSheet()` + `loadCloudSettings()` 平行查詢。
4. `performLoadData()` 在 IndexedDB render 後優先消費 bootstrap cache：
   - `syncLogId` 相同時不重繪。
   - 新版本直接渲染並寫回 IndexedDB。
   - bootstrap 結果只消費一次，後續 refresh 繼續使用 v1.0.5 direct metadata reader。
5. 無 active Sheet 時直接顯示綁定提示，不執行空 Sheet ID 的 cache query。

### `docs/CODEX_RESULT.md`

覆寫為本階段實作與實際驗證摘要。

## 不在範圍內

- 不移除既有 direct query 或 Render fallback。
- 不變更 Google Sheets 同步、background sync、Realtime、圖表或持股計算。
- 不在 session 確認前顯示 IndexedDB 資料。
- 不把 OAuth／Supabase token 放入 RPC response 或瀏覽器 cache。
- 不 merge、push、部署或代替使用者執行 Supabase migration。

## 部署順序

1. 在 Supabase SQL Editor 執行 `supabase/migration_dashboard_bootstrap.sql`。
2. 確認 authenticated RPC 只回傳目前登入者資料，anon 無法執行。
3. 部署前端；即使前端先部署，RPC error 也會自動使用舊查詢 fallback。

## 驗證

1. `git diff --check`、`node --check server.js` 與 `index.html` inline script 編譯。
2. 靜態核對 schema／migration function body、`security invoker`、`auth.uid()` 與 grants 一致。
3. 隔離測試 RPC success：單次 RPC 套用 Sheet／設定／cache，且不呼叫舊 bootstrap queries。
4. 隔離測試 RPC error：回退至 `loadLinkedSheet()` 與 `loadCloudSettings()`。
5. 隔離測試 bootstrap cache：同版不重繪、新版重繪並持久化、消費後回到 direct reader。
6. `npm start` 與 HTTP smoke test。
