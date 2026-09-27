# 前端直讀 Supabase 快取實作計畫 v1.0

Last updated: 2026-09-27 10:32:34 [Codex]

## Revision History

| Version | Date Time | Summary | Who | Branch |
|---|---|---|---|---|
| v1.0 | 2026-09-27 10:32:34 | 前端直讀 sync_logs 並將 authenticated 權限限制為 SELECT | Codex | `v1.0.5_direct_supabase_cache_read` |

## Branch

本階段已建立並切換至：

```bash
git checkout -b v1.0.5_direct_supabase_cache_read
```

Parent branch：`v1.0.4_perf_cache_refresh_pipeline`（commit `23e2cfd`）

本 branch 為 stacked branch；本輪完成後需單獨 review、commit，尚不合併至 `main`。

## 目標

讓已登入使用者的 dashboard cache 直接由瀏覽器透過 Supabase SDK 與 RLS 讀取，將 Render 冷啟動移出正常首屏路徑；保留 `/api/portfolio-cached` 作為 Supabase SDK 查詢失敗時的 legacy fallback。

## 修改範圍

### `index.html`

1. 新增 Supabase cache reader，從 `sync_logs` 查詢目前 `user_id + sheet_id` 最新一筆 `status=success`：
   - 首次載入讀取 `id`、`finished_at`、`row_count`、`spreadsheet_id`、`payload_json`。
   - 已有畫面版本時先只讀 metadata；`syncLogId` 改變才讀取該筆 `payload_json`。
   - 依 `finished_at desc`、`created_at desc` 排序並限制一筆。
   - 同時指定 `user_id` 與 `sheet_id`；RLS 再次限制只能讀取目前登入者資料。
2. 正常登入路徑優先使用 Supabase SDK 結果，沿用現有 `syncLogId` 去重與 render 流程。
3. Supabase query 回傳「沒有資料」時直接顯示尚無快取，不喚醒 Render。
4. 僅在 Supabase query 回傳 error／拋出例外時，才使用既有 `/api/portfolio-cached` ETag fallback。
5. legacy Google session/API token 路徑維持現況。

### `supabase/migration_sync_logs_select_only.sql`

1. 移除 authenticated 使用者可對自己 `sync_logs` 執行 all operations 的 policy。
2. 新增 owner SELECT-only policy。
3. 明確撤銷 `anon` 對 `sync_logs` 的所有權限。
4. authenticated 僅保留 SELECT；撤銷 INSERT／UPDATE／DELETE／TRUNCATE／REFERENCES／TRIGGER。
5. 明確保留 `service_role` 的 SELECT／INSERT／UPDATE／DELETE，供 Node 後端與 atomic RPC 使用。

### `supabase/schema.sql`

同步 migration 的 policy 與 grants，確保新環境 schema 一致。

### `docs/CODEX_RESULT.md`

覆寫為本階段實作與實際驗證摘要。

## 不在範圍內

- 不加入 IndexedDB 或 LocalStorage payload cache；留待 `v1.0.6`。
- 不新增 bootstrap RPC/view；留待 `v1.0.7`。
- 不修改 Google Sheets 同步、auto/manual mode、圖表或持股計算。
- 不移除 Render `/api/portfolio-cached` 或 v1.0.4 的 ETag fallback。
- 不 merge、push、部署或實際執行 Supabase migration。

## 部署順序

1. 在 Supabase SQL Editor 執行 `supabase/migration_sync_logs_select_only.sql`。
2. 確認登入使用者可 SELECT 自己的 `sync_logs`，但無法 INSERT／UPDATE／DELETE。
3. 再部署前端。

現有 `sync_logs_owner_all` 已允許 owner SELECT，因此前端先部署不會讀取失敗；仍建議先套 migration，避免保留過寬的 client write 權限。

## 驗證

1. `git diff --check`、`node --check server.js` 與 inline script 編譯。
2. 隔離測試 Supabase SDK query chain：user、sheet、status、排序、limit 與欄位選擇正確。
3. 驗證 direct read 成功時不呼叫 Render fetch。
4. 驗證無 cache 時不呼叫 Render；query error 時才呼叫 legacy fallback。
5. 靜態核對 schema 與 migration 的 RLS/grants 一致。
6. `npm start` smoke test。
