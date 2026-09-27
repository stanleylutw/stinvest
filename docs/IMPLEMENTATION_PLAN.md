# IndexedDB stale-while-revalidate 實作計畫 v1.0

Last updated: 2026-09-27 10:38:06 [Codex]

## Revision History

| Version | Date Time | Summary | Who | Branch |
|---|---|---|---|---|
| v1.0 | 2026-09-27 10:38:06 | 登入確認後先顯示 IndexedDB cache，再以 Supabase 背景驗證 | Codex | `v1.0.6_indexeddb_stale_while_revalidate` |

## Branch

本階段已建立並切換至：

```bash
git checkout -b v1.0.6_indexeddb_stale_while_revalidate
```

Parent branch：`v1.0.5_direct_supabase_cache_read`（commit `0cffe14`）

本 branch 為 stacked branch；本輪完成後需單獨 review、commit，尚不合併至 `main`。

## 目標

在 Supabase session 與 active Sheet 已確認後，先從 IndexedDB 顯示該 user／sheet 最近成功的 dashboard payload，再以 v1.0.5 的 Supabase direct reader 背景驗證 `syncLogId`；讓回訪使用者不必等待網路即可看到資料，同時維持 Supabase 為權威來源。

## 修改範圍

### `index.html`

1. 新增 IndexedDB cache store：
   - DB：`stinvest_dashboard_cache`
   - store：`portfolio_cache`
   - key：`${userId}:${sheetId}`
   - 保存 `userId`、`sheetId`、`syncLogId`、`cachedAt`、`data`、`savedAt`。
   - 建立 `userId` index，供登出／切換使用者時清除。
2. IndexedDB API 不可用、開啟失敗、quota 或 transaction 失敗時，只寫 debug log，不阻斷 Supabase 正常流程。
3. `performLoadData()` 在 session 與 active Sheet 確認後：
   - 若目前尚未渲染 cloud version，先讀取對應 IndexedDB cache。
   - 命中時立即呼叫現有 `renderDashboardData()`，狀態顯示「已顯示本機快取，確認更新中」。
   - 接著仍查詢 Supabase metadata；相同版本略過 payload，新版本下載並靜默重繪。
4. Supabase／Render revalidate 都失敗但已顯示本機 cache 時，保留畫面並顯示離線／雲端確認失敗狀態，不清空 dashboard。
5. 雲端成功取得完整 payload 後寫入 IndexedDB；不把 legacy API token 或 OAuth token 寫入 cache。
6. 登出、解除綁定與切換使用者／Sheet 時刪除對應 cache，避免私人資料跨 session 顯示。
7. 將「清空 dashboard 資料」與「清除 Sheet 綁定 UI」拆開；尚無 cloud cache 時只清空資料並保留 active Sheet，使開頁背景首次同步仍可執行。

### `docs/CODEX_RESULT.md`

覆寫為本階段實作與實際驗證摘要。

## 不在範圍內

- 不修改 Supabase schema、RLS 或 migration。
- 不新增 bootstrap RPC/view；留待 `v1.0.7`。
- 不在 session 確認前顯示 IndexedDB 資料。
- 不使用 LocalStorage 保存 portfolio payload。
- 不修改 Google Sheets 同步、圖表或持股計算。
- 不 merge、push 或部署。

## 驗證

1. `git diff --check`、`node --check server.js` 與 inline script 編譯。
2. 以 fake IndexedDB 驗證 open／upgrade、put、get、delete 與依 user index 清除。
3. 隔離驗證 stale-while-revalidate：本機 cache 先 render，cloud 同版本不重繪，cloud 新版本覆蓋並持久化。
4. 驗證 IndexedDB 錯誤不阻斷 cloud reader。
5. 驗證登出／解除綁定／切換 Sheet 的 cache invalidation 呼叫。
6. `npm start` 與 HTTP smoke test。
