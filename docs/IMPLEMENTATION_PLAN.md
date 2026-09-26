# 快取刷新管線效能改善實作計畫 v1.0

Last updated: 2026-09-26 23:53:51 [Codex]

## Revision History

| Version | Date Time | Summary | Who | Branch |
|---|---|---|---|---|
| v1.0 | 2026-09-26 23:53:51 | 降低重複快取請求、payload 傳輸與前端重繪成本 | Codex | `perf_cache_refresh_pipeline` |

## Branch

本階段已建立並切換至：

```bash
git checkout -b perf_cache_refresh_pipeline
```

Parent branch：`fix_dashboard_logic_and_charts`（commit `7468409`）

本 branch 為 stacked branch；需依序 review、commit，尚不合併至 `main`。

## 目標

在不改變開頁背景同步、每 5 分鐘自動同步與每 60 秒快取檢查等既有產品行為下，降低相同快取被重複請求、下載、解析與重繪的成本，並避免重疊 `loadData()` 造成舊回應覆蓋新畫面。

## 修改範圍

### `index.html`

1. 為 `loadData()` 增加 single-flight：已有快取請求進行時共用同一 Promise，避免 timer、focus 與同步 fallback 重疊發送請求。
2. 保存最後成功渲染的 `syncLogId` 與同步時間；讀取快取時以 `If-None-Match` 傳給後端。
3. 後端回 HTTP 304 時沿用目前畫面與同步時間，不重新下載、解析或渲染 payload。
4. 即使收到 HTTP 200，若 `syncLogId` 與最後渲染版本相同，也只更新狀態文字，不重跑完整 dashboard parse/render。
5. 解除綁定、登出或切換使用者時清除最後渲染版本，避免跨 Sheet／跨使用者誤判為未變更。
6. 將 `setInterval(loadData, ...)` 改為明確 callback，避免 timer 參數誤傳至未來擴充的函式介面。

### `server.js`

1. CORS allow headers 加入 `If-None-Match`。
2. `/api/portfolio-cached` 支援以最新 `sync_logs.id` 作為 ETag：
   - ETag 相同時回 HTTP 304，不回傳 `payload_json`。
   - 初次或版本變更時回 HTTP 200 與完整 payload，並附 ETag。
3. 已指定 `sheet_id` 時，平行執行 Sheet ownership 驗證與最新 log metadata 查詢。
4. 有條件請求先只讀 log metadata；僅在版本變更時再讀該筆 `payload_json`，降低每分鐘輪詢的 Supabase payload 傳輸量。
5. 未指定 `sheet_id` 的 legacy 路徑維持原本依序查詢行為。

### `docs/CODEX_RESULT.md`

覆寫為本階段實作與實際驗證摘要。

## 不在範圍內

- 不修改 Google Sheets 同步頻率、開頁背景同步或 auto/manual mode。
- 不修改 Supabase schema、RLS、migration 或 API response 的成功 payload 結構。
- 不導入 IndexedDB、Service Worker 或新的前端 framework。
- 不修改圖表、KPI、OAuth 與持股資料邏輯。
- 不 merge、push 或部署。

## 驗證

1. `git diff --check`、`node --check server.js` 與 inline script 編譯。
2. Mock Supabase integration：
   - 首次快取讀取回 200、完整 payload 與 ETag。
   - 相同 `If-None-Match` 回 304，且不執行 payload query。
   - 新 log ID 回 200，metadata 與 payload 查詢順序正確。
   - 不屬於目前使用者的 `sheet_id` 不得回傳資料。
3. 前端隔離測試：並行兩次 `loadData()` 只執行一次 underlying load。
4. 啟動本機 server，確認 `/`、`/health` 與靜態檔案 allowlist。
