# IMPLEMENTATION_PLAN - 安全性與同步完整性修正

Last updated: 2026-09-26 23:28:43 [Codex]

## Branch

本次實作使用 branch：

```text
fix_security_and_sync_safety
```

Base branch：`main`

## 1. 目標

本階段先修正不需要資料庫 transaction 便能安全部署的高風險問題：

1. 防止 Google Sheet 內容透過 `innerHTML` / SVG 造成 XSS。
2. 移除 Google OAuth client 全域 credentials 共用造成的 race condition。
3. 將 Google OAuth state 改成具 HMAC 簽章與期限的 stateless token，避免 Render 重啟造成狀態遺失。
4. 修正 `#N/A` 持股回退：有快取時只回填錯誤欄位，沒有快取時保留原始列，不再從 payload 中刪除。
5. Google 授權失效時，仍將已建立的 sync log 標記為 `failed`。
6. 停止由 Express 公開整個專案目錄，只提供前端必要檔案。
7. 統一 auto sync 的預設值與 5 分鐘提示文字。
8. 修正「標的」名稱欄位相容性與數值 `0` 顯示。
9. 更新可安全升級的 npm 依賴並重新執行 audit。

## 2. 修改範圍

### 2.1 `server.js`

- 新增 `createOAuth2Client()` factory。
- Google 授權 URL、callback token exchange、Sheets API request 各自使用獨立 client。
- 移除 `pendingGoogleLinkStates` 記憶體 Map 與其清理流程。
- 使用 `SESSION_SECRET` 對 OAuth state payload 做 HMAC-SHA256 簽章。
- state payload 包含 `purpose`、`userId`（link flow）、`returnTo`、`expiresAt` 與 nonce。
- callback 僅接受簽章正確、未過期且 purpose 合法的 state。
- `mergeCachedRowsForInvalidPrices()`：
  - 有舊資料時，只以舊值替換目前 row 中的 Sheet error cells。
  - 沒有舊資料時保留目前 row，避免從 `payload_json` 消失。
  - `portfolio_items` 仍不得寫入無效 price。
- 抽出 sync log failure helper；包含 `GoogleNotLinked` 在內的錯誤都先更新 log，再回應。
- 將 `express.static(__dirname)` 改成明確的前端檔案 allowlist。
- 不變更既有 API URL 與 response contract。

### 2.2 `index.html`

- 新增集中式 `escapeHtml()`，所有由 Sheet 或快取取得、再插入 `innerHTML` / SVG 的文字必須 escape。
- `td()` 使用 nullish/empty 判斷，數字 `0` 不得顯示為 `--`。
- `resolveColumnIndexes()` 的名稱欄位同時支援「股票/ETF」與「標的」。
- auto sync 提示改為 5 分鐘。
- 沒有已儲存偏好時預設為 `auto`，與 bootstrap 行為一致。
- 本階段不改 KPI 比較基準與負報酬圖表座標系；它們屬於下一個 UI/logic branch。

### 2.3 `package.json` / `package-lock.json`

- 執行非 breaking 的 dependency 更新。
- 不使用 `npm audit fix --force`。
- Google APIs 的 breaking major upgrade 留待獨立 branch。

### 2.4 `docs/CODEX_RESULT.md`

- 完成後依 `comm.md` 格式覆寫本次結果。

## 3. 本階段刻意不處理

以下工作需要獨立 migration、產品決策或較大的效能改造，不納入本 branch：

- `portfolio_items` delete/insert 改為 PostgreSQL transaction/RPC。
- 跨 Render instance 的 distributed sync lock。
- `user_google_tokens` RLS 收斂；將與 transaction migration 一起規劃並先套 SQL 再部署後端。
- KPI 比較基準改成前一筆有效快照。
- 投資分布圖支援負值座標。
- logo 壓縮、IndexedDB snapshot、history lazy loading、ETag/Realtime。
- Render Auto-Deploy 設定；這是部署平台設定，不是 repository code。

## 4. 驗證

1. `git diff --check`。
2. `node --check server.js`。
3. 抽取 `index.html` inline script 後執行 `node --check`。
4. 以 Node 小型案例驗證：
   - OAuth state 正確、竄改、過期三種情境。
   - `#N/A` 有 cache 時只替換錯誤 cell。
   - `#N/A` 無 cache 時 row 保留於 payload。
   - HTML escaping 與數字 `0` 顯示。
5. `npm start`，確認 `/`、`/health`、必要前端 assets 回傳 `200`。
6. 確認 `/server.js`、`/supabase/schema.sql`、`/comm.md` 回傳 `404`。
7. `npm audit --omit=dev`，記錄仍存在的漏洞與不能非破壞性修正的項目。

## 5. 後續 branches

1. `fix_atomic_portfolio_sync`：transaction/RPC、sync lock、token table RLS、索引與 retention。
2. `fix_dashboard_logic_and_charts`：KPI baseline、負報酬率圖、相關 UI 邊界案例。
3. `perf_dashboard_loading`：logo、bootstrap round trips、payload unchanged check、history lazy load、本機 snapshot。
