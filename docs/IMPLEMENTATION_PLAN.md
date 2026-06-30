# IMPLEMENTATION_PLAN — 背景同步 + Supabase Realtime 推送

Last updated: 2026-06-30 01:00:00 [Claude]

## Branch

Before starting implementation, create and switch to the new branch:

```
git checkout -b bg_sync_realtime_push
```

Base branch: `main`

---

## 1. 背景與目標

目前同步只能由前端觸發（開頁、按鈕、前景 auto-sync），沒人開著頁面時資料不會更新。目標：

1. 後端背景自動每 30 秒輪詢一次 Google Sheet，資料有變化才寫入 Supabase。
2. Supabase 寫入後，透過 Realtime 推送變更事件給前端。
3. 前端訂閱 Realtime channel，收到事件就重新讀取快取並更新畫面，不需要使用者手動同步。
4. 既有的「使用者主動同步」（按鈕 / 前景 auto-sync / 開頁時的條件式同步）**全部保留，不可刪除或停用**，背景同步是新增的並行機制，不是取代品。

使用情境：單一使用者（僅本人），Supabase 免費方案。已確認免費方案額度（Realtime 並發數、訊息數、DB 容量）足夠，不需要做多使用者分流設計。

## 2. 修改範圍

### 2.1 `server.js` — 抽出可重用的同步核心函式

目前 `POST /api/sync` 的 handler（約在 752-965 行之間，函式內 `try` 區塊）把「找 linked sheet → 讀 Google Sheet → 寫 portfolio_items → 更新 sync_logs」全部寫在 route handler 內部，且依賴 Express 的 `req`/`res`。

**新增一個獨立函式**，例如：

```js
async function performSyncForUser(userId, { fast = false } = {}) {
  // 把現有 /api/sync handler 內、從「找 linkedSheet」開始、
  // 到「組出回傳的 result 物件」為止的邏輯，原封不動搬進這個函式。
  // 不要依賴 req / res，所有輸入只透過參數 userId / fast 傳入。
  // 回傳值至少要包含：
  //   { ok, userId, sheetId, spreadsheetId, syncLogId, syncedRows, fast, sourceRanges, finishedAt, totalMs, data, changed }
  // 新增一個 `changed: boolean` 欄位（見 2.2）。
  // 錯誤情況：不要呼叫 res.status(...)，改成 throw new Error(...)，
  // 讓呼叫端（route handler 或背景排程）自行決定怎麼處理錯誤。
}
```

`POST /api/sync` 的 route handler 改成：先做 `requireSupabaseUser(req, res)` 拿到 `userId`，再呼叫 `performSyncForUser(userId, { fast: req.body?.fast === true })`，把回傳值組成現有的 JSON response 格式（維持目前 response 的欄位不變，前端不需要因此改動）。

**重要**：這是重構既有邏輯搬家，不是重寫。搬動時逐行比對，不要遺漏任何步驟（建立 sync_log → fetchSheetData → mergeWithCachedHistory → 判斷 isHistoryStale → buildPortfolioItemsFromSheet → delete + insert portfolio_items → patch user_sheets/sync_logs）。

### 2.2 變更判斷：避免無意義的 DB 寫入

在 `performSyncForUser` 內，組出 `items`（`buildPortfolioItemsFromSheet` 的結果）之後、寫入 DB 之前，新增一個輕量比對：

```js
function computeSyncContentHash(items) {
  // 用穩定排序後的 items 陣列做 JSON.stringify，再做簡單 hash
  // （可以用 node:crypto 的 createHash("sha256")，不需要額外套件）
}
```

讀取「上一次成功同步」的 `sync_logs`（可重用既有的 `getLatestCachedSyncLog`），比對這次算出來的 hash 跟上次是否相同：

- **相同**：跳過 `portfolio_items` 的 delete/insert，也跳過建立新的 `sync_logs` 紀錄（或者只更新一個輕量的 `last_checked_at` 欄位，不要每次都新增一筆 sync_logs，避免表格膨脹——具體做法：如果決定要記錄「有檢查過但沒變化」，可以用 PATCH 既有最新一筆 sync_log 的方式，不要 INSERT 新的一筆）。`performSyncForUser` 回傳 `{ changed: false, ... }`。
- **不同**：照原本流程寫入，回傳 `{ changed: true, ... }`。

如果這個 hash 比對邏輯讓你覺得會跟既有的 fast-sync / history-refresh 邏輯衝突或難以判斷怎麼整合，**請先停下來提問**，不要自己猜測整合方式。

### 2.3 背景排程

在 `server.js` 開頭新增環境變數讀取與設定：

```js
const BACKGROUND_SYNC_ENABLED = process.env.BACKGROUND_SYNC_ENABLED === "true";
const BACKGROUND_SYNC_INTERVAL_MS = Number(process.env.BACKGROUND_SYNC_INTERVAL_MS || 30000);
```

新增一個背景排程函式，在 `app.listen(...)` 成功啟動後啟動（不要在模組載入時就啟動，確保 server 已經準備好）：

```js
let backgroundSyncRunning = false;

async function runBackgroundSyncTick() {
  if (backgroundSyncRunning) return; // 防止上一輪還沒跑完就疊加
  backgroundSyncRunning = true;
  try {
    // 查詢所有 is_active = true 的 user_sheets，取得 distinct user_id 列表
    // 對每個 user_id 呼叫 performSyncForUser(userId, { fast: true })
    // 單一使用者情境下這應該只有 1 筆，但程式邏輯要寫成可以處理多筆（迴圈），
    // 不要寫死成只處理第一筆。
    // 每個 user 之間呼叫失敗不能讓整個迴圈中斷，個別 catch + console.error 記錄即可。
  } catch (error) {
    console.error("Background sync tick failed:", error);
  } finally {
    backgroundSyncRunning = false;
  }
}

if (BACKGROUND_SYNC_ENABLED) {
  setInterval(runBackgroundSyncTick, BACKGROUND_SYNC_INTERVAL_MS);
}
```

**注意**：`BACKGROUND_SYNC_ENABLED` 預設為 `false`（即不設定環境變數時，背景同步不會啟動）。這是刻意設計，因為目前不確定後端部署環境是否為常駐 process；先讓功能可以「明確開關」，由使用者實際部署測試後再決定是否設成 `true`。

### 2.4 `.env.example` 更新

在 `.env.example` 新增這兩個變數的說明（不要動到其他既有變數）：

```
# Background sync (optional, defaults to disabled)
BACKGROUND_SYNC_ENABLED=false
BACKGROUND_SYNC_INTERVAL_MS=30000
```

### 2.5 Supabase — 啟用 Realtime（新增 migration 檔案）

新增檔案 `supabase/migration_enable_realtime.sql`：

```sql
-- Enable Realtime for portfolio_items and sync_logs so the frontend
-- can subscribe to changes and refresh without polling.
alter publication supabase_realtime add table portfolio_items;
alter publication supabase_realtime add table sync_logs;
```

不要嘗試自動執行這個 migration（沒有 Supabase CLI 連線權限），只新增檔案，使用者會自行手動到 Supabase dashboard 執行。在這個檔案開頭加一行註解說明「需要使用者手動於 Supabase SQL editor 執行」。

### 2.6 `index.html` — 訂閱 Realtime

找到 `ensureSupabaseAuth` 函式內，登入成功後的區塊（已知 `currentUserId` 的地方）。新增一個函式：

```js
let realtimeChannel = null;

function subscribeRealtimeUpdates(userId) {
  if (!supabaseClient || !userId) return;
  if (realtimeChannel) {
    supabaseClient.removeChannel(realtimeChannel);
    realtimeChannel = null;
  }
  realtimeChannel = supabaseClient
    .channel(`portfolio-updates-${userId}`)
    .on(
      "postgres_changes",
      { event: "*", schema: "public", table: "portfolio_items", filter: `user_id=eq.${userId}` },
      () => {
        loadData();
      }
    )
    .on(
      "postgres_changes",
      { event: "*", schema: "public", table: "sync_logs", filter: `user_id=eq.${userId}` },
      () => {
        loadData();
      }
    )
    .subscribe();
}

function unsubscribeRealtimeUpdates() {
  if (realtimeChannel && supabaseClient) {
    supabaseClient.removeChannel(realtimeChannel);
  }
  realtimeChannel = null;
}
```

**呼叫時機：**
- 在 `ensureSupabaseAuth` 確認登入成功、`currentUserId` 設定完成之後，呼叫 `subscribeRealtimeUpdates(currentUserId)`。
- 在 `setupSupabaseAuthListener` 的 `SIGNED_OUT` 分支，呼叫 `unsubscribeRealtimeUpdates()`。

**不要刪除既有的 `REFRESH_MS` 60 秒輪詢機制**（`refreshTimer = setInterval(loadData, REFRESH_MS)`），它要繼續保留作為 Realtime 斷線或訂閱失敗時的備援，兩者並存沒有衝突（`loadData()` 本身有獨立的執行邏輯，重複呼叫是安全的，不需要額外加鎖）。

## 3. 不得進行的修改

- 不得刪除或停用任何既有的「使用者主動觸發同步」機制（按鈕、auto-sync 下拉選單、開頁時的條件式同步）。
- 不得修改 `buildPortfolioItemsFromSheet`、`mergeWithCachedHistory`、`mergeWithHistoryRange`、`shouldRetryHistoryRefreshSoon` 的既有邏輯，只能呼叫它們。
- 不得新增外部套件依賴（背景排程用原生 `setInterval`、hash 比對用 Node 內建 `node:crypto`，不需要 `node-cron` 等套件）。
- 不得修改前端的 `REFRESH_MS`、`AUTO_SYNC_MS` 數值。
- `BACKGROUND_SYNC_ENABLED` 必須預設為關閉，不可預設開啟。
- 若發現「比對 hash 跳過寫入」這段邏輯會破壞既有 fast-sync 的歷史刷新冷卻判斷（`shouldRetryHistoryRefreshSoon`），請先提問，不要自行決定如何處理衝突。

## 4. 驗證方式

1. 啟動本地 server：在 `.env` 暫時加上 `BACKGROUND_SYNC_ENABLED=true` 與 `BACKGROUND_SYNC_INTERVAL_MS=10000`（測試用短間隔），執行 `node server.js`，觀察 console 是否每 10 秒輸出一次背景同步的 log（沿用既有的 `console.info("Sync timing", ...)` 風格即可，不需要新增額外 log 格式）。
2. 確認背景同步不會在資料沒變化時，每次都新增一筆 `sync_logs`（可在 Supabase dashboard 查 `sync_logs` 表筆數變化）。
3. 開啟前端頁面，登入後，**不要手動按同步**，等待後端背景同步觸發一次寫入，確認前端畫面在數秒內自動更新（驗證 Realtime 推送有效）。
4. 確認既有手動「立即同步」按鈕、auto-sync 下拉選單功能都正常，沒有被背景機制影響。
5. 把 `BACKGROUND_SYNC_ENABLED` 改回 `false`（或移除），確認 server 啟動後不會跑背景排程，行為與修改前一致。
6. 檢查瀏覽器 console 與 server log 沒有新增的未預期錯誤。

## 5. 完成後

請將 diff 回報給 Claude Code 進行 Step 5 review。記得依照 comm.md 規則，輸出可複製貼上的完成摘要。
