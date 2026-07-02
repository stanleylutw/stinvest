# IMPLEMENTATION_PLAN — 開頁立即 sync + 自動每 5 分鐘 sync

Last updated: 2026-07-02 00:00:00 [Claude]

## Branch

Before starting implementation, create and switch to the new branch:

```
git checkout -b feat_auto_sync_on_open
```

Base branch: `main`

---

## 1. 背景

目前的同步策略：
- **開頁**：`withSync: false`，只讀 Supabase 快取，不打 Google Sheets API
- **自動同步**：預設 `syncMode = "manual"`，`autoSyncTimer` 不啟動，使用者需手動切換才有定時 sync
- **定時間隔**：`AUTO_SYNC_MS = 3 * 60 * 1000`（3 分鐘）
- **快取過期閾值**：`STALE_CACHE_MS = 10 * 60 * 1000`（10 分鐘），tab focus 回來只有快取超過 10 分鐘才 sync

目標新策略：
1. **開頁立即 sync**：進頁面就打 Google Sheets API，讓使用者看到最新股價
2. **每 5 分鐘自動 sync**：預設開啟 auto 模式，不需要使用者手動切換
3. **tab 回來時**：只要距上次 sync > 30 秒就再 sync（而非現在的 10 分鐘）

---

## 2. 修改範圍（僅限 `index.html`，以下 4 處，不得修改其他函式或檔案）

### 2.1 縮小快取過期閾值

找到（`index.html` 約第 1474 行）：

```js
const STALE_CACHE_MS = 10 * 60 * 1000;
```

改成：

```js
const STALE_CACHE_MS = 30 * 1000;
```

說明：`triggerImmediateRefresh` 內的 sync 判斷是 `cacheAgeMs > STALE_CACHE_MS`，把閾值從 10 分鐘降到 30 秒，讓開頁及 tab focus 幾乎都會觸發 sync（除非 30 秒內剛剛 sync 過）。

### 2.2 縮短自動 sync 間隔

找到（約第 1473 行）：

```js
const AUTO_SYNC_MS = 3 * 60 * 1000;
```

改成：

```js
const AUTO_SYNC_MS = 5 * 60 * 1000;
```

說明：GOOGLEFINANCE 約每 15～20 分鐘更新一次，5 分鐘 sync 間隔是合理頻率，比 3 分鐘更節省 Google API quota。

### 2.3 開頁時改為 withSync: true

找到（約第 3647 行）：

```js
await startAppDataFlow("bootstrap", { force: true, withSync: false });
```

改成：

```js
await startAppDataFlow("bootstrap", { force: true, withSync: true });
```

說明：開頁時立即觸發 Google Sheets sync，不等快取新舊判斷。

### 2.4 預設同步模式改為 auto

找到（約第 3646 行）：

```js
setSyncMode("manual", { persist: false });
```

改成：

```js
setSyncMode("auto", { persist: false });
```

說明：預設啟用 auto 模式，讓 `configureAutoSync()` 在登入後自動建立 `autoSyncTimer`，不需要使用者手動切換。

---

## 3. 不得進行的修改

- 不得修改 `REFRESH_MS`（維持 60 秒）。
- 不得修改 `triggerImmediateRefresh`、`syncNow`、`loadData`、`configureAutoSync` 的函式邏輯。
- 不得修改任何 CSS、SVG 圖表、或其他功能。
- 不得修改 `server.js`。

---

## 4. 驗證方式

1. 啟動本地 server：`node server.js`，開啟 `http://localhost:3000`，登入後觀察：
   - **開頁**：瀏覽器 Network tab 應看到 `/api/sync` 被呼叫（確認有打 Google Sheets）。
   - **設定面板**：「同步模式」選項應預設顯示「自動」而非「手動」。
2. 切換到其他 tab 等待 30 秒以上，再切回來，Network tab 應再次看到 `/api/sync`。
3. 等待 5 分鐘，應自動觸發一次 sync（可觀察 server log 的 `syncNow` 訊息）。
4. 在 30 秒內連續切換 tab，應只觸發一次 sync（防抖保護正常）。
5. 檢查瀏覽器 console 沒有新增的 JS 錯誤。

---

## 5. 完成後

依照 comm.md 最新規則，把完成摘要寫入 `docs/CODEX_RESULT.md`（覆寫，不要累加），不需要在聊天視窗整段貼出摘要全文，跟使用者說一句已完成即可。
