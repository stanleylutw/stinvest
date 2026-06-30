# REVIEW_REPORT — bg_sync_realtime_push

Last updated: 2026-06-30 01:30:00 [Claude]

Reviewed branch: `bg_sync_realtime_push`
Reviewed against: `docs/IMPLEMENTATION_PLAN.md` + 對話中補充的 hash 範圍決策（對 `sheetData.valueRanges` 做 hash，非 `items`）

## 結論

**Pass — 無 Critical issue，有 2 個 Minor 觀察點建議記錄但不要求本輪修正。**

## Diff 範圍檢查

### `server.js`
- `performSyncForUser(userId, { fast })` 正確抽出，邏輯與原 `/api/sync` handler 逐步比對一致（建立 sync_log → fetch → merge history → build items → delete/insert → patch）✅
- `/api/sync` route handler 改為呼叫 `performSyncForUser`，response 欄位維持不變，新增 `changed` 欄位（向後相容，不影響既有前端解析）✅
- `computeSyncContentHash` 重用既有 `crypto` import，未新增套件 ✅
- **hash 範圍正確依照補充決策**：對 `sheetData.valueRanges`（mergeWithCachedHistory/mergeWithHistoryRange 之後的最終版本）做 hash，不是對 `items` 做 hash，正確涵蓋歷史/分布圖變化 ✅
- `changed === false` 時正確跳過 `portfolio_items` 寫入與新增 `sync_logs` ✅
- `runBackgroundSyncTick`：查詢 active `user_sheets` 的 distinct user_id，逐一呼叫，個別 try/catch 不中斷迴圈 ✅
- `BACKGROUND_SYNC_ENABLED` 預設關閉，`setInterval` 在 `app.listen` callback 內才啟動 ✅
- `node --check server.js` 通過（Claude 自行覆核）✅

### `index.html`
- `subscribeRealtimeUpdates` / `unsubscribeRealtimeUpdates` 正確訂閱/取消訂閱，filter 限定 `user_id`，符合 RLS 精神 ✅
- 呼叫時機正確：登入成功設定 `currentUserId` 後訂閱；無 session 與 `SIGNED_OUT` 時取消訂閱 ✅
- 既有 `REFRESH_MS` 輪詢、手動同步、auto-sync 完全未被觸碰 ✅
- 抽取 inline script `node --check` 通過（Claude 自行覆核）✅

### `.env.example` / `supabase/migration_enable_realtime.sql`
- 完全照 plan 新增，無範圍外修改 ✅

## Issue 分類

| 等級 | 數量 | 說明 |
|---|---|---|
| Critical | 0 | 無 |
| Major | 0 | 無 |
| Minor | 2 | 見下方 |

### Minor-1：`changed === false` 時不更新 `user_sheets.last_synced_at`

目前無變化的同步完全略過寫入，`last_synced_at` 只會反映「最後一次有實際變化」的時間，而不是「最後一次有檢查過」的時間。如果未來這個欄位被用來判斷「資料是否太久沒檢查」會有誤判風險。Plan 本身沒有明確規定這個欄位在 `changed:false` 時該不該更新，Codex 的選擇（不更新）合理，先記錄，不要求本輪修正。

### Minor-2：`changed:false` 路徑下的錯誤不會留下 sync_log 失敗紀錄

`sync_logs.create`（建立 `status: "running"` 的紀錄）現在被移到 hash 比對「之後」，意味著如果 fetch Google Sheet 階段就出錯（在 hash 比對之前），`syncLogId` 會是空字串，catch block 中「patch sync_log 為失敗狀態」這段邏輯會直接跳過（因為 `if (syncLogId)` 為 false）。相較於修改前「一開始就先建立 running 的 log」，現在這類早期錯誤不會在 `sync_logs` 留下任何紀錄，只能靠 server console log 排查。這是合理的 trade-off（為了避免「沒變化也建 log」而把建立時機往後挪），但會略微降低錯誤可追溯性，先記錄為觀察點。

## 驗證確認

- Codex 回報：語法檢查通過、本地 server 可啟動、`BACKGROUND_SYNC_ENABLED` 未設定時無背景行為。
- Codex 誠實標註未能驗證的部分（真實背景同步跑通、Supabase Realtime 推送、`sync_logs` 筆數未增加），且明確列出原因（需要真實憑證/手動 migration/登入），沒有假裝驗證過，摘要品質符合 comm.md Step 4 摘要格式要求。
- Claude 已獨立覆核：`node --check server.js`、抽取 inline script `node --check` 皆通過；逐行比對 diff 與 plan 一致。
- 建議使用者本輪合併後，自行到 Supabase SQL editor 執行 `supabase/migration_enable_realtime.sql`，並在確認後端部署方式（是否常駐 process）後再決定是否設定 `BACKGROUND_SYNC_ENABLED=true`。

## 後續

Review 通過，進入 Step 7（更新永久文件）。
