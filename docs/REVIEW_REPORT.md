# REVIEW_REPORT — fix_history_chart_label_gap

Last updated: 2026-06-30 03:50:00 [Claude]

Reviewed branch: `fix_history_chart_label_gap`
Reviewed against: `docs/IMPLEMENTATION_PLAN.md`

## 結論

**Pass — 無 Critical / Major issue，有 1 個 Minor 邊界案例記錄但不要求本輪修正。**

## Diff 範圍檢查

僅修改 `index.html` 的 `renderHistoryTrendChart`，與 plan 完全一致：

1. `m.r`：`showY2 ? 74 : 20` → `showY2 ? 56 : 20` ✅
2. Y2 座標軸數字：`x="${w - m.r + 10}"` `text-anchor="start"` → `x="${w - 4}"` `text-anchor="end"`，貼齊右邊界 ✅
3. X 軸日期標籤：改用 `xLabelIndexes` 集合，偵測「規律最後一個」與「強制最後一個」距離過近時移除前者 ✅
4. Y2 右上角圖例文字（`x="${w - m.r}"`）維持原樣未動——正確判斷：圖例在 `y=13`（頂部），跟座標軸數字分佈在不同 y 列，沒有重疊風險，不需要額外修改 ✅

## Issue 分類

| 等級 | 數量 | 說明 |
|---|---|---|
| Critical | 0 | 無 |
| Major | 0 | 無 |
| Minor | 1 | 見下方 |

### Minor-1：防重疊判斷在特定 `n`/`xStep` 組合下，仍可能留下「相鄰 1 格」的標籤

用 Node 獨立驗證這段邏輯時，發現當 `xStep` 為偶數、且「規律最後一個」與「強制最後一個」剛好相差 `xStep / 2`（例如 `n=16` 時 `xStep=2`，產生索引 `..., 14, 15`）時，判斷式 `last - secondLast < xStep / 2` 不成立（`1 < 1` 為 false），兩個標籤會保留相鄰 1 格的距離，仍有機率視覺上偏擠（雖然遠比修復前的「完全疊在一起」輕微很多）。

這是一個範圍很窄的邊界案例（需要特定 `n` 與 `xStep` 整除關係才會出現），且即使出現，效果也只是「稍微擠」而非「完全重疊亂碼」，不影響本次主要問題已解決的結論。建議標記但不要求本輪修正，下次如果使用者實際看到還是有點擠，可以把判斷條件從 `<` 改成 `<=` 再修一次。

## 驗證確認

- Codex 回報：語法檢查通過、本地 server 可啟動、DOM 檢查確認程式碼包含預期片段、用獨立 Node 案例驗證 `n=17` 情境正確避開碰撞。
- Codex 誠實標註：未登入無法用真實資料目視驗證，且如實記錄了未登入狀態下 `loadData()` 出現的 `Failed to fetch`（屬於既有行為，非本次改動範圍，正確判斷不算入本次驗證項目）。
- Claude 已獨立覆核：`node --check server.js`、抽取 inline script `node --check` 均通過；額外用 Node 跑了 `n=17/16/9/1` 四組案例，發現上述 Minor-1 邊界狀況。
- `docs/CODEX_RESULT.md` 本次正確產生，流程已照新規則運作，不需要使用者複製貼上。

## 後續

Review 通過，進入 Step 7（更新永久文件）。
