# IMPLEMENTATION_PLAN — 修正手機直向圖表文字重疊（回歸問題）

Last updated: 2026-06-30 00:30:00 [Claude]

## Branch

Before starting implementation, create and switch to the new branch:

```
git checkout -b fix_mobile_chart_label_overlap
```

Base branch: `main`

---

## 1. 背景

上次修復「手機直向圖表下方留白」（branch `fix_mobile_chart_blank_space`）時，將 `renderHistoryTrendChart` 與 `renderDistribution` 內的圖表寬度計算，由 `Math.max(N, measuredWidth)` 改成 `measuredWidth || N`。

這個改動在桌面寬螢幕沒有副作用，但在手機直向（容器寬度約 350px）時，造成 SVG 內部繪圖座標系統（viewBox）也跟著縮到 350，而文字 `font-size` 是寫死的絕對數值不會跟著縮小，導致：
- 「投資分布圖」X 軸的 8 個分類名稱、漲跌幅標籤全部重疊。
- 「歷史報酬率趨勢」X 軸的日期標籤全部重疊。

## 2. 修改範圍（僅限 `index.html`，以下兩處，不得修改其他任何程式碼）

### 2.1 `renderHistoryTrendChart`

找到：
```js
const w = measuredWidth || 760;
```
改回：
```js
const w = Math.max(760, measuredWidth);
```

### 2.2 `renderDistribution`

找到：
```js
const chartW = measuredWidth || 720;
```
改回：
```js
const chartW = Math.max(720, measuredWidth);
```

## 3. 為什麼這樣改不會讓「留白問題」再次出現

留白問題（UI-1）的根因是 CSS `.dist-chart` / `.history-trend-chart` 的固定 `min-height`，與「上一輪」已經移除，這次完全不動 CSS，繼續保留移除狀態。

本次只回復 JS 的寬度計算邏輯。SVG 用 `width:100%; height:auto`（CSS 既有規則）搭配固定的內部 viewBox 比例，瀏覽器會自動等比例縮放整個 SVG（含文字）去貼合容器寬度，文字之間的「相對比例」維持不變，不會重疊；容器高度也會跟著等比縮小，因為沒有 `min-height` 卡住，所以不會留白。

## 4. 不得進行的修改

- 不得修改 CSS（`.dist-chart`、`.history-trend-chart` 的 `min-height` 移除狀態必須維持不動，不要加回去）。
- 不得修改上一輪「歷史趨勢圖視覺優化」新增的邏輯（`findPeak`、`peakMarker`、`areaPath`、漸層 `<linearGradient>`）。
- 不得修改其他任何函式或檔案。
- **不要再嘗試把寬度計算改成跟隨 `measuredWidth` 縮放** — 這正是本次要修復的回歸問題的根源，未來如果要再優化圖表寬度邏輯，必須同時驗證手機直向下文字是否重疊，不能只看是否留白。

## 5. 驗證方式

1. 啟動本地 server：`node server.js`，開啟 `http://localhost:3000`，登入後檢視「投資分布圖」與「歷史報酬率趨勢」卡片。
2. 用瀏覽器 DevTools 切換成手機尺寸（375px 寬），確認：
   - 「投資分布圖」X 軸的分類名稱（台股ETF、台股個股...）彼此不重疊，可清楚辨識。
   - 漲跌幅標籤（▲/▼ 百分比）不重疊。
   - 「歷史報酬率趨勢」X 軸日期標籤不重疊。
   - 兩張圖表下方都沒有恢復出現大片空白（確認沒有讓 UI-1 復發）。
3. 切回桌面寬螢幕尺寸，確認顯示效果與優化後版本一致（無 regression）。
4. 檢查瀏覽器 console 沒有新增的 JS 錯誤。

## 6. 完成後

請將 diff 回報給 Claude Code 進行 Step 5 review。
