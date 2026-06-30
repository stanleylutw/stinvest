# IMPLEMENTATION_PLAN — 修正手機直向圖表下方留白問題

Last updated: 2026-06-30 00:00:00 [Claude]

## Branch

Before starting implementation, create and switch to the new branch:

```
git checkout -b fix_mobile_chart_blank_space
```

Base branch: `_supabase`

---

## 1. 問題描述

手機「直向」檢視時，「歷史報酬率趨勢」與「投資分布圖」兩張卡片，圖表（SVG）下方出現大片空白。橫向（桌面寬螢幕）顯示正常，無此問題。

## 2. 根因分析

兩個圖表的 SVG 尺寸計算，都把寬度強制鎖在一個「最小寬螢幕寬度」，導致 viewBox 長寬比固定為寬螢幕比例（約 2.5:1）。但 CSS 容器又同時設了固定 `min-height`。手機直向時容器寬度變窄，SVG 用 `width:100%; height:auto` 依比例縮小後的實際高度，遠小於容器的 `min-height`，差額就變成圖表下方的空白。

## 3. 修改範圍（僅限以下檔案與區塊，不得修改其他無關程式碼）

檔案：`index.html`

### 3.1 CSS — 移除/調整固定 min-height

**位置 A**：`.history-trend-chart`（約在 1058-1062 行附近，以實際文字內容比對，不要依賴行號）

```css
.history-trend-chart {
  width: 100%;
  min-height: 260px;
  overflow: hidden;
}
```

→ 移除 `min-height: 260px;` 這一行（其餘屬性保留）。

**位置 B**：`.dist-chart`（約在 1000-1004 行附近）

```css
.dist-chart {
  width: 100%;
  min-height: 220px;
  overflow: hidden;
}
```

→ 移除 `min-height: 220px;` 這一行（其餘屬性保留）。

### 3.2 JS — 圖表寬度改用實際量測寬度，不強制鎖最小寬螢幕寬度

**位置 C**：函式 `renderHistoryTrendChart`，找到這一行：

```js
const w = Math.max(760, measuredWidth);
```

→ 改為：

```js
const w = measuredWidth || 760;
```

（意義：優先使用容器實際量到的寬度；只有量不到時 [`measuredWidth` 為 0 或 falsy] 才退回 760 當保底值。不可改變後面 `h`、`m`、`pw`、`ph` 等任何其他計算邏輯。）

**位置 D**：函式 `renderDistribution`，找到這一行：

```js
const chartW = Math.max(720, measuredWidth);
```

→ 改為：

```js
const chartW = measuredWidth || 720;
```

（同樣邏輯，不可更動其餘變數計算。）

## 4. 不得進行的修改

- 不得更動其他 CSS class（例如 `.dist-chart-wrap`、`.history-trend-wrap` 等）。
- 不得更動圖表的繪製邏輯（座標計算、bar/line/grid 繪製、margin 設定）。
- 不得新增任何套件依賴。
- 不得修改桌面（寬螢幕）版面的既有顯示效果 — 因為 `Math.max(760, measuredWidth)` 在桌面寬螢幕時，`measuredWidth` 本身通常已經 > 760，所以改成 `measuredWidth || 760` 在桌面情境下行為應該完全相同，只在手機窄螢幕時才會有差異。

## 5. 驗證方式

1. 啟動本地 server：`node server.js`，開啟 `http://localhost:3000`。
2. 用瀏覽器 DevTools 切換成手機尺寸（例如 iPhone 12/375px 寬），檢查：
   - 「歷史報酬率趨勢」卡片圖表下方不再有大片空白。
   - 「投資分布圖」卡片圖表下方不再有大片空白。
3. 切回桌面寬螢幕尺寸，確認兩張圖表顯示效果與修改前一致（無 regression）。
4. 檢查瀏覽器 console 沒有新增的 JS 錯誤。

## 6. 完成後

請將 diff 回報給 Claude Code 進行 Step 5 review。
