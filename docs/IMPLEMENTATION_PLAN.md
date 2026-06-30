# IMPLEMENTATION_PLAN — 修正歷史趨勢圖選項列窄螢幕斷行

Last updated: 2026-06-30 02:00:00 [Claude]

## Branch

Before starting implementation, create and switch to the new branch:

```
git checkout -b fix_history_tools_wrap
```

Base branch: `main`

---

## 1. 問題描述

「歷史報酬率趨勢」卡片上方的選項列（範圍／Y1／Y2）在窄螢幕時換行很奇怪：「Y2」這個文字標籤留在第一行，但它對應的 `<select>` 卻被擠到第二行單獨一行，視覺上像是斷掉、不成一組。

## 2. 根因

檔案：`index.html`

1. `.history-tools select`（約在 1022-1029 行附近）沒有設定寬度，`<select>` 會被瀏覽器撐到「足以容納最長選項文字」的寬度（`HISTORY_METRIC_OPTIONS` 裡最長的是「含息報酬率」5 個字），導致即使目前選的是「無」這種短文字，選單本體仍然很寬。
2. `.history-tools`（約在 1011-1020 行附近）使用 `flex-wrap: wrap`，但 `<label for="histY2Select">Y2</label>` 與 `<select id="histY2Select">` 是兩個獨立的 flex 子元素（[index.html:1384-1385](index.html:1384)），容器寬度不夠時兩者各自獨立換行，造成 label 留在上一行、select 被擠到下一行的斷裂感。

## 3. 修改範圍（僅限 `index.html`，以下兩處，不得修改其他程式碼）

### 3.1 CSS — 限制 select 寬度

找到 `.history-tools select` 規則：

```css
.history-tools select {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 0.3rem 0.45rem;
  background: #fff;
  color: var(--ink);
  font: inherit;
}
```

新增一行固定寬度（其餘屬性不動）：

```css
.history-tools select {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 0.3rem 0.45rem;
  background: #fff;
  color: var(--ink);
  font: inherit;
  width: 92px;
}
```

`width: 92px` 是建議值，要能完整顯示「含息報酬率」這種 5 字選項不被截斷即可（可以用瀏覽器實際測試微調，但不要超過 110px，避免又佔太多空間）。

### 3.2 HTML — 把每組 label + select 包成一個不可拆開的單位

找到（[index.html:1382-1385](index.html:1382)）：

```html
<label for="histY1Select">Y1</label>
<select id="histY1Select"></select>
<label for="histY2Select">Y2</label>
<select id="histY2Select"></select>
```

改成（用 `<span>` 把每組包起來，id 與既有 JS 綁定的元素 id 完全不變，只是多包一層容器）：

```html
<span class="history-tool-group">
  <label for="histY1Select">Y1</label>
  <select id="histY1Select"></select>
</span>
<span class="history-tool-group">
  <label for="histY2Select">Y2</label>
  <select id="histY2Select"></select>
</span>
```

同樣的包裝邏輯，也套用到「範圍」那一組（[index.html:1369-1370](index.html:1369)）：

```html
<span class="history-tool-group">
  <label for="histRangeSelect">範圍</label>
  <select id="histRangeSelect">
    <option value="all" selected>全部</option>
    <option value="month">月</option>
    <option value="quarter">季</option>
    <option value="year">年</option>
    <option value="custom">自訂</option>
  </select>
</span>
```

**不要包住** `<span class="history-custom-range is-hidden" id="histCustomRange">`，那是另一個獨立功能（自訂日期區間），保持原樣不動。

### 3.3 CSS — 新增 `.history-tool-group` 樣式

在 `.history-tools select` 規則之後，新增：

```css
.history-tool-group {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  white-space: nowrap;
}
```

這讓每組「label + select」變成一個不可拆開的 flex item，`.history-tools` 的 `flex-wrap: wrap` 換行時，只會整組一起換到下一行，不會切在 label 跟 select 中間。

## 4. 不得進行的修改

- 不得修改任何 JS（`histRangeSelect`、`histY1Select`、`histY2Select` 等變數的查找與事件綁定邏輯完全不動，因為元素 id 沒有改變，只是多包一層 `<span>`）。
- 不得修改 `.history-custom-range` 相關的顯示/隱藏邏輯。
- 不得修改其他卡片（投資分布圖等）的版面。
- `width` 數值若你測試後發現 92px 會截斷文字或太擠，可以微調（建議範圍 84px ~ 110px），但要確保「含息報酬率」完整顯示，不要被裁切。

## 5. 驗證方式

1. 啟動本地 server：`node server.js`，開啟 `http://localhost:3000`，登入後檢視「歷史報酬率趨勢」卡片上方的選項列。
2. 用瀏覽器 DevTools 切換到較窄的寬度（例如 600px、375px），確認：
   - 不會再出現「Y2」文字留在上一行、選單被擠到下一行單獨顯示的狀況。
   - 如果空間不夠真的需要換行，應該是整組「Y2 + 下拉選單」一起換行，視覺上仍然成對。
   - 三個下拉選單（範圍/Y1/Y2）寬度看起來一致、不會異常寬大。
3. 切到桌面寬螢幕尺寸，確認原本一行排列的效果沒有被破壞。
4. 切換 Y1/Y2 下拉選單的選項，確認圖表更新功能正常（沒有因為多包一層 `<span>` 而影響原本的 `addEventListener` 綁定）。
5. 檢查瀏覽器 console 沒有新增的 JS 錯誤。

## 6. 完成後

請將 diff 回報給 Claude Code 進行 Step 5 review。記得依照 comm.md 規則，輸出可複製貼上的完成摘要。
