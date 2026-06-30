# IMPLEMENTATION_PLAN — 歷史趨勢圖視覺優化

Last updated: 2026-06-30 00:00:00 [Claude]

## Branch

Before starting implementation, create and switch to the new branch:

```
git checkout -b polish_history_trend_chart
```

Base branch: `_supabase`（請確認已包含先前 `fix_mobile_chart_blank_space` 的 commit）

---

## 1. 背景

「歷史報酬率趨勢」折線圖目前每個資料點都畫一個小圓點，資料量大時看起來雜亂。使用者要求：
1. 拿掉沿途所有的點，只畫純折線。
2. 只在「數值最高的那個點」保留標記（marker + 數值標籤），而不是固定畫最後一點。
3. 整體視覺更專業：折線下方加漸層填色（area chart 效果）。

## 2. 修改範圍（僅限 `index.html`，函式 `renderHistoryTrendChart`，不得修改其他函式或檔案）

### 2.1 移除沿途所有資料點的圓點

找到 `points` 這個 helper function：

```js
const points = (key, yFn, color) => valid.map((p, i) => {
  const v = p[key];
  if (!Number.isFinite(v)) return "";
  return `<circle cx="${xAt(i)}" cy="${yFn(v)}" r="2.8" fill="${color}" />`;
}).join("");
```

以及它在 SVG 模板中的呼叫：

```js
${showY1 ? points("y1", yAt1, "#2563eb") : ""}
${showY2 ? points("y2", yAt2, "#64748b") : ""}
```

→ 整段移除（function 定義 + 兩處呼叫）。不要保留沿途逐點圓點繪製。

### 2.2 找出最高值的點，並只在該點畫 marker + 數值標籤

在 `pathFrom` 定義之後、SVG 模板字串之前，新增一個 helper，找出 Y1 與 Y2 各自的最高值點（peak）：

```js
const findPeak = (key, yFn) => {
  let best = null;
  valid.forEach((p, i) => {
    const v = p[key];
    if (!Number.isFinite(v)) return;
    if (!best || v > best.v) best = { v, i, x: xAt(i), y: yFn(v) };
  });
  return best;
};
const y1Peak = showY1 ? findPeak("y1", yAt1) : null;
const y2Peak = showY2 ? findPeak("y2", yAt2) : null;

const peakMarker = (peak, color, def) => {
  if (!peak) return "";
  return `
    <circle cx="${peak.x}" cy="${peak.y}" r="4" fill="#fff" stroke="${color}" stroke-width="2" />
    <text x="${peak.x}" y="${peak.y - 10}" text-anchor="middle" font-size="11" fill="${color}" font-weight="700">${formatAxisValue(peak.v, def.axis)}</text>
  `;
};
```

注意：
- `formatAxisValue` 與 `def`（`y1Def`/`y2Def`）在這個函式作用域內已存在，直接重用，不要新增重複的格式化邏輯。
- peak marker 的圓點樣式（白底、彩色描邊）刻意與原本沿途的實心小圓點不同，作為「峰值標記」的視覺區隔。

### 2.3 在 SVG 模板中插入 peak marker，並加入折線下方漸層填色

**漸層填色（area chart）**：在 `<svg ...>` 開頭新增 `<defs>` 定義線性漸層，並在折線 `<path>` 之前，新增一個「面積路徑」（折線路徑 + 沿著底部 baseline 封閉），只對 Y1（主要序列，藍色）做漸層填色，Y2 不需要。

封閉面積路徑可以用既有的 `p1` 折線路徑字串組出：

```js
const areaPath = showY1 && p1
  ? `${p1} L ${xAt(valid.length - 1)} ${m.t + ph} L ${xAt(0)} ${m.t + ph} Z`
  : "";
```

SVG 模板調整為（在現有結構基礎上插入，不要重寫整個 SVG 字串）：

```js
historyTrendChart.innerHTML = `
  <svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" xmlns="http://www.w3.org/2000/svg">
    <defs>
      <linearGradient id="historyAreaGradient" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#2563eb" stop-opacity="0.18" />
        <stop offset="100%" stop-color="#2563eb" stop-opacity="0" />
      </linearGradient>
    </defs>
    <rect x="0" y="0" width="${w}" height="${h}" fill="#f7f8fa" />
    ${grid}
    ${areaPath ? `<path d="${areaPath}" fill="url(#historyAreaGradient)" stroke="none" />` : ""}
    ${showY1 ? `<path d="${p1}" fill="none" stroke="#2563eb" stroke-width="2.2" />` : ""}
    ${showY2 ? `<path d="${p2}" fill="none" stroke="#64748b" stroke-width="2.2" />` : ""}
    ${y1Peak ? peakMarker(y1Peak, "#2563eb", y1Def) : ""}
    ${y2Peak ? peakMarker(y2Peak, "#64748b", y2Def) : ""}
    <line x1="${m.l}" y1="${m.t + ph}" x2="${w - m.r}" y2="${m.t + ph}" stroke="#64748b" stroke-width="1.3" />
    ${xLabels}
    ${showY1 ? `<text x="${m.l}" y="${13}" text-anchor="start" font-size="11" fill="#2563eb" font-weight="700">${formatMetricLabel(y1Def)}</text>` : ""}
    ${showY2 ? `<text x="${w - m.r}" y="${13}" text-anchor="end" font-size="11" fill="#64748b" font-weight="700">${formatMetricLabel(y2Def)}</text>` : ""}
  </svg>
`;
```

`<linearGradient>` 的 `id="historyAreaGradient"` 若該 SVG 在同一頁面只會出現一次（目前架構是如此，整頁只有一個 `#historyTrendChart` 容器），可以固定 id，不需要動態產生唯一 id。

### 2.4 圖表副標題/圖例維持不變

`formatMetricLabel(y1Def)` / `formatMetricLabel(y2Def)` 的左上、右上文字標籤邏輯不變，不要修改。

## 3. 不得進行的修改

- 不得修改 `renderDistribution`（分布圖）或其他函式。
- 不得修改 `xAt`、`yAt1`、`yAt2`、`range`、`pathFrom` 既有計算邏輯。
- 不得新增任何外部套件依賴（純手寫 SVG，沿用現有風格）。
- 若 Y1 或 Y2 的 `valid` 資料只有 1 個點，`findPeak` 仍需正常運作（不可拋錯）。
- peak marker 文字標籤若超出圖表上邊界（例如最高點剛好在圖表頂部），可以不處理 clipping，但若有簡單作法（例如 `Math.max(peak.y - 10, m.t + 12)` 限制文字 y 座標下限）可以順手加上，非必須。

## 4. 驗證方式

1. 啟動本地 server：`node server.js`，開啟 `http://localhost:3000`，登入後檢視「歷史報酬率趨勢」卡片。
2. 確認：
   - 折線上不再有沿途密集小圓點。
   - 只有數值最高的那一點有圓點標記 + 數值文字。
   - 折線下方出現淡藍色漸層填色，往下漸淡至透明。
   - 切換 Y2 下拉選單（例如選一個非「無」的序列），確認 Y2 也只在峰值處有標記，且 Y2 不畫漸層填色。
   - 切換「範圍」篩選（例如只看近 3 個月），peak marker 會跟著重新計算到篩選後資料的最高點。
3. 檢查瀏覽器 console 沒有新增的 JS 錯誤。
4. 確認手機直向尺寸下（DevTools 375px 寬）顯示正常，與上次 `fix_mobile_chart_blank_space` 的修復沒有衝突（圖表下方不應該又出現空白）。

## 5. 完成後

請將 diff 回報給 Claude Code 進行 Step 5 review。
