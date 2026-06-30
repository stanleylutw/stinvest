# IMPLEMENTATION_PLAN — 修正趨勢圖日期標籤重疊 + Y2 開啟時右側留白過多

Last updated: 2026-06-30 03:30:00 [Claude]

## Branch

Before starting implementation, create and switch to the new branch:

```
git checkout -b fix_history_chart_label_gap
```

Base branch: `main`

---

## 1. 背景

兩個獨立問題，都在 `renderHistoryTrendChart` 函式內：

**問題 A：X 軸日期標籤在圖表右側重疊**

[index.html:2194-2198](index.html:2194)：

```js
const xStep = Math.max(1, Math.ceil(n / 8));
const xLabels = valid.map((p, i) => {
  if (i % xStep !== 0 && i !== n - 1) return "";
  return `<text x="${xAt(i)}" ...>${p.d}</text>`;
});
```

邏輯是「每隔 `xStep` 個點畫一個日期標籤，且最後一個點一定要畫」。當資料點數量 `n` 不能被 `xStep` 整除時，「規律該畫的最後一個標籤」跟「強制要畫的最後一點」可能只差 1~2 個索引，兩個日期文字的 X 座標太接近，畫面上看起來像疊在一起的亂碼（例如 `2026/06/27` 跟 `2026/06/30` 疊成 `20026/06/06/30`）。

**問題 B：Y2 開啟時，圖表右側跟卡片邊框之間留白過多**

[index.html:2190](index.html:2190)：

```js
<text x="${w - m.r + 10}" y="${y + 4}" text-anchor="start" font-size="11" fill="#4b5563">${showY2 ? formatAxisValue(v2, y2Def.axis) : ""}</text>
```

Y2 座標軸數字用 `text-anchor="start"`，文字從 `w - m.r + 10` 這個位置「往右延伸」。但右邊界（margin 結束的地方）是 `w`，數字文字（例如「3,405」這種 5 字元）通常不會剛好填滿到 `w`，中間會留下一段沒被文字佔用、但也不是繪圖區的「死空間」，加上卡片本身的 padding，整體看起來右側留白特別多。

## 2. 修改範圍（僅限 `index.html`，函式 `renderHistoryTrendChart`，以下兩處，不得修改其他函式或檔案）

### 2.1 問題 A：避免最後兩個日期標籤太接近而重疊

找到：

```js
const xStep = Math.max(1, Math.ceil(n / 8));
const xLabels = valid.map((p, i) => {
  if (i % xStep !== 0 && i !== n - 1) return "";
  return `<text x="${xAt(i)}" y="${m.t + ph + 22}" text-anchor="middle" font-size="11" fill="#334155">${p.d}</text>`;
}).join("");
```

改成：

```js
const xStep = Math.max(1, Math.ceil(n / 8));
const xLabelIndexes = new Set();
for (let i = 0; i < n; i += xStep) xLabelIndexes.add(i);
xLabelIndexes.add(n - 1);
const xLabelSorted = [...xLabelIndexes].sort((a, b) => a - b);
if (xLabelSorted.length >= 2) {
  const last = xLabelSorted[xLabelSorted.length - 1];
  const secondLast = xLabelSorted[xLabelSorted.length - 2];
  if (last - secondLast < xStep / 2) {
    xLabelIndexes.delete(secondLast);
  }
}
const xLabels = valid.map((p, i) => {
  if (!xLabelIndexes.has(i)) return "";
  return `<text x="${xAt(i)}" y="${m.t + ph + 22}" text-anchor="middle" font-size="11" fill="#334155">${p.d}</text>`;
}).join("");
```

邏輯：先算出「規律間隔該畫的所有索引」+「最後一個索引（一定要畫）」，如果規律間隔裡最後一個跟強制最後一個距離小於 `xStep` 的一半（太近），就把規律間隔裡那個多餘的去掉，只留最後一個。其餘 `xAt`、`m.t`、`ph` 等既有計算完全不動。

### 2.2 問題 B：Y2 座標軸數字改成貼齊右邊界，並縮小右側留白

找到：

```js
<text x="${w - m.r + 10}" y="${y + 4}" text-anchor="start" font-size="11" fill="#4b5563">${showY2 ? formatAxisValue(v2, y2Def.axis) : ""}</text>
```

改成（`text-anchor` 從 `start` 改為 `end`，`x` 改為貼齊 `w` 邊界）：

```js
<text x="${w - 4}" y="${y + 4}" text-anchor="end" font-size="11" fill="#4b5563">${showY2 ? formatAxisValue(v2, y2Def.axis) : ""}</text>
```

同時，因為文字現在貼齊右邊界、不再需要原本「往右延伸」預留的緩衝空間，把 `m.r` 在 `showY2` 為 `true` 時的數值，從 `74` 縮小到 `56`：

找到：

```js
const m = { l: 74, r: showY2 ? 74 : 20, t: 16, b: 44 };
```

改成：

```js
const m = { l: 74, r: showY2 ? 56 : 20, t: 16, b: 44 };
```

**同時要檢查**：右上角的 Y2 圖例文字（[index.html:2203](index.html:2203) 附近，`formatMetricLabel(y2Def)` 那一行，`text-anchor="end"` 且 `x="${w - m.r}"`）在 `m.r` 縮小後，文字會不會跟座標軸數字重疊。如果發現有重疊風險，把這個圖例文字的 `x` 改成 `w - 4`、`text-anchor` 保持 `end` 即可（跟座標軸數字共用同一個右邊界基準），不要為了避開重疊而新增複雜的避讓邏輯。

## 3. 不得進行的修改

- 不得修改 `renderDistribution`（分布圖）或其他函式。
- 不得修改 `m.l`、`m.t`、`m.b`，以及 `showY2` 為 `false` 時的 `m.r`（維持 `20`）。
- 不得修改 `findPeak`、`peakMarker`、`areaPath`、`historyAreaGradient`、`xAt`、`yAt1`、`yAt2` 等既有計算邏輯。
- 不得修改 [2.1 節 fix_history_tools_wrap / polish_history_chart_layout] 已經完成的選項列換行邏輯（CSS media query 部分）。
- `m.r = 56` 是建議值，如果實測後發現 5~6 位數字（例如 `12,345`）被裁切，可以微調到最多 `64`，但不要超過原本的 `74`，否則就失去這次優化的意義。

## 4. 驗證方式

1. 啟動本地 server：`node server.js`，開啟 `http://localhost:3000`，登入後檢視「歷史報酬率趨勢」卡片。
2. 把「範圍」切到資料點數量較少的選項（例如「月」或「季」），確認：
   - X 軸右側不再出現日期文字重疊、亂碼的狀況。
   - 各日期標籤之間間距合理，可清楚辨識。
3. 把 Y2 切到一個有值的選項（例如「成本」），確認：
   - 圖表右側跟卡片邊框之間的留白明顯變小。
   - Y2 座標軸數字（例如 `3,405`）完整顯示，沒有被裁切。
   - 右上角 Y2 圖例文字沒有跟座標軸數字重疊。
4. 把 Y2 切回「無」，確認 `showY2=false` 時的版面（留白較窄的那個狀態）沒有被這次改動影響。
5. 切回桌面寬螢幕尺寸，確認顯示效果合理，無明顯 regression。
6. 檢查瀏覽器 console 沒有新增的 JS 錯誤。

## 5. 完成後

依照 comm.md 最新規則，把完成摘要寫入 `docs/CODEX_RESULT.md`（覆寫，不要累加），不需要在聊天視窗整段貼出摘要全文，跟使用者說一句已完成即可。
