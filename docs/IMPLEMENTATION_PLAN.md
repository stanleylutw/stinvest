# IMPLEMENTATION_PLAN — 選項列窄螢幕單行 + 趨勢圖右側留白

Last updated: 2026-06-30 02:30:00 [Claude]

## Branch

Before starting implementation, create and switch to the new branch:

```
git checkout -b polish_history_chart_layout
```

Base branch: `main`

---

## 1. 背景

兩個獨立問題，都在「歷史報酬率趨勢」卡片：

**問題 A：選項列窄螢幕仍然換行**
上次（branch `fix_history_tools_wrap`）已修正「label 跟 select 分開換行」的醜陋斷裂，但手機窄螢幕下，「範圍」「Y1」「Y2」三組加起來的寬度仍然超過容器可用寬度，所以還是會換成兩行（只是現在換行换得比較整齊）。

**問題 B：折線圖右側留白過大**
圖表的右側 margin（`m.r`）固定是 74px，這是為了預留「Y2 座標軸文字」的空間。但當使用者沒有選 Y2（`y2Key === "none"`，畫面上 Y2 顯示「無」）時，這 74px 完全沒有文字要畫，變成一塊純空白，導致折線圖看起來明顯沒有貼齊右邊界，視覺上很奇怪。

## 2. 修改範圍（僅限 `index.html`，以下兩處，不得修改其他程式碼）

### 2.1 問題 A：窄螢幕 media query，讓選項列縮小到能塞進一行

在 `.history-tool-group` 規則（[index.html:1030-1035](index.html:1030) 附近，上次 `fix_history_tools_wrap` 新增的）之後，新增一個 media query：

```css
@media (max-width: 480px) {
  .history-tools select {
    width: 76px;
  }
  .history-tools {
    gap: 0.3rem;
  }
  .history-tool-group {
    gap: 0.2rem;
    font-size: 0.82rem;
  }
}
```

數值說明：
- `select` 寬度從 92px 縮到 76px（仍要能完整顯示「含息報酬率」5 個字，若實測會截斷，可微調到 80px，但不要超過 84px，否則塞不進一行）。
- `.history-tools` 整體的 gap 縮小，減少組與組之間的間距。
- `.history-tool-group` 內部 label 與 select 的間距也稍微縮小，字級略降一點（`0.82rem`），讓「範圍」「Y1」「Y2」三組文字都更省空間。

斷點 `480px` 是建議值，涵蓋大多數手機直向寬度（375~430px 左右），不需要做更複雜的多階斷點。

**驗證標準**：在 375px 寬度下，「範圍 [選單] Y1 [選單] Y2 [選單]」必須能在一行內完整顯示，不換行。如果加上以上數值仍然換行，可以再小幅調低 `select` 寬度（最低不要低於 68px，避免選項文字被裁切），但不要拿掉 label 文字或刪除任何既有元素。

### 2.2 問題 B：折線圖右側 margin 依 Y2 是否顯示動態調整

找到 `renderHistoryTrendChart` 函式內，目前的程式碼順序大致是：

```js
const w = Math.max(760, measuredWidth);
const h = Math.min(460, Math.max(300, Math.round(w * 0.28)));
const m = { l: 74, r: 74, t: 16, b: 44 };
const pw = w - m.l - m.r;
const ph = h - m.t - m.b;
const n = valid.length;
const showY1 = y1Key !== "none";
const showY2 = y2Key !== "none";
```

**問題**：`m` 在 `showY2` 被算出來「之前」就先定義了，所以沒辦法依照 `showY2` 決定 `m.r`。

**修改方式**：把 `showY1` / `showY2` 的計算，搬到 `m` 定義「之前」，然後讓 `m.r` 依 `showY2` 決定：

```js
const w = Math.max(760, measuredWidth);
const h = Math.min(460, Math.max(300, Math.round(w * 0.28)));
const n = valid.length;
const showY1 = y1Key !== "none";
const showY2 = y2Key !== "none";
const m = { l: 74, r: showY2 ? 74 : 20, t: 16, b: 44 };
const pw = w - m.l - m.r;
const ph = h - m.t - m.b;
```

數值說明：
- `showY2` 為 `true` 時，維持原本的 74px（要預留 Y2 座標軸數字與圖例文字空間）。
- `showY2` 為 `false` 時，縮到 20px（只留一點點呼吸空間，不要完全是 0，避免折線/資料點貼到邊界被裁切）。

**注意**：`n` 這行原本在 `showY1`/`showY2` 之後，搬動時保持它在 `pw`/`ph` 計算之前即可（它沒有依賴 `m`），不要把計算順序搞亂導致其他變數（`pw`、`ph`、`xAt`、`yAt1`、`yAt2`）拿到錯誤的 `m` 值。

## 3. 不得進行的修改

- 不得修改 `renderDistribution`（分布圖）或其他函式。
- 不得修改 `m.l`（左側 margin，與 Y1 座標軸有關，必須保留）、`m.t`、`m.b`。
- 不得修改 `findPeak`、`peakMarker`、`areaPath`、`historyAreaGradient` 等既有邏輯。
- 不得新增外部套件依賴。
- 2.1 的 media query 數值若實測需要微調，幅度限制如上述說明（select 寬度不低於 68px）。

## 4. 驗證方式

1. 啟動本地 server：`node server.js`，開啟 `http://localhost:3000`，登入後檢視「歷史報酬率趨勢」卡片。
2. 用瀏覽器 DevTools 切換到 375px 寬度：
   - 確認「範圍／Y1／Y2」三組選項在**一行內**顯示完整，不換行。
   - 確認 Y2 維持「無」時，折線圖右側不再有明顯大片空白，線條／資料點更貼近圖表右邊界。
3. 把 Y2 切換成有值的選項（例如「現值」），確認：
   - 右側 margin 恢復原本寬度，Y2 座標軸數字與右上角圖例文字正常顯示，沒有被裁切或重疊。
4. 切回桌面寬螢幕尺寸，確認原本排列與圖表比例沒有被破壞（無 regression）。
5. 檢查瀏覽器 console 沒有新增的 JS 錯誤。

## 5. 完成後

請將 diff 回報給 Claude Code 進行 Step 5 review。記得依照 comm.md 規則，輸出可複製貼上的完成摘要。
