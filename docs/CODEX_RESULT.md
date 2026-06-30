English correction: `When finished, write a summary to docs/CODEX_RESULT.md, overwriting the file each time instead of appending.`

中文主要回覆：已依照 docs/IMPLEMENTATION_PLAN.md 完成實作，並建立/切到 branch `fix_history_chart_label_gap`。

修改範圍：
- index.html：在 `renderHistoryTrendChart()` 內把 `showY2=true` 時的右側 margin 從 `74` 縮小為 `56`，`showY2=false` 仍維持 `20`。
- index.html：將 Y2 座標軸數字改為 `x="${w - 4}"`、`text-anchor="end"`，讓數字貼齊 SVG 右側邊界，減少右側死空間。
- index.html：將 X 軸日期標籤改為先建立 `xLabelIndexes`，再強制加入最後一筆；若倒數第二個標籤距離最後一筆小於 `xStep / 2`，會刪除倒數第二個，避免右側日期標籤重疊。
- docs/CODEX_RESULT.md：依 comm.md 規則新增本次 Step 4 完成摘要。

驗證：
- `git diff --check`：通過。
- `node --check server.js`：通過。
- 抽出 `index.html` inline script 到 `/tmp/stinvest-inline.js` 後執行 `node --check /tmp/stinvest-inline.js`：通過。
- `npm start`：成功啟動本地 server，顯示 `Server running on http://localhost:3000`。
- 瀏覽器開啟 `http://localhost:3000`：頁面可載入，確認 `#historyTrendChart` 與 `.history-tools` 存在。
- 瀏覽器 DOM 檢查：確認頁面程式碼包含 `x="${w - 4}" y="${y + 4}" text-anchor="end"` 與 `r: showY2 ? 56 : 20`。
- X 軸標籤索引邏輯用 Node 小案例驗證：`n=17` 時索引為 `[0,3,6,9,12,16]`，會避開過近的倒數第二個標籤。

限制／未能驗證的部分：
- 本機頁面目前是未登入狀態，無法用真實 Google Sheet / Supabase 資料目視檢查完整「歷史報酬率趨勢」圖表。
- 瀏覽器 console 出現 `TypeError: Failed to fetch`，發生於未登入狀態初始化 `loadData()` / `triggerImmediateRefresh()`；本次改動未涉及該資料載入流程，已如實記錄，未判定為本次圖表修改通過項目。
- 未能在本機目視確認 Y2 開啟後的座標軸數字與右上角 Y2 圖例是否完全無重疊；已依 plan 保留右上角 Y2 圖例原本的 `x="${w - m.r}"` 與 `text-anchor="end"`，只修改 Y2 座標軸數字與 margin。

工作區狀態：
- 目前 branch：`fix_history_chart_label_gap`
- 已修改檔案：`index.html`
- 已新增檔案：`docs/CODEX_RESULT.md`
- 既有未提交修改仍存在：`docs/IMPLEMENTATION_PLAN.md`
- 未追蹤檔案仍存在：`.DS_Store`、`comm.md`、`stinvest_logo1.original.png`
