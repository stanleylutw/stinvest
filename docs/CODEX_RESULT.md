English correction: `Please proceed with the next branch.`

中文主要回覆：已依照 `docs/IMPLEMENTATION_PLAN.md` 完成第三階段實作，並建立／切換至 stacked branch `fix_dashboard_logic_and_charts`。Parent branch 為 `fix_atomic_portfolio_sync`，commit `7285396`。

修改範圍：
- `docs/IMPLEMENTATION_PLAN.md`：覆寫為儀表板比較基準與圖表修正計畫，記錄 branch 相依、限定範圍與驗證方式。
- `index.html`：`findBaselineSnapshot()` 改用 `history.daily` 的有效每日快照；若最新快照已等於目前總市值就取前一日，若尚未反映目前值就取最新一日，不再跳過連續平盤日期。
- `index.html`：新增分布圖正負 Y 軸 scale 與長條 geometry；Y 軸 tick 可包含負值，長條以 0% 為基準，負報酬率向下繪製並將數值標籤放在負長條端點下方。
- `index.html`：歷史趨勢圖最後兩個 X 軸日期標籤的邊界條件改為 `<= xStep / 2`，剛好等於臨界間距時也會移除近重複標籤。
- `docs/CODEX_RESULT.md`：覆寫為本階段實作結果。

驗證：
- `git diff --check`：通過。
- `index.html` inline script 編譯：通過，共編譯 1 個 inline script。
- KPI baseline 隔離測試：5 組通過，涵蓋最新值相同、連續平盤、最新歷史值不同、無有效值與僅有目前快照。
- 分布圖 scale／geometry 隔離測試：4 組通過，確認全正值 domain、負值 tick、負長條自 0% 向下與正長條向上。
- 歷史圖 X 軸臨界間距測試：通過。
- `npm start`：成功，server 啟動於 `http://localhost:3000`；測試完成後已正常停止。
- HTTP smoke test：`/` 回 `200`、`/health` 回 `200`、`/server.js` 回 `404`。

限制／未能驗證的部分：
- 本機沒有使用者的 Supabase 登入 session 與真實投資資料，因此無法在登入後畫面目視確認負報酬長條；計算函式已用隔離案例驗證。
- 本階段沒有修改後端、Supabase schema、migration 或 API contract，不需要執行新 SQL。
- 尚未 commit、merge 或 push；需先由 reviewer 檢查此 stacked branch。

工作區狀態：
- branch：`fix_dashboard_logic_and_charts`
- parent commit：`7285396 fix: make portfolio sync atomic`
- 已修改：`index.html`、`docs/IMPLEMENTATION_PLAN.md`、`docs/CODEX_RESULT.md`
- 未追蹤且未加入：`.DS_Store`、`stinvest_logo1.original.png`
- 未修改 plan 範圍外的檔案。
