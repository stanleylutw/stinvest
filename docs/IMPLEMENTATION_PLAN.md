# 儀表板比較基準與圖表修正實作計畫 v1.0

Last updated: 2026-09-26 23:48:26 [Codex]

## Revision History

| Version | Date Time | Summary | Who | Branch |
|---|---|---|---|---|
| v1.0 | 2026-09-26 23:48:26 | 修正 KPI 比較基準、負報酬長條與歷史圖標籤邊界 | Codex | `fix_dashboard_logic_and_charts` |

## Branch

本階段已建立並切換至：

```bash
git checkout -b fix_dashboard_logic_and_charts
```

Parent branch：`fix_atomic_portfolio_sync`

本 branch 為依序處理審查問題的 stacked branch；需先完成前兩階段再單獨 review、commit，尚不合併至 `main`。

## 目標

修正儀表板三個前端邏輯／顯示問題：

1. KPI 比較基準不應因連續兩日總市值相同而跳過最近日期。
2. 投資分布圖應顯示負報酬率，不可將負值壓成 0%。
3. 歷史趨勢圖最後兩個日期標籤在剛好落於臨界間距時也應避免重疊。

## 修改範圍

### `index.html`

1. `findBaselineSnapshot()` 改以 `history.daily` 的有效每日快照判斷：
   - 若最新每日快照的總市值等於目前總市值，回傳前一筆有效每日快照。
   - 若最新每日快照尚未反映目前總市值，回傳最新有效每日快照。
   - 不再用「一路尋找不同市值」作為前一期判斷，確保平盤時顯示 0 差異。
2. `renderDistribution()` 建立同時涵蓋正負值的 Y 軸 domain：
   - Y 軸 tick 可包含負百分比。
   - 0% 線作為長條基準。
   - 正值向上、負值向下繪製，標籤放在各自長條端點外側。
   - 保留既有寬度、響應式與趨勢文字配置。
3. 歷史趨勢圖 X 軸最後標籤的近距判斷由 `< xStep / 2` 改為 `<= xStep / 2`。

### `docs/CODEX_RESULT.md`

覆寫為本階段實作與實際驗證摘要。

## 不在範圍內

- 不修改 `server.js`、Supabase schema、migration 或 API contract。
- 不調整圖表既有最小寬度與橫向捲動策略。
- 不處理審查報告中已由前兩階段完成的 OAuth、同步原子性、token 權限或 `#N/A` 快取問題。
- 不合併至 `main`，不 push。

## 驗證

1. 執行 `git diff --check`。
2. 以 Node 編譯 `index.html` 內 inline script，確認無 JavaScript 語法錯誤。
3. 以隔離測試覆蓋 KPI 比較基準：最新值相同、連續平盤、最新值尚未同步、無有效歷史資料。
4. 以隔離測試覆蓋分布圖 scale／geometry：全正值、含負值、負值長條向下及 0% 基準。
5. 啟動本機 server，檢查 `/`、`/health` 與靜態檔案 allowlist。
6. 記錄因登入與真實資料限制而無法完成的瀏覽器目視驗證。
