# ST投資總表 — Product & Architecture Plan

Last updated: 2026-06-30 00:40:00 [Claude]

## Revision History

| Version | Date Time | Summary | Who | Branch |
|---|---|---|---|---|
| v1.0 | 2026-06-30 00:00:00 | Initial plan created from codebase scan; documents current architecture and known performance issues | Claude | N/A |
| v1.1 | 2026-06-30 00:10:00 | Fixed mobile-portrait blank space below history trend chart and distribution chart (CSS min-height conflicting with auto-scaled SVG height) | Claude | fix_mobile_chart_blank_space |
| v1.2 | 2026-06-30 00:20:00 | Polished history trend chart: removed per-point dots, added peak-value marker, added Y1 gradient area fill | Claude | polish_history_trend_chart |
| v1.3 | 2026-06-30 00:40:00 | Fixed regression from v1.1: mobile-portrait chart labels (x-axis categories/dates) were overlapping because chart width followed actual narrow viewport instead of a fixed internal resolution. Reverted to forced minimum width while keeping the min-height CSS fix | Claude | fix_mobile_chart_label_overlap |

---

## 1. 專案目標（WHY）

ST投資總表是一個個人投資組合追蹤儀表板，讓使用者透過 Google Sheets 記錄持股，並在網頁上即時檢視：
- 持倉明細與市值
- 資產分布
- 歷史趨勢

目標是讓使用者不需要打開 Google Sheets，就能用更直覺的視覺化方式檢視投資狀況，同時保留 Google Sheets 作為資料輸入介面（不需要重新開發記帳功能）。

## 2. 系統架構（WHAT）

```
Google Sheets（資料來源，使用者手動記帳）
        ↓ Google Sheets API（OAuth 2.0, read-only）
server.js（Express 後端）
  ├── Google OAuth 認證 + token 管理
  ├── Supabase 使用者認證整合
  ├── 雙模式同步引擎（fast / full）
  └── REST API
        ↓
Supabase PostgreSQL（快取層 + 使用者資料）
  ├── user_sheets          — 使用者綁定的 Google Sheet
  ├── sync_logs            — 同步紀錄 + 完整資料快照（payload_json）
  ├── portfolio_items      — 解析後的持倉明細
  ├── user_settings        — 使用者偏好（如金額遮罩）
  └── user_google_tokens   — Google OAuth refresh token
        ↓
index.html（前端 SPA，純 Vanilla JS）
  ├── 概覽 KPI 卡片
  ├── 持倉明細表格
  ├── 資產分布圖
  ├── 歷史趨勢圖
  └── 設定面板（綁定 / 同步 / 隱藏金額）
```

### 2.1 技術棧

| 層級 | 技術 |
|---|---|
| 後端 | Node.js (ES Modules) + Express.js |
| 認證 | Supabase Auth + Google OAuth 2.0 |
| 資料來源 | Google Sheets API v4（唯讀） |
| 資料庫 | Supabase PostgreSQL（含 RLS） |
| 前端 | 原生 HTML + CSS + Vanilla JS（單頁應用，無框架） |
| 部署 | GitHub Pages（前端）+ 雲端 Node 服務（後端） |

### 2.2 主要檔案

| 檔案 | 用途 |
|---|---|
| `server.js` | 後端主程式，OAuth、Sheets 讀取、Supabase 整合、同步引擎 |
| `index.html` | 前端 SPA，含 inline CSS/JS |
| `supabase/schema.sql` | 資料庫 schema 定義 |
| `supabase/migration_add_sync_cache.sql` | 快取相關 migration |

### 2.3 核心資料流：同步引擎

雙模式同步：
- **FAST**：只拉取 2 個 sheet range（持倉 + 分布圖），節省 API 呼叫
- **FULL**：拉取 3 個 range（含歷史紀錄 `09_歷史紀錄`）

歷史資料有 30 分鐘冷卻窗口，避免重複刷新造成不必要的 Google API 呼叫。

### 2.4 認證流程（三條路徑）

1. **Supabase 登入**（主要路徑）：使用者透過 Supabase Auth 登入 → 取得 Bearer Token → 綁定 Google Sheet
2. **Google OAuth 直接登入**（legacy）：後端發放 API Token，存於 URL hash 或 localStorage
3. **本機 Session Cookie**（開發模式）

## 3. 已知問題與待辦（Known Issues）

以下問題已於 2026-06-30 完成分析（詳見對話紀錄），尚未實作修復：

### 3.1 頁面載入效能問題

| 編號 | 問題 | 位置 | 嚴重度 |
|---|---|---|---|
| PERF-1 | Supabase CDN script 同步阻塞渲染，無 `defer` | `index.html:1163` | 高 |
| PERF-2 | `ensureSupabaseAuth` 中 `loadLinkedSheet` 與 `loadCloudSettings` 序列執行，本可並行 | `index.html:3134-3137` | 高 |
| PERF-3 | `getSession()` 被重複呼叫兩次（`ensureSupabaseAuth` 與 `loadData` 內） | `index.html:2593`, `index.html:3275` | 中 |
| PERF-4 | 每次開頁都強制觸發背景同步（`withSync: true`），即使快取仍新鮮 | `index.html:3514` | 中 |
| PERF-5 | 後端 `/api/portfolio-cached` 兩次 Supabase 查詢序列執行（`user_sheets` → `sync_logs`） | `server.js:713-726` | 低 |

修復方案已整理為 Codex prompt（見對話紀錄），尚未建立對應的 `docs/IMPLEMENTATION_PLAN.md`。

### 3.2 手機版面問題（已修復）

| 編號 | 問題 | 位置 | 狀態 |
|---|---|---|---|
| UI-1 | 手機直向時，「歷史報酬率趨勢」與「投資分布圖」卡片，SVG 圖表下方出現大片空白；根因為 CSS `min-height` 與依容器寬度等比縮放後的 SVG 實際高度不匹配 | `index.html` `.dist-chart` / `.history-trend-chart` / `renderHistoryTrendChart` / `renderDistribution` | ✅ 已修復（branch `fix_mobile_chart_blank_space`） |
| UI-2 | 歷史趨勢圖沿途資料點過多，視覺雜亂；缺乏 area chart 漸層填色，不夠專業 | `index.html` `renderHistoryTrendChart` | ✅ 已修復：移除沿途圓點，只在數值最高點畫 marker，Y1 加漸層填色（branch `polish_history_trend_chart`） |
| UI-3 | （UI-1 修復引入的回歸）手機直向時，圖表寬度改用實際容器寬度計算，導致 SVG 內部座標系統縮小，但文字 `font-size` 為固定絕對值，造成 X 軸分類名稱、日期標籤、漲跌幅標籤全部重疊 | `index.html` `renderHistoryTrendChart` / `renderDistribution` | ✅ 已修復：寬度計算改回強制最小值 `Math.max(N, measuredWidth)`，同時保留 UI-1 的 CSS `min-height` 移除（branch `fix_mobile_chart_label_overlap`） |

## 4. 待確認事項（需使用者澄清）

- 後端目前部署於哪個服務（Render / Railway / 其他）？是否為免費方案（會有冷啟動問題）？
- 是否有自動化測試？目前掃描未發現測試腳本。
- `_supabase` 是否為目前唯一的開發分支？未來是否會 merge 回 `main`？

## 5. 下一步

依 `comm.md` 流程，下一步為 Step 3：針對 3.1 節的效能問題，產出 `docs/IMPLEMENTATION_PLAN.md`，包含：
- Branch 建議（如 `perf_parallel_auth_load`）
- 針對 PERF-1 ~ PERF-5 的具體修改指引
- 驗證方式（本地啟動 + console/log 檢查）
