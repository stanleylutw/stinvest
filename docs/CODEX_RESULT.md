English correction: `Let's do the next branch.` -> `Let's proceed with the next branch.`

中文主要回覆：已依照 `docs/IMPLEMENTATION_PLAN.md` 完成實作，並建立／切換至 stacked branch `v1.0.6_indexeddb_stale_while_revalidate`。Parent branch 為 `v1.0.5_direct_supabase_cache_read`，commit `0cffe14`。

修改範圍：
- `docs/IMPLEMENTATION_PLAN.md`：覆寫為 v1.0.6 IndexedDB stale-while-revalidate 計畫，限定本輪只修改前端快取流程與成果摘要。
- `index.html`：新增 `stinvest_dashboard_cache` IndexedDB 與 `portfolio_cache` object store，以 `userId:sheetId` 隔離快取，保存 dashboard payload、`syncLogId` 與同步時間。
- `index.html`：新增 IndexedDB open／read／write／delete helpers；API 不可用、quota、transaction 或 upgrade 失敗時只記錄 warning，不阻斷既有 Supabase／Render 流程。
- `index.html`：`performLoadData()` 在 Supabase session 與 active Sheet 確認後，先渲染 IndexedDB payload，再以 v1.0.5 direct reader 查詢 Supabase；同一 `syncLogId` 不重繪，新版本才下載、重繪並回寫 IndexedDB。
- `index.html`：雲端 revalidate 失敗時保留已顯示的本機快取並標示確認失敗；雲端明確無 cache 時刪除過期本機資料。
- `index.html`：手動／自動同步直接取得 payload 時同步更新 IndexedDB；登出、解除綁定、切換使用者或 active Sheet 時清除相應快取。
- `index.html`：拆分 dashboard 資料清除與 Sheet 綁定 UI 清除；已綁定但尚無 cloud cache 時保留 active Sheet，讓首次背景同步仍能繼續。
- `docs/CODEX_RESULT.md`：覆寫為本階段實作結果。

驗證：
- `git diff --check`：通過。
- `node --check server.js`：通過。
- `index.html` inline script 編譯：通過。
- fake IndexedDB CRUD／invalidation 隔離測試：7 項通過，涵蓋 open／upgrade、put、get、單筆 delete 與依 user index 清除。
- stale-while-revalidate 隔離測試：4 個情境通過，涵蓋本機後同版雲端不重繪、本機後新版雲端覆蓋並持久化、雲端失敗保留本機畫面，以及 IndexedDB 不可用時正常走 cloud reader。
- invalidation 靜態核對：登出、auth user switch、解除綁定、active Sheet switch 與雲端明確無 cache 均連接至對應 delete helper。
- `npm start`：成功啟動於 `http://localhost:3000`，測試後已停止。
- HTTP smoke test：`/` 回 200、`/health` 回 200、`/server.js` 回 404。

限制／未能驗證的部分：
- 本機沒有真實 Supabase 登入 session，因此未能在實際帳號與 production RLS 下目視量測「IndexedDB 首屏 -> Supabase revalidate」速度。
- IndexedDB 行為以隔離 fake 實作驗證；瀏覽器 smoke test 可開啟登入頁，但未在使用者真實瀏覽器資料庫寫入測試 payload，以免污染個人快取。
- 本輪沒有 Supabase schema／migration 變更，不需要執行新 SQL；v1.0.7 bootstrap RPC/view 尚未實作。
- 尚未 commit、merge、push 或部署，需先 review 此 stacked branch。

工作區狀態：
- branch：`v1.0.6_indexeddb_stale_while_revalidate`
- parent commit：`0cffe14 perf: read portfolio cache directly from Supabase`
- 本輪修改：`index.html`、`docs/IMPLEMENTATION_PLAN.md`、`docs/CODEX_RESULT.md`
- 外部修改、未由本輪 Codex 編輯：`docs/REVIEW_REPORT.md`、`00_investment_dashboard_plan_v1.0.md`（保留原狀，不應誤納入 v1.0.6 commit，除非使用者另行指定）
- 未追蹤且未加入：`.DS_Store`、`stinvest_logo1.original.png`
