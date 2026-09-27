# 溝通規則

## 回覆規則
1. 第一步：提供使用者英文句子的修正。
2. 第二步：用繁體中文提供主要回覆。
3. 英文修正需短且自然。
4. 繁體中文回覆需清楚，並以行動為主。
5. 技術請求需在相關處提供具體檔案路徑或設定。
6. 所有 Markdown 文件描述應使用繁體中文，但特定技術詞（如 API、Supabase、OAuth）可以保留英文。

## 輸出模板
English correction: `...`

中文主要回覆：...

## 開發快捷指令
1. `#m` = modify，修改目前指定功能或檔案。
2. `#r` = run，啟動本地 server（`node server.js` 或 `npm start`）進行測試。
3. `#t` = test，跑既有測試（若專案有加入測試腳本）。
4. `#mr` = modify + run，修改後啟動本地測試。
5. `#sync` = 同步 Supabase schema（套用 `supabase/schema.sql` 或最新 migration）。

## Plan Markdown 版本管理規則
1. 修改主要 plan 文件時，必須同步更新文件版本號。
2. 版本號格式使用 `vMAJOR.MINOR`，例如 `v1.3`。
3. 一般內容更新時增加 minor version，例如 `v1.3 -> v1.4`。
4. 當 minor version 從 `9` 再往上增加時，進位到下一個 major version，例如 `v1.9 -> v2.0`。
5. 若只是修正 typo、排版或不影響規格的文字，可不升版，但必須在回覆中說明原因。
6. Plan 文件 header 必須包含 `Last updated` 欄位，格式如下：

```text
Last updated: YYYY-MM-DD HH:MM:SS [Who]
```

7. Plan 文件 header 必須包含 `Revision History`，用簡短紀錄追蹤重要修改。
8. Revision History 建議放在文件前段，標題下方或專案摘要後方，格式如下：

```markdown
## Revision History

| Version | Date Time | Summary | Who |
|---|---|---|---|
| v1.4 | 2026-06-30 15:30:00 | Add cache loading optimization plan | Claude |
```

9. Revision summary 應簡短描述「修改了什麼」，不要寫過長的開發細節。
10. 修改 plan 時，應同時檢查文件標題、版本號、`Last updated` 與 `Revision History` 是否一致。
11. `Revision History` 表格必須包含 `Branch` 欄，記錄對應的 working branch：
    - 有對應 code change：填寫 branch name，例如 `v1.1.0_perf_cache_loading`
    - 只是文件修正、無對應 code change：填 `N/A`
    - 格式：`| Version | Date Time | Summary | Who | Branch |`

## App Semantic Version、Branch、Main 與 Tag 規則

### 版本格式與單一顯示來源

1. App release version 一律使用 Semantic Version 格式：`vMAJOR.MINOR.PATCH`，例如 `v1.0.0`、`v1.0.7`、`v1.1.0`。
2. `index.html` 頁尾的 `#versionText` 是使用者看到的 App version，必須顯示完整的 `vX.Y.Z`。
3. 禁止再用 `document.lastModified` 或 `vYYYYMMDD.HHMM` 充當 App release version。
4. 日期、時間、commit SHA 若需要顯示，只能作為獨立的 build metadata；不可取代 `vX.Y.Z`，也不可讓使用者誤認為 release version。
5. 每次修改版本時，只能保留一個明確的版本來源；不得在 HTML、JavaScript 或文件中留下彼此矛盾的 App version。

### Version branch 命名與版本來源

1. 所有會合併至 `main` 的實作 branch，命名格式為：

```text
vMAJOR.MINOR.PATCH_short_topic_in_snake_case
```

2. 範例：
   - `v1.0.7_bootstrap_query_consolidation`
   - `v1.0.8_fix_mobile_chart_labels`
   - `v1.1.0_add_portfolio_alerts`
3. branch 名稱最前面的 `vX.Y.Z` 是該 branch 合併完成後預期顯示的 App version。
4. 同一條 stacked branch 鏈若依序為 `v1.0.1` 到 `v1.0.7`，最終 branch `v1.0.7_*` 合併到 `main` 後，頁面必須顯示 `v1.0.7`。
5. branch 完成 review、準備 commit 前，必須將 `index.html` 的 `#versionText` 更新為該 branch 前綴版本，且版本修改必須包含在該 branch 的 commit 中。
6. 不得只修改 branch 名稱而不更新頁面版本，也不得只更新頁面版本而使用沒有版本前綴的 release branch。

### 合併到 `main` 的版本規則

1. `main` 沒有 tag 指向目前 HEAD 時，頁面版本以「最後一個已合併 version branch 的 `vX.Y.Z`」為準。
2. 合併 `vX.Y.Z_topic` 前，必須確認該 branch 的 `index.html` 已顯示相同的 `vX.Y.Z`，而且修改已 commit；未 commit 的 working-tree 修改不會跟著 branch merge。
3. 合併完成後必須在 `main` 再次確認：

```bash
git branch --show-current
git log -1 --oneline
rg -n 'id="versionText"' index.html
```

4. 若先後合併多個版本 branch，頁面版本只能前進，不得倒退。較舊 branch 在較新版本後補合併時，不得把 `#versionText` 降回較舊版本。
5. stacked branches 合併時，以整條鏈中最高、最後核准的 SemVer 為準；通常只需合併最末 branch，但合併前仍要確認 commit graph 與版本文字一致。
6. merge 完成但版本不一致時，視為 release blocker；在修正並 commit 前不得 push／部署 `main`。

### `main` Tag 優先規則

1. 若 `main` 的目前 HEAD 有合法的 `vX.Y.Z` tag，tag 是該 commit 的權威 App version，頁面必須顯示完全相同的 `vX.Y.Z`。
2. 「tag 在 `main`」是指 tag 精確指向 `main` 的目前 HEAD；只存在於 repo、其他 branch 或非 `main` 歷史中的 tag 不算。
3. 若同一個 `main` commit 有多個合法 SemVer tags，以 SemVer 最高者為準；正常流程應避免同一 commit 出現多個 release tags。
4. Git tag 不會自動修改已提交的靜態 `index.html`。因此正確順序必須是：
   1. 決定 release tag `vX.Y.Z`。
   2. 將 `index.html` 的 `#versionText` 更新成 `vX.Y.Z`。
   3. commit 版本修改，確保 `main` HEAD 已包含正確版本。
   4. 在同一個 commit 建立 annotated tag。
   5. 先 push `main`，再 push 該 tag。
5. 禁止先建立 tag、再另外 commit 頁面版本；這會讓 tag 指向的內容與畫面版本不一致。
6. 已 push 的 tag 原則上不可移動或覆寫。若已發布 tag 與頁面版本不一致，應建立新的 patch version 修正，例如 `v1.0.0` 有誤時發布 `v1.0.1`，不要 force-update 公開 tag。

### Release／Tag 標準流程

```bash
# 1. 確認 version branch 與頁面版本一致，且 working tree 的版本修改已 commit
git switch vX.Y.Z_short_topic
rg -n 'id="versionText"' index.html
git status --short

# 2. 合併最終核准 branch
git switch main
git merge --ff-only vX.Y.Z_short_topic

# 3. 再次確認 main HEAD 與頁面版本
git log -1 --oneline
rg -n 'id="versionText"' index.html

# 4. 建立 annotated tag；tag 必須指向包含同版本頁面的 main HEAD
git tag -a vX.Y.Z -m "Release vX.Y.Z"

# 5. Push main 與單一 release tag
git push origin main
git push origin vX.Y.Z

# 6. 驗證 tag 精確指向 main HEAD
git tag --points-at main
git rev-parse main
git rev-list -n 1 vX.Y.Z
```

### Merge／Release 必查清單

1. branch 名稱是否符合 `vX.Y.Z_short_topic`。
2. `index.html` 的 `#versionText` 是否等於 branch 前綴版本。
3. 版本修改是否已 commit，而不是只存在 working tree。
4. 即將合併的版本是否不低於 `main` 目前版本。
5. 若要建立 tag，tag 名稱是否與 `#versionText` 完全一致。
6. tag 是否建立在包含該版本文字的 `main` HEAD。
7. `main` 與 tag 是否都成功 push，且兩者解析到同一 commit。
8. GitHub Pages／瀏覽器 cache 更新後，線上頁尾是否顯示預期的 `vX.Y.Z`。

## Claude Code / Codex 分工規則

### 角色定義

| 工具 | 角色 | 職責 |
|---|---|---|
| Claude Code | 架構師 / Reviewer / MD 維護者 | 讀 MD、分析 code、產生 plan、review diff、更新文件 |
| Codex | 執行工程師 | 依照 plan 修改前端 / 後端 code，修正 review issue |

### Claude Code 職責

1. 讀 MD、分析現有 code 結構（index.html、server.js、supabase/schema.sql）。
2. 產生 `docs/IMPLEMENTATION_PLAN.md`，作為 Codex 的施工單。
3. 新功能完成後更新 `00_investment_dashboard_plan_vX.X.md`，包含版本號、`Last updated`、`Revision History` 與內容。
4. Review Codex diff，輸出 `docs/REVIEW_REPORT.md`，分類 Critical / Major / Minor issue。
5. **不直接修改 `index.html` / `server.js` 原始碼**，除非使用者明確指示。
6. 產生 implementation plan 時指定本次預期 App version，並確認 branch 前綴符合 `vX.Y.Z`。
7. Review 時核對 branch 前綴、`#versionText` 與預期 tag；任何不一致至少列為 Major issue，release 前視為 blocker。

### Codex 職責

1. 依照 `IMPLEMENTATION_PLAN.md` 修改前端 / 後端 code。
2. 只修改 plan 指定的檔案，不重構無關架構。
3. 不自行更動 Supabase schema 或 API contract，一切以 MD spec 為準。
4. 修正 `REVIEW_REPORT.md` 中的 Critical / Major issue。
5. **不更新 plan MD**，除非極小 typo，且須在 diff 中說明。
6. 依照 plan 將 `index.html` 的 `#versionText` 更新為 branch 的 `vX.Y.Z`，並在完成摘要中列出實際版本。
7. 執行 commit／merge／tag 指令前，重新檢查版本文字已 commit，且不會造成 `main` 版本倒退。

### 標準開發流程

```text
Step 1：討論需求、確認規格                    → Claude Code
Step 2：更新 plan MD                          → Claude Code
Step 3：產生 IMPLEMENTATION_PLAN.md           → Claude Code
        （含 branch 建議，由 Codex 在 Step 4 前建立）
Step 4：建立 branch + 修改 code               → Codex
        （使用標準指令格式，見下方 Step 4 指令規則）
Step 5：Review diff → REVIEW_REPORT.md        → Claude Code
Step 6：修正 Critical / Major issue           → Codex（有問題才執行）
Step 7：同步更新永久文件                      → Claude Code
Step 8：建議 Codex git commit                 → Claude Code 提供指令
```

### 流程分支說明

```text
有 Critical / Major issue：
  Step 4 → Step 5（有問題）
         → Step 6（Codex 修正）
         → Step 5（重新 review，通過後）
         → Step 7（Claude Code 更新文件）
         → Step 8（建議 Codex git commit）

無 Critical / Major issue：
  Step 4 → Step 5（全部通過）
         → Step 7（Claude Code 更新文件）
         → Step 8（建議 Codex git commit）
```

Git commit 永遠在 Step 7 之後執行，確保 commit 同時包含 code 修改與文件更新。

### Step 3 — Branch 建議規則

Claude Code 產生 `IMPLEMENTATION_PLAN.md` 時，**必須在文件開頭加入 `## Branch` section**，提供 Codex 在 Step 4 開始前建立並切換到正確 branch。

**Branch 命名格式：**
```
vMAJOR.MINOR.PATCH_short_topic_in_snake_case
```

**命名範例：**

| 任務類型 | 範例 |
|---|---|
| Bug fix / 小修正 | `v1.0.8_fix_sync_unauthorized_redirect` |
| 新功能 / 架構調整 / 優化 | `v1.1.0_perf_parallel_auth_load` |
| 破壞相容 / 大改版 | `v2.0.0_refactor_api_token_flow` |
| 純文件、不會合併發布 | `docs_update_collaboration_rules` |

**Branch section 範本（放在 IMPLEMENTATION_PLAN.md 最前面）：**

```markdown
## Branch

Before starting implementation, create and switch to the new branch:

git checkout -b v1.1.0_perf_parallel_auth_load

Base branch: main
```

**規則：**
1. 會合併至 `main` 的 code branch 必須使用 `vMAJOR.MINOR.PATCH_` 前綴；topic 使用英文小寫與底線，簡短描述本次任務。
2. Base branch 預設為 `main`。若 plan 明確定義 stacked branch 鏈，下一個版本 branch 可以前一個已 commit 的 version branch 為 base；plan 必須寫出 parent branch 與 parent commit，不可自行猜測。
3. Codex 在 Step 4 的第一步就執行 branch 建立，之後所有修改在新 branch 上進行。
4. 純文件且不會形成 App release 的 branch 可使用 `docs_` 前綴，不要求更新 App version。
5. Claude Code 產生 plan 時，必須同時指定預期 App version；Codex 在 Step 4 完成前必須確認 `#versionText` 與 branch 前綴一致。
6. 非 stacked 開發仍一律從 `main` 建立；stacked branch 只有在 plan 明確列出依賴順序時才允許。

### Step 5 通過後的自動行為

當 Step 5 review 結果為「無 Critical / Major issue（全部 Pass）」時，Claude Code **必須自動進入 Step 7**，完成後再進入 Step 8，不需要使用者另外要求。

自動建議格式（Step 7 完成後）：
```
Step 7 完成。

**進入 Step 8：請將以下指令貼給 Codex 執行 git commit：**

git add <file1>
git add <file2>
...
git commit -m "<commit message>"

Do NOT merge to main.
After commit, run: git log --oneline -3
```

若有 Critical / Major issue，則進入 Step 6（Codex 修正），修正完成後再回到 Step 5 重新 review，通過後才依序執行 Step 7 → Step 8。

### Step 4 — Codex 標準指令格式

每次交給 Codex 實作時，使用以下標準格式：

```
Please read docs/IMPLEMENTATION_PLAN.md and implement it.
If you think something is not quite right or the scope is unclear,
please ask questions before modifying any files.
Do NOT modify files outside the scope listed in the plan.

When finished, WRITE a summary to docs/CODEX_RESULT.md (overwrite the
file each time, do not append) formatted per comm.md's "Step 4 完成後
摘要格式". Do not just print it in chat — Claude Code reads this file
directly, the user does not need to copy/paste anything.
```

**這個格式的作用：**
- Codex 有疑問時會先提問，不會直接亂改。
- 明確限制修改範圍，避免 Codex 動到無關檔案。
- 減少 Step 5 review 發現問題的機率。
- 摘要寫成檔案而非只印在聊天視窗，讓 Claude Code 可以直接讀取，使用者不需要手動複製貼上。

### Step 4 完成後摘要格式

Codex 依照 `IMPLEMENTATION_PLAN.md` 完成修改後，**必須把摘要寫入 `docs/CODEX_RESULT.md`**（每次覆寫，不要累加），讓 Claude Code 可以直接讀取這個檔案進行 Step 5 review，使用者不需要自己複製貼上或轉述。

摘要必須包含以下欄位：

```markdown
English correction: `...`（若使用者最後一句是英文，提供修正；若無則省略此行）

中文主要回覆：已依照 docs/IMPLEMENTATION_PLAN.md 完成實作，並建立/切到 branch `<branch_name>`。

修改範圍：
- <檔案路徑>：<具體改了什麼，逐項列出>

驗證：
- <實際跑過的驗證步驟與結果，例如 lint / build / 啟動 server / console 檢查>

限制／未能驗證的部分：
- <例如本機未登入無法目視驗證、或某些情境未涵蓋>

工作區狀態：
- <git status 摘要，列出哪些檔案被修改/新增，是否有未追蹤檔案>
```

**規則：**
1. 摘要必須基於實際執行結果（real `git diff` / 真的跑過的指令），不可憑空想像驗證結果。
2. 「修改範圍」必須對應 `IMPLEMENTATION_PLAN.md` 列出的修改點，逐項說明，方便 Claude Code 比對 diff。
3. 若有偏離 plan 範圍的修改（例如發現必須多動一個檔案才能完成），必須在摘要中明確指出並說明原因，不可隱瞞。
4. 摘要長度以清楚、可核對為主，不需要過長的開發細節。
5. **必須寫入 `docs/CODEX_RESULT.md`**，每次任務覆寫整份檔案內容（不要累加歷史紀錄，歷史已經由 git commit 紀錄）。
6. Codex 完成並寫入 `docs/CODEX_RESULT.md` 後，只需要跟使用者說「已完成，請通知 Claude Code」之類的簡短訊息即可，不需要在聊天視窗整段貼出摘要全文。
7. 使用者收到 Codex 完成通知後，只需要跟 Claude Code 說一句「Codex 完成了，幫我看一下」之類的話，**不需要複製貼上任何內容**，Claude Code 會自己讀 `docs/CODEX_RESULT.md`。

### 驗證規則（取代 firmware build 驗證）

**每次 code 修改後必跑：**
```
1. 啟動本地 server：node server.js（或 npm start）
2. 開啟 http://localhost:3000 確認登入 / 同步 / 渲染流程正常
3. 檢查瀏覽器 console 與 server log 是否有新增的錯誤
```

**Supabase schema 變更時額外檢查：**
- 確認 `supabase/schema.sql` 或 migration 檔案同步更新
- 確認 RLS policy 沒有被破壞（避免跨用戶資料外洩）

---

### Step 7 — 同步更新永久文件（Claude Code 負責）

更新對象：
1. `00_investment_dashboard_plan_vX.X.md`
   - 反映這次任務對架構、行為、同步策略的修改
   - 必須更新版本號、`Last updated`、`Revision History`
2. `supabase/schema.sql`（若資料表結構有變動，需同步註解說明）
3. `IMPLEMENTATION_PLAN.md`（若 review 發現有錯誤需修正）

更新規則：
- Claude Code 負責判斷哪些 section 受影響。
- 內容必須反映實際 code 行為，不能超前描述未實作的功能。
- Codex **不負責**更新 plan MD。
- Step 7 必須再次核對 `#versionText`、branch 前綴與預期 release tag；版本不一致時不得進入 Step 8。

### Step 8 — 建議 Codex git commit（Claude Code 提供指令）

Claude Code 提供明確的 git 指令，包含：
- 要 `git add` 的檔案清單（明確列出，不使用 `git add .`）
- 完整 commit message（英文，說明這次做了什麼）
- 若為 App release branch，檔案清單必須包含已更新 `#versionText` 的 `index.html`
- 說明不 merge 到 main
- 要求 Codex 執行後顯示 `git log --oneline -3` 確認

### Claude Code 更新 Plan MD 的時機

1. 新增同步模式（如 fast/full sync 規則變動）。
2. 修改認證流程（Supabase Auth / Google OAuth）。
3. 修改 API contract（新增/移除 endpoint、修改 request/response 格式）。
4. 修改 Supabase schema（新增 table、欄位、RLS policy）。
5. 新增前端模組或調整資料流架構。

### 文件定位說明

| 文件 | 定位 | 生命週期 |
|---|---|---|
| `00_investment_dashboard_plan_vX.X.md` | 產品說明書，定義 WHY + WHAT | 長期維護，持續升版 |
| `docs/IMPLEMENTATION_PLAN.md` | 本次施工單，定義 HOW | 任務完成後封存 |
| `docs/CODEX_RESULT.md` | Codex 完成回報，Claude Code 直接讀取進行 Step 5 review | 每次任務覆寫，任務完成後跟著封存 |
| `docs/REVIEW_REPORT.md` | 本次 review 結果 | 任務完成後封存 |

## 範例
English correction: `Please review comm.md again, and make sure all actions follow the rules.`

中文主要回覆：我已重新檢查 `comm.md`，並把回覆規則整理成固定流程。後續我會先提供英文修正，再用中文給主要回覆，並在技術任務中附上具體設定與檔案路徑。
