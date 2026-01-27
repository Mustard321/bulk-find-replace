# Bulk Find & Replace Runbook

Recommended Node version: 20.x

Setup
```sh
cd server
npm install
cd ../client
npm install
```

Start server (3001)
```sh
cd server
npm start
```

Start client (5173)
```sh
cd client
npm run dev -- --host 0.0.0.0 --port 5173
```

Test in Monday (Vercel prod)
1) Vercel Production URL: `https://bulk-find-replace.vercel.app`
2) Monday Developer Center → App → Features → set Board View URL to the Vercel production URL.
3) Open the board view in Monday and hard refresh (Cmd/Ctrl+Shift+R).
4) If cached, remove/re-add the view or open the board in a fresh tab.

Live test checklist (Board View)
- Authorize if prompted (one-time).
- Step 1 (Where to look): confirm targets toggle and field/group lists load by name (no IDs shown).
- Step 2 (What to change): run preview with a short find term.
- Step 3 (Safety): confirm max changes default is 250 and Dry run starts ON.
- Step 4 (Preview & apply): confirm counts, filters, and paging work; check “Show only changed”.
- Apply: confirm typing APPLY + acknowledgement is required; successful apply shows run ID.
- Audit export: open `/api/audit?run_id=...` and confirm rows exist.

API examples
Preview
```sh
curl -X POST "$API_BASE/api/preview" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d '{
    "accountId": "12345",
    "boardId": 123456,
    "find": "old",
    "replace": "new",
    "targets": { "items": true, "subitems": true, "docs": true },
    "rules": { "caseSensitive": false, "wholeWord": false },
    "filters": {
      "includeColumnIds": ["text"],
      "excludeColumnIds": ["notes"],
      "includeGroupIds": ["topics"],
      "excludeGroupIds": ["done"],
      "includeNameContains": ["alpha"],
      "excludeNameContains": ["draft"],
      "docIds": ["12345"]
    },
    "limit": { "maxChanges": 200 },
    "pagination": { "pageSize": 200, "cursor": null }
  }'
```

Apply
```sh
curl -X POST "$API_BASE/api/apply" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $SESSION_TOKEN" \
  -d '{
    "accountId": "12345",
    "boardId": 123456,
    "find": "old",
    "replace": "new",
    "confirmText": "APPLY",
    "targets": { "items": true, "subitems": true, "docs": false },
    "rules": { "caseSensitive": false, "wholeWord": false },
    "filters": { "includeColumnIds": [], "excludeColumnIds": [] },
    "limit": { "maxChanges": 1000 }
  }'
```

Audit log
- Stored in sqlite table `audit_log` within the same database as tokens.
- Default path: `server/tokens.db` (or `TOKENS_DB_PATH`).
- Export JSON:
```sh
curl "$API_BASE/api/audit?run_id=<run_id>"
```
- Reset locally: stop the server and delete `server/tokens.db`.

Troubleshooting
- 401 Not authorized: open `/auth/authorize?accountId=...` to connect or re-open inside Monday.
- Authorization expired: preview/apply return 401 or `NOT_AUTHORIZED`; click Reconnect in the UI or open `/auth/authorize?accountId=...` in a new tab.
- Missing accountId/boardId: reopen inside a board view.
- Preview empty: check filters, targets, or case sensitivity.
- Docs warning: docs API calls are best-effort; add doc IDs manually or disable docs target.
- Apply failed: open Diagnostics, copy Request ID, and check server logs for the same requestId.
- 429/5xx errors: apply uses retries with backoff, but large runs may need lower max changes.

Assumptions (no web research)
- Docs queries/mutations use `docs(ids: ...)` and `update_doc_block` with `content`.
- Doc column values contain `doc_id`/`docId` in the raw `value` payload.
- Subitem column values are safe to update via `change_multiple_column_values` with subitem board id.
- Items pagination relies on `items_page` cursors; preview pagination is per items page.

Known limitations
- Docs support is best-effort and may skip blocks if the GraphQL schema differs.
- Preview paging is items-page based and does not dedupe if the board changes mid-run.
- Subitem scanning is capped per item to keep previews responsive.

Privacy/data storage notes
- OAuth tokens are stored in sqlite (`tokens` table) to authorize Monday API calls.
- Audit logs are stored in sqlite (`audit_log` table) with before/after text for each update.

Marketplace submission checklist
- Production URL points to `https://bulk-find-replace.vercel.app` with Production Branch = `main`.
- Privacy statement includes token storage + audit log retention.
- Support contact is set (email or URL).
- Known limitations include docs best-effort and potential paging duplication.
