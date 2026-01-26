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
- Missing accountId/boardId: reopen inside a board view.
- Preview empty: check filters, targets, or case sensitivity.
- Docs warning: docs API calls are best-effort; add doc IDs manually or disable docs target.

Assumptions (no web research)
- Docs queries/mutations use `docs(ids: ...)` and `update_doc_block` with `content`.
- Doc column values contain `doc_id`/`docId` in the raw `value` payload.
- Subitem column values are safe to update via `change_multiple_column_values` with subitem board id.
- Items pagination relies on `items_page` cursors; preview pagination is per items page.
