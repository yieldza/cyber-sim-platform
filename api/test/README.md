# API tests

Tests use Node's built-in `node --test` runner. They exercise pure
helpers (no db) plus an end-to-end smoke that runs against a live
`docker compose up` stack.

## Running

```bash
# Pure-helper tests (no docker needed). The current api node deps
# (better-sqlite3) require Node 20; the bundled docker image uses
# node:20-alpine so this matches CI/runtime.
docker run --rm -v "$PWD":/app -w /app node:20-alpine sh -c \
  "npm install --silent && npm test"

# End-to-end smoke (requires docker compose up):
bash ../scripts/smoke-e2e.sh
```

## What's tested

| File | Coverage |
|------|----------|
| `agentAuth.test.js` | bcrypt round-trip, secret generation, error path on malformed hash |

## What's deliberately NOT tested here

- Express route handlers — covered by `scripts/smoke-e2e.sh` (curl-based)
- DB migrations — covered by `worker/tests/test_techniques.py`
  (catalog content) + manual SQL inspection
