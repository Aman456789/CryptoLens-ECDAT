# ECDAT — End-to-End Implementation & Run Plan

This is the actual, ordered path from "files on disk" to "a running platform that scans a real repo and shows results in the dashboard" — grounded in the real codebase you uploaded (`ecdat-workspace-fixed.zip`, `files.zip`, `new_code.zip`), not a generic guide.

---

## 0. Two things to fix before you start

I checked the codebase directly rather than assuming it matches the docs. Two gaps will block you immediately if skipped:

### 0.1 Project creation didn't exist anywhere

The Application Flow doc describes "the user creates a project, gets a token, shown once" — but `server.js` has no route for it, and the frontend's `api.js` never calls one either. **Nothing in this system works without a token**, so this is step zero, not an afterthought.

I've written the missing piece: `backend/src/controllers/projectController.js` (created above). You still need to wire it into `server.js`:

```js
// server.js — add near the top with the other controller imports
const { createProject } = require('./controllers/projectController');

// add near the other routes, BEFORE any authenticateProject-gated route —
// this is the one route that must NOT require a token, since its whole
// job is to issue one
app.post('/api/projects', express.json({ limit: '10kb' }), createProject);
```

Until the real UI catches up, you'll create projects with `curl` (Step 5 below shows exactly how).

### 0.2 The v3.0 files need to be dropped into place and wired in

`new_code.zip` and `files.zip` contain new/modified files that aren't connected to anything yet. Placement:

| From | Goes to |
|---|---|
| `new_code/classicalTriageEngine.js` | `backend/src/services/classicalTriageEngine.js` |
| `new_code/patchValidator.js` | `backend/src/services/patchValidator.js` |
| `new_code/nist-kat-vectors.json` | `backend/src/services/fixtures/nist-kat-vectors.json` |
| `files/Asset.js` | **replaces** `backend/src/models/Asset.js` |
| `files/exportController.js` | `backend/src/controllers/exportController.js` |
| *(from this session)* `nvidiaLlmService.js` | **replaces** `backend/src/services/nvidiaLlmService.js` |
| *(from this session)* `verificationQueue.js` | **replaces** `backend/src/queues/verificationQueue.js` |

And `server.js` needs one more route (the CycloneDX export, per the v3.0 delta — also never wired in):

```js
const exportController = require('./controllers/exportController');
router.get('/api/export/cyclonedx', authenticateProject, exportController.toCycloneDx);
```

⚠️ **Critical, not optional:** `nist-kat-vectors.json` is explicitly labeled a placeholder in its own `_WARNING` field — every value is zeros. `patchValidator.js` will correctly fail-closed on every real candidate until you replace it with actual FIPS 203 ML-KEM vectors and NIST CAVP AES-GCM/ChaCha20-Poly1305 vectors. **This means `fixStatus` will never reach `'generated'` until you do this.** That's the gate working as designed, not a bug — but it will look like a broken feature if you don't know why.

---

## 1. Prerequisites

| Tool | Why | Check |
|---|---|---|
| Docker + Docker Compose v2 | Runs the whole stack identically to production | `docker compose version` |
| Node.js 18+ | Only needed if you want to run the backend bare (outside Docker) for fast iteration | `node --version` |
| Python 3.11 | Only needed for bare (non-Docker) scanner-cli/ai-service runs | `python3 --version` |
| An NVIDIA API key | Powers PQC fix generation (hosted mode) | console.nvidia.com |
| GitHub repo + Actions enabled | For the automated CI scan path | — |

You do **not** need Semgrep, Redis, or MongoDB installed locally — they run inside containers.

---

## 2. Directory layout you should end up with

```
ecdat-workspace/
├── .env                          # ← you create this (copy from .env.example)
├── .env.example
├── docker-compose.yml
├── Caddyfile
├── .github/workflows/ecdat-scan.yml
├── backend/
│   ├── Dockerfile
│   ├── package.json
│   └── src/
│       ├── server.js             # ← edit: add /api/projects + /api/export/cyclonedx
│       ├── controllers/
│       │   ├── ingestController.js
│       │   ├── scanController.js
│       │   ├── dashboardController.js
│       │   ├── projectController.js     # ← NEW (Step 0.1)
│       │   └── exportController.js      # ← NEW (from files.zip)
│       ├── middleware/{authenticateProject,verifySignature}.js
│       ├── models/{Project,Asset}.js    # ← Asset.js REPLACED (from files.zip)
│       ├── queues/verificationQueue.js  # ← REPLACED (this session)
│       └── services/
│           ├── sanitizer.js
│           ├── resilientClient.js
│           ├── moscaAlgorithm.js
│           ├── nvidiaLlmService.js      # ← REPLACED (this session)
│           ├── classicalTriageEngine.js # ← NEW (new_code.zip)
│           ├── patchValidator.js        # ← NEW (new_code.zip)
│           └── fixtures/nist-kat-vectors.json  # ← NEW (new_code.zip)
├── ai-service/            (Python FastAPI — unchanged this round)
├── scanner-cli/           (Python Semgrep runner — unchanged this round)
└── frontend/              (React dashboard — unchanged this round)
```

---

## 3. Environment configuration

Copy the template and fill it in — the existing `.env.example` is missing the v3.0 variables the directory delta specifies, so add those too:

```bash
cp .env.example .env
```

```dotenv
# --- existing (.env.example) ---
MONGO_URI=mongodb://ecdat_user:changeme@mongo:27017/ecdat?authSource=admin
PROJECT_SECRET=$(openssl rand -hex 32)          # run this and paste the output
FRONTEND_URL=http://localhost                    # use your real domain in production
MONGO_INITDB_ROOT_USERNAME=ecdat_user
MONGO_INITDB_ROOT_PASSWORD=changeme
NVIDIA_API_KEY=nvapi-xxxxxxxxxxxxxxxxxxxx

# --- v3.0 additions (not in the current .env.example — add these) ---
LLM_TARGET=hosted                                 # hosted | nim
NIM_ENDPOINT_URL=http://nim:8000/v1/completions   # only read when LLM_TARGET=nim
KAT_VECTORS_PATH=./src/services/fixtures/nist-kat-vectors.json
```

Also update `docker-compose.yml`'s `backend` service to actually pass the new vars through (they exist in `.env` but nothing forwards them into the container yet):

```yaml
  backend:
    environment:
      # ...existing vars unchanged...
      - LLM_TARGET=${LLM_TARGET}
      - NIM_ENDPOINT_URL=${NIM_ENDPOINT_URL}
      - KAT_VECTORS_PATH=${KAT_VECTORS_PATH}
```

Never commit `.env` — it's already in `.gitignore`.

---

## 4. Bring the stack up

```bash
cd ecdat-workspace
docker compose build
docker compose up -d
docker compose ps
```

Expect 6 containers: `caddy`, `backend`, `frontend`, `ai-service`, `redis`, `mongo`. Note that per the compose file, **only Caddy publishes ports to the host** (80/443) — `backend` and `ai-service` are deliberately unreachable directly, by design (Patch 3 isolation). Everything goes through `http://localhost/...`.

### 4.1 Verify each service is actually healthy — don't assume

```bash
# Gateway (through Caddy)
curl -s http://localhost/api/dashboard -H "X-ECDAT-Token: x" | head -c 200
# expect a 401/403 JSON error at this point — that's CORRECT, it proves
# routing + auth middleware are alive; you don't have a real token yet

# AI service — only reachable from inside the network, not the host, by design
docker compose exec backend curl -sf http://ai-service:8000/health
# expect: {"status":"ok"}

# Redis
docker compose exec backend sh -c "node -e \"require('ioredis'); console.log('ok')\""
docker compose exec redis redis-cli ping
# expect: PONG

# Mongo
docker compose exec mongo mongosh --quiet --eval "db.adminCommand('ping')"
```

If `ai-service` doesn't respond, check its logs specifically — the model-weight bake-in step in its Dockerfile downloads from Hugging Face **at build time**, so a build-time network failure there is a common first-run issue:

```bash
docker compose logs ai-service --tail=50
```

---

## 5. Create your first project and get a token

```bash
curl -s -X POST http://localhost/api/projects \
  -H "Content-Type: application/json" \
  -d '{"name": "AyurSutra Backend"}'
```

```json
{ "projectId": "66f...", "token": "ecdat_66f....<64-hex-chars>" }
```

**Save the `token` value now** — it is bcrypt-hashed on the server and is not retrievable again. Export it for convenience:

```bash
export ECDAT_TOKEN="ecdat_66f....<64-hex-chars>"
```

Verify auth now works end-to-end:

```bash
curl -s http://localhost/api/dashboard -H "X-ECDAT-Token: $ECDAT_TOKEN"
# expect: {"totalAssets":0, ...} — a real, empty dashboard, not a 401/403
```

---

## 6. Run Path A — the automated code scan (locally first, before wiring CI)

Don't debug the scanner for the first time inside GitHub Actions — run it locally against a small vulnerable dummy repo first, exactly the way the whitepaper's MVD strategy describes.

### 6.1 Build a dummy vulnerable target

```bash
mkdir -p /tmp/dummy-vulnerable-app && cd /tmp/dummy-vulnerable-app
cat > auth.js << 'EOF'
const crypto = require('crypto');
function encrypt(data) {
  const key = crypto.createHash('RSA-1024').update('secret').digest();
  return key;
}
module.exports = { encrypt };
EOF
git init -q
```

### 6.2 Run the scanner container directly against it

```bash
cd ecdat-workspace
docker compose build scanner-cli   # scanner-cli isn't in the up stack by default — build it standalone
docker run --rm \
  --network ecdat-workspace_ecdat-net \
  -v /tmp/dummy-vulnerable-app:/repo:ro \
  -e ECDAT_TOKEN="$ECDAT_TOKEN" \
  -e PROJECT_SECRET="<the raw secret half of your token, after the dot>" \
  -e BACKEND_URL="http://backend:5000" \
  ecdat-workspace-scanner-cli /repo
```

You should see log output confirming Semgrep found the `RSA-1024` pattern and the batch POST to `/api/ingest/batch` returned `202`.

### 6.3 Confirm it landed

```bash
curl -s http://localhost/api/assets -H "X-ECDAT-Token: $ECDAT_TOKEN" | python3 -m json.tool
```

You should see one asset with `algorithm: "RSA-1024"`, `status: "active"`, and — within a few seconds, once the BullMQ worker processes it — `riskTag` populated (watch it move from `Unverified` to `Critical`).

---

## 7. Watch the v3.0 engines actually run

This is the part unique to this revision — verify each new piece individually, not just "the dashboard looks fine":

```bash
docker compose logs backend --tail=100 -f
```

Push another finding with a **SWEET32-class** algorithm to confirm the Classical Triage Engine fires independently of Mosca:

```bash
# add to auth.js: const legacy = crypto.createCipheriv('des-ede3-cbc', key, iv);
```

Re-run the scanner (Step 6.2), then check the asset:

```bash
curl -s http://localhost/api/assets -H "X-ECDAT-Token: $ECDAT_TOKEN" | python3 -m json.tool
```

Look for `"classicalRiskFlags": ["SWEET32"]` on that finding — set independently of whatever `riskTag` Mosca assigned, exactly as designed.

### 7.1 Expect `fixStatus: "fix_pending"` until you load real KAT vectors

Given the placeholder fixture (Step 0.2), every Critical finding will show:

```json
"fixStatus": "fix_pending",
"fixValidation": { "sastPassed": true, "katPassed": false, "validatedAt": "..." }
```

`sastPassed: true` proves the LLM candidate was generated and passed the Semgrep re-scan. `katPassed: false` is the placeholder fixture correctly rejecting it. This is expected — treat it as your signal that the gate is wired correctly, not as a failure to chase.

---

## 8. Run Path B — the manual network scan

```bash
curl -s -X POST http://localhost/api/scan/network \
  -H "X-ECDAT-Token: $ECDAT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://expired.badssl.com"}'
```

This exercises the "Unlinked Asset" safeguard on a fresh project — since no code scan has established an `expectedDomains` list yet, this finding should come back tagged `isLinked: false`. Check it:

```bash
curl -s http://localhost/api/assets -H "X-ECDAT-Token: $ECDAT_TOKEN" | python3 -m json.tool
```

---

## 9. Open the actual dashboard

```
http://localhost
```

The frontend currently has no UI for creating a project or entering a token (that gap mirrors the backend gap in Step 0.1) — for now, the fastest unblock is to open browser dev tools on `http://localhost` and manually set whatever `localStorage`/context value `frontend/src/services/api.js` expects to attach as `X-ECDAT-Token` (check that file for the exact key it reads). Wiring a real login/project-picker screen is the next frontend task, not something to reverse-engineer live — flagging it here rather than leaving it implicit.

---

## 10. Wire up real CI (GitHub Actions)

The workflow file already exists and is correct; you need to:

1. **Publish the scanner image to ghcr.io** (the workflow pulls `ghcr.io/<owner>/ecdat-scanner:latest`, it doesn't build it):
   ```bash
   docker build -t ghcr.io/<your-org>/ecdat-scanner:latest ./scanner-cli
   echo $GITHUB_PAT | docker login ghcr.io -u <your-username> --password-stdin
   docker push ghcr.io/<your-org>/ecdat-scanner:latest
   ```
2. **Set repo secrets** (Settings → Secrets and variables → Actions):
   - `ECDAT_TOKEN` — the full token from Step 5
   - `PROJECT_SECRET` — the raw secret half (after the `.`)
3. **Set a repo variable**: `BACKEND_URL` — your real, publicly reachable backend URL (not `localhost` — GitHub's runners can't reach your laptop; see the ngrok note below for local testing).

### 10.1 If you're still developing locally, not deployed yet

GitHub's hosted runners cannot reach `localhost` on your machine. Bridge it temporarily:

```bash
ngrok http 80
# set the GitHub repo variable BACKEND_URL to the printed https://*.ngrok-free.app URL
```

This is explicitly a development-only bridge — production replaces it with your real domain, no code change required.

---

## 11. Production / air-gapped path (when you're ready)

Everything above ran with `LLM_TARGET=hosted`. For an NTRO-style air-gapped deployment:

1. Add the `nim` service block to `docker-compose.yml` (documented in the v3.0 directory delta — gated behind a compose profile so it never starts by default):
   ```bash
   docker compose --profile air-gapped up -d
   ```
2. Flip `.env`: `LLM_TARGET=nim`. No code change — this is exactly the toggle implemented in `nvidiaLlmService.js` this session.
3. Confirm the `ai-service` container never makes an outbound call at runtime (it shouldn't — weights are baked in at build time per its Dockerfile) by checking its logs for any Hugging Face request attempts after startup — there should be none.

---

## 12. Troubleshooting quick-reference

| Symptom | Likely cause |
|---|---|
| `401 missing X-ECDAT-Token header` on everything | You skipped Step 5, or exported the token wrong (check for a trailing newline from `curl` output) |
| Scanner POSTs but nothing appears in `/api/assets` | Check `docker compose logs backend` for a signature-verification failure — confirm `PROJECT_SECRET` passed to the scanner container is the *raw secret* (after the dot), not the full token |
| `fixStatus` never leaves `fix_pending` | Expected — see §7.1. Replace the placeholder KAT vectors with real FIPS 203 / NIST CAVP data |
| `ai-service` container keeps restarting | Check `docker compose logs ai-service` — most likely the Hugging Face download failed during `docker compose build` (needs internet at build time only) |
| `docker run --network ecdat-workspace_ecdat-net` fails with "network not found" | Your compose project name differs — run `docker network ls` and substitute the actual name |
| CORS errors in the browser console | `FRONTEND_URL` in `.env` doesn't exactly match the origin you're loading the dashboard from (scheme + host + port all have to match) |

---

## Summary — what's genuinely new vs. what already existed

| Already existed and works as documented | Had to be added/fixed to actually run |
|---|---|
| Docker network isolation, Caddy TLS/reverse-proxy, HMAC signing, token auth, BullMQ concurrency cap, Mosca's engine, sanitizer masking | `/api/projects` route + controller (didn't exist anywhere) |
| `ai-service`'s offline model bake-in, ghcr.io-based CI workflow | `/api/export/cyclonedx` route registration in `server.js` (file existed, was never wired in) |
| — | `LLM_TARGET`/`NIM_ENDPOINT_URL`/`KAT_VECTORS_PATH` missing from `.env.example` and not forwarded in `docker-compose.yml` |
| — | Real NIST KAT vectors (current fixture is an explicitly-labeled placeholder that fails every candidate by design) |