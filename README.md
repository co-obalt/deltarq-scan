# deltarq-scan

**Scan your startup's codebase and infrastructure for security gaps in 30 seconds.**

[![License: MIT](https://img.shields.io/badge/License-MIT-6C5CE7.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-339933.svg)](https://nodejs.org/)

---

```bash
npx deltarq-scan
```

`deltarq-scan` is a **local-first, zero-install, read-only** CLI security audit tool. It scans your repository (configurations, environment variables, IAM policies, git history) for critical security gaps that block enterprise deals, fail SOC 2 audits, or expose you to immediate breach.

---

## What it checks

| Rule | Severity | What it catches |
|------|----------|----------------|
| `IAM-001` | 🔴 CRITICAL | Wildcard IAM policies (`Action: *`, `Resource: *`) |
| `DB-001` | 🔴 CRITICAL | Postgres with no SSL on public endpoints |
| `INFRA-001` | 🔴 CRITICAL | Docker containers running as root |
| `INFRA-004` | 🔴 CRITICAL | Insecure CI/CD workflow (Dangerous `pull_request_target` in GitHub Actions) |
| `IAM-002` | 🟠 HIGH | Hardcoded Cloud/API Secrets (AWS, Stripe, Slack, GitHub keys in `.env`) |
| `INFRA-002` | 🟠 HIGH | Database ports exposed to all interfaces |
| `INFRA-003` | 🟠 HIGH | Missing package lockfile (Deterministic builds/SOC 2 control) |
| `LOG-001` | 🟠 HIGH | No structured audit trail / logging |
| `IAM-003` | 🟡 MEDIUM | No MFA on AWS root account |
| `DB-002` | 🟡 MEDIUM | No connection pool limits |
| `GIT-001` | 🟡 MEDIUM | Secrets leaked in git history |

---

## How it works

1. **Runs entirely on your machine** — scans `.env`, `Dockerfile`, `docker-compose.yml`, IAM policies
2. **Generates a security score** — 0-100 with grade (A-F) and enterprise readiness flag
3. **Shows a rich terminal report** — color-coded findings with plain English explanations
4. **Optionally uploads anonymous metadata** — only boolean pass/fail data, no secrets ever leave your machine

```
────────────────────────────────────────────────────────
   DELTARQ Security Scanner v0.1.0
   Scanning: /Users/you/my-startup
────────────────────────────────────────────────────────

   ✓ Detecting project type...           FastAPI + PostgreSQL
   ⚠ Scanning configuration files...     3 issues found
   ✓ Scanning IAM configuration...       1 issue found
   ✓ Scanning database config...         No issues
   ✓ Scanning git history...             Clean

────────────────────────────────────────────────────────
   YOUR SECURITY SCORE: 34/100   [F — Critical Exposure]
────────────────────────────────────────────────────────

   🔴 CRITICAL   IAM-001  Wildcard IAM policy detected
                  → Any compromised service = full account takeover

   🔴 CRITICAL   DB-001   Postgres unencrypted on public host
                  → User data exposed to interception in transit

   🟠 HIGH       LOG-001  No audit trail detected
                  → You cannot detect or investigate a breach

────────────────────────────────────────────────────────
   ENTERPRISE READINESS: ✗ Not Ready
   SOC 2 Gap Count: 3 controls failing
────────────────────────────────────────────────────────
```

---

## Usage

```bash
# Scan current directory
npx deltarq-scan

# Scan a specific project
npx deltarq-scan ./my-project

# Scan without upload prompt
npx deltarq-scan --no-upload

# Output JSON (for CI/CD pipelines)
npx deltarq-scan --json

# Verbose mode (see upload payload preview)
npx deltarq-scan --verbose
```

---

## What data is uploaded?

**Only if you consent.** And only this:

```json
{
  "scan_id": "uuid",
  "score": 34,
  "grade": "F",
  "enterprise_ready": false,
  "findings": [
    { "rule": "IAM-001", "severity": "CRITICAL", "passed": false }
  ]
}
```

**What is NEVER uploaded:**
- ❌ No `.env` values
- ❌ No AWS keys or secrets  
- ❌ No file contents
- ❌ No IP addresses
- ❌ No company name (unless you opt in on dashboard)

---

## Privacy & Security

- **Open source** — read every line of code before running
- **Read-only** — never modifies your files
- **Local-first** — all scanning happens on your machine
- **Consent-gated** — nothing leaves without your explicit `Y`
- **MIT Licensed** — use it however you want

---

## Development & Local Testing

### 1. Setup
```bash
# Clone the repository
git clone https://github.com/deltarq/deltarq-scan.git
cd deltarq-scan

# Install dependencies
npm install
```

### 2. Run Scanner Locally
```bash
# Scan the current directory
node bin/deltarq-scan.js

# Scan mock test fixtures (no upload prompt)
node bin/deltarq-scan.js ./tests/fixtures --no-upload
```

### 3. Test Global CLI Command Locally (`npm link`)
Before publishing to the npm registry, you can test the global `npx deltarq-scan` command in any directory on your computer by linking it:
```bash
# 1. In the deltarq-scan project root, run:
npm link

# 2. Go to any other directory/project folder and run:
npx deltarq-scan
# or simply:
deltarq-scan
```

### 4. Test Full Upload Pipeline Locally
You can spin up a local Express server and test uploader integration directly.

**Terminal 1: Start Dashboard API Server**
```bash
npm run server
```

**Terminal 2: Run Scan & Upload to Local Server**
* **Windows (PowerShell)**:
  ```powershell
  $env:DELTARQ_API_URL="http://localhost:3000/v1/scans"; $env:DELTARQ_DASHBOARD_URL="http://localhost:3000"; node bin/deltarq-scan.js ./tests/fixtures
  ```
* **Mac/Linux (Bash)**:
  ```bash
  DELTARQ_API_URL="http://localhost:3000/v1/scans" DELTARQ_DASHBOARD_URL="http://localhost:3000" node bin/deltarq-scan.js ./tests/fixtures
  ```

### 5. Run Automated Unit Tests
```bash
# Run Vitest test runner
npm test
```

---

## Production Deployment

### 1. Database Setup (Supabase)
Create a project on [Supabase](https://supabase.com) and copy the SQL code inside [supabase_schema.sql](supabase_schema.sql) into the **Supabase SQL Editor**, then click **Run**. This instantiates the `scans` and `leads` tables with pre-configured Row-Level Security (RLS) rules.

### 2. Host Backend & Dashboard (Vercel)
Deploy the unified Express server and static dashboard using the Vercel CLI from the root folder:
```bash
vercel --prod
```
Be sure to set the following **Environment Variables** on your Vercel Dashboard:
- `DATA_LAYER_ENDPOINT` = your-supabase-project-url
- `DATA_LAYER_ANON_KEY` = your-supabase-public-anon-key (or `DATA_LAYER_SERVICE_ROLE_KEY` for higher privilege)
- `DELTARQ_DASHBOARD_URL` = your-deployed-vercel-domain (e.g. `https://deltarq-scan.vercel.app`)

---

## License

MIT — [DELTARQ](https://deltarq.io)
