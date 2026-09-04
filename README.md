# Supabase Health Inspector (v3 — Python Backend)

A deep PostgreSQL & Supabase diagnostic suite and reliability agent. Pure Python 3.10+ / FastAPI backend, direct `asyncpg` telemetry engines, Supabase Vault credential storage, read-only RLS policy inspection, and Gemini-powered function-calling diagnostic assistance.

The design principle running through the whole tool: **a support tool should not need read access to customer data in order to explain a misconfiguration**, and it should never report OK for a check it could not actually run.

---

## Architecture & Design Rationale

### 1. Why Python End-to-End?
- **Python Ownership**: Every diagnostic query, auth validation, JWT cryptographic verification, Gemini function-calling agent loop, and background job runs in Python.
- **Direct `asyncpg`**: By bypassing heavy ORMs and wrapper SDKs, all diagnostic queries against both the control-plane and target PostgreSQL instances are executed over the asynchronous binary protocol.
- **Minimal Browser Surface**: The only JavaScript in the repository is `frontend/static/app.js` (vanilla DOM updates and `fetch()` calls). No Node build step, no frontend framework, no client-side secret exposure. The five HTML pages contain no inline scripts.

### Python version

`requires-python` is `>=3.10`. The codebase uses no syntax newer than the walrus operator, and pinning to 3.12 forced a toolchain upgrade that bought nothing. If you are starting fresh, 3.12 is still a fine choice — it is just not required.

---

## 2. Nested Row Level Security (RLS) Ownership Design

The control-plane database schema (`backend/migrations/001_initial_schema.sql`) enforces strict multi-tenant isolation across organizations:

- **Profiles**: `id = auth.uid()`
- **Target Connections & Scans**: Visibility is secured via nested subquery chains back to the caller's organization through `profiles`.
- **Zero Client-Writable Policies**: All scan results, chat histories, and diagnostic records are written exclusively by the backend service account connecting via a privileged role, preventing client-side tampering while maintaining read isolation.

```sql
-- Nested RLS Policy for Scan Results
CREATE POLICY "Members can view org scan results"
    ON public.scan_results
    FOR SELECT
    USING (
        scan_run_id IN (
            SELECT sr.id FROM public.scan_runs sr
            WHERE sr.target_connection_id IN (
                SELECT tc.id FROM public.target_connections tc
                WHERE tc.org_id IN (
                    SELECT p.org_id FROM public.profiles p WHERE p.id = auth.uid()
                )
            )
        )
    );
```

---

## 3. The 5 Core Diagnostic Modules

| Module | Purpose & Method | Target Telemetry Source |
|---|---|---|
| **1. Vacuum Wraparound** | Tracks frozen transaction ID age (`relfrozenxid`) against Postgres's 2-billion transaction limit | `pg_class` where `relkind in ('r','m')` |
| **2. RLS Inspector** | Reads policy expressions and column types from catalog metadata, determines *why* rows are or aren't visible, and captures the planner's verdict | `pg_policies`, `pg_tables`, `information_schema.columns`, `has_table_privilege`, `pg_has_role`, `EXPLAIN (VERBOSE, FORMAT JSON)` |
| **3. Connection Health** | Counts connections and detects lock contention and `idle in transaction` stalls **among the rows it can read**, reporting how many were opaque | `pg_stat_activity` |
| **4. Storage Audit** | Audits `storage.buckets` and `storage.objects` policies, and reports whether the bucket listing was trustworthy in the first place | `storage.buckets`, `pg_policies` on `storage.objects` |
| **5. Slow Queries** | Profiles query latency and call frequency; reports when statement text is redacted and no hotspot can be named | `pg_stat_statements` (resolved from `pg_extension`, not assumed to be on the `search_path`) |

Modules 3 and 5 are shaped by a privilege limit rather than a design choice — see §5.1.

---

## 4. The RLS Inspector (`rls_debug.py`)

The centerpiece diagnostic explains why a policy behaves the way it does, using only information a diagnostic role can see without reading customer rows.

### 4.1 What it actually does

1. **Identifier validation.** The table identifier is checked against `information_schema.tables` with a parameterized query before it is ever interpolated into SQL.
2. **Policy metadata.** Reads every policy on the table from `pg_policies` — command, roles, `USING` and `WITH CHECK` expressions — plus `rowsecurity` from `pg_tables`.
3. **Type-compatibility analysis.** Compares each column referenced by a policy expression against `information_schema.columns`. `auth.uid()` returns `uuid`; comparing it to a `text` column without a cast has no operator, and comparing a `uuid` column to `auth.uid()::text` casts every row and bypasses the index. Column references are matched as whole identifiers, so a column named `id` is not found inside `user_id`.
4. **Read-access verification.** Distinguishes four states that all look like `count(*) = 0` from the outside:

   | State | Signal | Verdict |
   |---|---|---|
   | No SELECT privilege | `has_table_privilege(...) = false` | INDETERMINATE — needs a `GRANT` |
   | No policy targets this role | no policy role the caller belongs to; planner emits `One-Time Filter: "false"` | INDETERMINATE — structurally invisible to this connection |
   | A policy applies, and filtered every row | policy applies, `count(*) = 0` | INDETERMINATE — RLS filtered these rows |
   | Rows visible | `count(*) > 0` | Data-shape checks are meaningful |

   The middle two are the interesting pair. Both return zero rows, but they are different problems: the first means this role can *never* see any row of the table no matter what it contains, and is a property of the connection rather than a defect in the data; the second means the policy actually ran and these particular rows did not match. Reporting them identically — as an earlier version did — tells a support engineer to go looking in the wrong place.

5. **Plan inspection.** Runs `EXPLAIN (VERBOSE, FORMAT JSON)` — **without** `ANALYZE` — to capture what the planner derived from the policy. `ANALYZE` would execute the query; the plan alone is sufficient and touches no rows.

   **Be aware of what this does and does not yield.** When a policy targets the connecting role, the plan shows the filter the planner built from it. When *no* policy targets the connecting role — the normal case for `inspector_ro`, since the policies target `authenticated` — there is no filter to show. Postgres proves at plan time that nothing can match and collapses the query to a constant-false node:

   ```
   Result  (cost=0.00..0.00 rows=0 width=0)
     One-Time Filter: "false"
   ```

   So for the read-only role, plan inspection yields no policy filter at all. That is not a failure: `One-Time Filter: "false"` is itself a stronger signal than `count(*) = 0`, because the planner is asserting statically — without touching the heap — that this role cannot see any row. The module surfaces it as `plan_proves_zero_rows`, and cross-checks it against an independent metadata query (`pg_has_role` over each policy's target roles) rather than trusting either signal alone.

There is no transaction, no role switch, and no simulated user. The module opens nothing it needs to roll back.

### 4.2 `reltuples` is not a row count

`pg_class.reltuples` is `-1` on a table that has never been analyzed. That means *"no estimate available"*, not *"zero rows"*. An earlier version of this module guarded its read-access check with `reltuples > 0`, which silently never fired on freshly seeded tables — so the module fell through and reported **OK on a table it had never successfully read.**

`has_table_privilege` is now the primary signal precisely because it is a fact rather than an estimate, and `reltuples` is reported as `null` when unavailable rather than coerced to a number. `seed_demo.py` deliberately does **not** run `ANALYZE`, so the seeded fixture reproduces this condition rather than masking it.

### 4.3 Why role impersonation was considered and rejected

An obvious design for this tool is to impersonate the caller inside a transaction:

```sql
BEGIN;
SET LOCAL ROLE authenticated;
SELECT set_config('request.jwt.claims', '{"sub":"...","role":"authenticated"}', true);
EXPLAIN (ANALYZE) SELECT * FROM public.orders;
ROLLBACK;
```

This was implemented, and then removed. Two reasons:

**The concrete trigger.** `SET ROLE authenticated` requires the connecting role to be a member of `authenticated`. The diagnostic role `inspector_ro` deliberately is not, so the statement fails outright. Granting that membership would make the inspector able to read every row of every RLS-protected table in the database.

**The principle.** A diagnostic that requires membership in `authenticated` requires elevated privileges on a customer's production database. A support tool should not need read access to customer data in order to explain a policy misconfiguration. Diagnosing from `pg_policies`, `information_schema`, and planner output alone is both safer and sufficient for the metadata-level defects this tool targets.

The tradeoff is real and worth stating: the metadata-only path cannot see row *contents*, so it cannot by itself confirm a defect that lives in the data. It reports INDETERMINATE instead, which is the honest answer — and §4.4 is the opt-in escape hatch for when you want more.

### 4.4 The optional elevated path (`TARGET_ELEVATED_DATABASE_URL`)

Some defects are invisible to policy inspection because the policy is correct and the *data* is malformed. The canonical case:

```
public.orders — user_id TEXT, RLS on
policy: FOR SELECT TO authenticated USING (user_id = auth.uid()::text)   -- correct

  user_id = '11111111-1111-1111-1111-111111111111 '   <- trailing space
  user_id = '11111111-1111-1111-1111-111111111111 '   <- trailing space
  user_id = '22222222-2222-2222-2222-222222222222'    <- clean
```

Nothing is wrong with the policy. User `1111…1111` still sees **0 rows instead of 2**, because `'…111 ' <> '…111'`. Finding this requires reading the rows.

So it is opt-in, and off by default:

- **Unset (default).** Data-shape checks do not run. The result is **INDETERMINATE with an explanation** — never OK, and never a silent skip.
- **Set.** Data-shape checks run through that connection only. Every finding it produces names the connection that produced it, in both the API response (`data_shape_source`) and the UI.

**What privilege the elevated path needs.** A role that can actually read the rows of the tables you want inspected — in practice either `BYPASSRLS`, or membership in a role the policies admit. **This is a real privilege escalation**, and declining it is a reasonable, supported choice: you keep every metadata finding and lose only the data-shape checks, which is why their absence is reported as INDETERMINATE rather than passed over.

### 4.5 What the API returns

`RLSDebugResponse` contains only things the inspector observed. Fields describing work the module does not perform were removed rather than stubbed:

- `rows_returned_count` was hardcoded to `0` and is gone; `readable_rows_count` reports what the diagnostic role could actually see, and is `null` when the read was not attempted.
- `transaction_rolled_back` was hardcoded to `true` for a transaction that was never opened. It is gone.
- `test_user_uuid` was accepted and ignored. It is gone from the request model.

A field that describes something the code does not do should not exist, because a caller cannot tell a placeholder from a result.

---

## 5. Target Database Read-Only Role Setup

Always connect using a dedicated read-only role. Run these grants on your target Supabase/PostgreSQL database:

```sql
-- 1. Create diagnostic role
CREATE ROLE inspector_ro WITH LOGIN PASSWORD 'YOUR_STRONG_PASSWORD';

-- 2. Grant connection and read permissions
GRANT CONNECT ON DATABASE postgres TO inspector_ro;
GRANT USAGE ON SCHEMA public TO inspector_ro;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO inspector_ro;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO inspector_ro;

-- 3. Grant system telemetry inspection
GRANT pg_read_all_stats TO inspector_ro;
```

### 5.1 What the read-only role cannot see, and what that costs

Three limits are structural on Supabase. Each one degrades a specific check, and in every case the module reports the degradation rather than a clean result. Measured against the live target instance:

| Limit | Cause | Effect on output |
|---|---|---|
| **`pg_read_all_stats` is not grantable** | Supabase's managed `postgres` role lacks ADMIN option on it, so it cannot be granted onward. Not a setup mistake. | `pg_stat_activity` returns `state = NULL` and `query = '<insufficient privilege>'` for backends owned by other users. On the test instance that was **4 of 5 connections**. Idle-in-transaction and lock-wait detection can only run against the remainder, so the connection module reports INDETERMINATE rather than "0 idle-in-transaction". |
| **Same limit, `pg_stat_statements`** | As above. | Timings are real for every statement, but statement *text* is redacted — **19 of 20** entries on the test instance. Latency is still assessable; the hotspot cannot be named. The module reports the latency finding and states plainly that the query behind it is unidentifiable. |
| **`storage.buckets` has RLS enabled** | Standard on Supabase; no bucket policy targets the diagnostic role. | The bucket listing comes back empty whether or not buckets exist. The module reports INDETERMINATE instead of "no buckets configured" — a claim about the customer's project that this role has no standing to make. |

`pg_stat_statements` also lives in the `extensions` schema on Supabase, not `public`, and is not on the default `search_path`. An unqualified `SELECT ... FROM pg_stat_statements` raises `UndefinedTable` even though the extension is installed and readable, so the module resolves the schema from `pg_extension` rather than assuming it.

Vacuum wraparound is unaffected — `pg_class` is world-readable, and `age(relfrozenxid)` needs no elevated privilege.

### 5.2 Role grants

Deliberately **not** granted: membership in `authenticated`, and `BYPASSRLS`. `inspector_ro` is therefore subject to RLS and sees zero rows on protected tables — which is the condition the INDETERMINATE reporting exists to handle honestly. Pointing `TARGET_DATABASE_URL` at a superuser would defeat the read-only design and hide exactly the behavior this tool is built to surface.

---

## 6. Configuration

All variables live in `backend/.env`. `config.py` resolves that path relative to the module, not the working directory, so the location is unambiguous no matter where `uvicorn` is launched from.

| Variable | Purpose | Required |
|---|---|---|
| `TARGET_DATABASE_URL` | Target instance, connecting as `inspector_ro` | Yes |
| `TARGET_ELEVATED_DATABASE_URL` | Opt-in higher-privilege connection for data-shape checks (§4.4) | No — off by default |
| `CONTROL_PLANE_DB_URL` | Control-plane instance (orgs, scans, chats). Unset ⇒ in-memory mode | No |
| `SUPABASE_URL` | Control-plane project API URL | No — demo auth without it |
| `SUPABASE_ANON_KEY` | Control-plane anon key | No |
| `SUPABASE_SERVICE_ROLE_KEY` | Backend only; never sent to the frontend | No |
| `GEMINI_API_KEY` | Gemini narration and the function-calling assistant | No — diagnostics run without it |

**Percent-encode passwords in connection URIs.** A password containing `@ # / ? :` breaks the URI: `@`→`%40`, `#`→`%23`, `/`→`%2F`, `?`→`%3F`, `:`→`%3A`.

**Variable names are matched exactly.** A near-miss such as `CONTROL_PLANE_DATABASE_URL` reads as unset with no error. The server prints which settings resolved at startup — names and set/unset only, never values — so check that output rather than assuming the file was read.

`.env*` is gitignored (excluding `.env.example`). Never commit it, and never print its contents.

---

## 7. Relationship to reported Supabase issues

These are the *classes* of problem this tool is built around. Stating the relationship precisely matters more than the length of the list, so each entry below says what the inspector actually does and does not do.

**What the RLS module addresses.** It detects the class of defect in these reports — a policy that looks provably correct but matches nothing, because of a type mismatch, a missing cast, or malformed data on one side of the comparison:

- [#49106](https://github.com/supabase/supabase/issues/49106) — policy rejects a provably-matching `auth.uid()` through a type mismatch or omitted cast.
- [#48302](https://github.com/supabase/supabase/issues/48302) — policy rejected for `anon` despite apparently correct configuration.
- [#36260](https://github.com/supabase/supabase/issues/36260) — RLS behaving differently between direct queries and stored procedures (`SECURITY DEFINER` vs `SECURITY INVOKER`).

The inspector reports the *evidence* — the policy expression, the column types, whether any policy targets the connecting role, and the planner's verdict. It does not reproduce any specific issue above, and it does not decide that a given database is affected by one.

**What this tool does not do.** It diagnoses *your database*, not Supabase's hosted infrastructure. Two categories are out of scope, and the inspector should not be presented as covering them:

- Platform and pooler faults — e.g. [#47438](https://github.com/supabase/supabase/issues/47438) (`FATAL: database "supabase_admin" does not exist`, pooler misrouting) and [#46225](https://github.com/supabase/supabase/issues/46225) (intermittent schema-cache errors during connection spikes). These are hosted-infrastructure problems. Nothing in `pg_stat_activity` or `pg_class` diagnoses them, and the connection module makes no claim to.
- Dashboard/Studio bugs — e.g. [#48015](https://github.com/supabase/supabase/issues/48015), where storage policy expressions silently fail to save in the editor. The storage module can observe the *symptom* (a bucket whose policies are missing or unexpectedly permissive); it cannot see the UI defect that caused it, and cannot distinguish "never saved" from "deliberately absent".

**Storage, stated accurately.** The module inspects `storage.buckets` and the policies on `storage.objects`, which is the shape of misconfiguration behind reports like [#29908](https://github.com/supabase/supabase/issues/29908) (private bucket access failing under custom request headers). On a read-only role that no bucket policy targets, it reports INDETERMINATE rather than an all-clear — see §5.1.

---

## 8. Authentication and the control plane

**Token verification.** Access tokens are verified with PyJWT against the project's published JWKS, checking signature, expiry, and the `authenticated` audience. The allow-list is `["ES256", "RS256"]`.

Two details worth knowing:

- Current Supabase projects sign with **ES256** (EC P-256). An allow-list of `["RS256", "HS256"]` — which this code shipped with — raises `InvalidAlgorithmError` on every valid token.
- **HS256 is deliberately absent.** Every key on this path arrives from JWKS and is therefore public. Permitting a symmetric algorithm alongside public keys is the classic algorithm-confusion attack: sign a forged token using the public key as an HMAC secret and the verifier accepts it. Legacy HS256 projects would need the shared JWT secret supplied explicitly, on a separate path.

**Demo auth is gated.** `ENVIRONMENT` defaults to `production` in `config.py`, and in production:

| Behaviour | Non-production | Production |
|---|---|---|
| Request with no token | Answered as a hardcoded demo user | **401** |
| Token when `SUPABASE_URL` is unset | Decoded without signature verification | **503** — refuses to accept what it cannot verify |
| Startup output | Loud multi-line `DEMO AUTH IS ENABLED` banner | `demo auth: DISABLED` |

Every use of a demo path logs a warning naming the request that took it. Tokens are accepted as a `Bearer` header or as the HTTP-only `shi_session` cookie set by `/auth/callback`.

**Control-plane persistence.** Scan runs and their per-module results are written to Project A. The run row is inserted *before* diagnostics execute, so a crash mid-sweep leaves a `running` row rather than no trace, and `started_at` reflects when the scan began rather than when its results were written. `raw_result` is stored as queryable `jsonb`. The API response carries a `persisted` flag, so a run held only in memory cannot be mistaken for a saved one.

**Control-plane RLS.** Migration 001 left `public.orgs` without RLS; on Supabase the `public` schema is exposed through PostgREST, so every organisation row was readable by anyone holding the anon key. Migration 002 closes it with the same nested `profiles.org_id` pattern used by every other table, and 003 does the same for `public._schema_migrations`. All eight tables now have RLS enabled.

---

## 9. LLM providers: Gemini, Ollama, or neither

The model is a pluggable layer, not a dependency. Diagnostics are the product; the LLM only puts words around results that were produced by SQL. Nothing in §3–§5 needs a model to run.

| `LLM_PROVIDER` | Behaviour |
|---|---|
| `auto` (default) | Try Gemini, fall back to Ollama, then to deterministic routing |
| `gemini` | Gemini only |
| `ollama` | Local Ollama only — no API key, no egress |
| `none` | No LLM; deterministic keyword routing only |

Switchable at runtime from the assistant page (`PUT /assistant/provider`) without a restart. The override is process-local and is not persisted — a restart returns to `LLM_PROVIDER` in `backend/.env`.

**Availability is probed, not assumed.** `GET /assistant/providers` calls each provider for real, so `configured` and `available` can disagree — which is exactly what a rejected API key looks like:

```
gemini  configured=True  available=False  ClientError: 401 UNAUTHENTICATED ...
ollama  configured=True  available=False  No Ollama at http://localhost:11434 (ConnectError).
```

**Every reply names its source.** `ChatMessageResponse.provider` is `gemini`, `ollama`, or `none`, and the UI prints it above each answer. When no provider answers, the reply is prefixed with why, and the real diagnostic still runs:

```
[No LLM provider answered (ollama: Ollama request failed: ConnectError: All
connection attempts failed). The diagnostic below still ran against the live
database.]
```

That distinction is the point: a fallback answer is deterministic keyword routing over real query output, not a model's reasoning, and it must never be presented as the latter.

**Tool schemas are translated, not duplicated.** google-genai parses tool definitions into `types.Schema`, whose Type enum is uppercase (`"OBJECT"`); Ollama expects plain lowercase JSON Schema. The Gemini-native form in `tools.py` is the source of truth and `ollama_tool_schemas()` converts it, so a tool is defined once.

**Running Ollama:**

```bash
ollama serve
ollama pull llama3.1
```

Tool calling needs a model that supports it — `llama3.1`, `qwen2.5`, and `mistral-nemo` do. Set `OLLAMA_MODEL` to match what you pulled; the status probe accepts either a bare name or a tagged one (`llama3.1` matches `llama3.1:latest`).

**Verified end to end** against a live daemon with `llama3.2` (3.2B, Q4_K_M). With `LLM_PROVIDER=auto` and the Gemini key rejected, a request fell through to Ollama and completed a real tool call:

```
provider:   ollama
tool_calls: 1
  - run_rls_debug args={'table_name': 'orders'}
```

**Latency:** ~70s on the first call (loading a 2 GB model into memory), then **4-10s** warm. The diagnostics are a couple of seconds of that; the rest is inference.

### 9.1 Why the model is handed a verdict, not just rows

A small local model asked to interpret raw telemetry will invent findings. Given only `pct_to_wraparound: 0.00`, `llama3.2` reported:

> "there is a potential issue with transaction ID wraparound on the `orders` table... which could lead to data corruption"

on a table that is entirely healthy. That is the exact failure this project exists to avoid, produced by the narration layer rather than by the diagnostics.

The fix is structural, not a prompt patch. Severity is computed in Python from explicit thresholds, and that **verdict is passed to the model alongside the raw rows**:

```json
{"severity": "ok", "summary": "OK: Transaction ID age healthy...", "raw_result": [...]}
```

The model's job is to explain a verdict, not to reach one. After the change, the same question returns:

> "The results indicate that all public tables are healthy, with no transaction ID wraparound issues... No further action is required."

The same pattern fixed a second error. Asked why a user sees zero rows, the model had recommended `GRANT SELECT ON public.orders` -- useless, since `has_select_privilege` was already `true` and RLS was the cause. It now correctly identifies that no policy targets `inspector_ro`, and proposes role membership or a new policy instead.

**Residual inaccuracy is still expected.** In the corrected wraparound answer the model still added "the `orders` table is still 11 transactions behind", a garbled reading of `xid_age`. The verdict was right and no false alarm was raised, but the prose around it is not trustworthy on its own. This is why every answer displays its tool call, arguments, and full result: the narration is a summary to check against the trace, never an authority. A larger tool-calling model (`qwen2.5:7b`, `mistral-nemo`) reduces this; it does not eliminate it.

---

## 10. Transaction ID Wraparound: Production vs Demo

- **What Wraparound Reports in Production**: In an active production Postgres database, tables report real frozen transaction ID ages (`age(relfrozenxid)`). When this value approaches 2 billion (e.g. >1.6B or 80%), Postgres enters emergency mode and refuses write queries to prevent data corruption. The inspector alerts when tables exceed warning thresholds (50% and 80%).
- **Why Wraparound Cannot Be Faked in Demo**: Simulating genuine wraparound requires consuming billions of distinct transactions (`txid_current()`), which is impractical and unsafe on demo databases. The inspector documents this physical constraint while calculating genuine mathematical ages from `pg_class`.

---

## 11. What I'd Build Next

1. **Automated Autovacuum Tuning Advisor**: Compute custom `autovacuum_vacuum_scale_factor` and `autovacuum_freeze_max_age` recommendations per table based on write volume.
2. **Supavisor & PgBouncer Real-time Topology Map**: Live connection graph visualizing client pools, pooler queuing, and server-side connections.
3. **Automated RLS Policy Generator & Fixer**: AI-generated SQL migration scripts that patch type mismatches and data-shape defects, with one-click staging tests.
4. **Data-shape checks without elevated access**: the trailing-whitespace class of defect is currently only reachable through the opt-in elevated connection. A `SECURITY DEFINER` function that the customer installs themselves — returning only aggregate counts, never row contents — would let the inspector confirm the defect while keeping the privilege boundary intact.
