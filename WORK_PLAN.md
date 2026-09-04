# Work plan — Supabase Health Inspector

Hand this to Claude Code as the working brief. Work through the phases in order.
Do not skip ahead — each phase depends on the previous one actually working, not
just compiling.

---

## Context you need before starting

This is a Postgres/Supabase diagnostic tool, originally scaffolded by Google AI
Studio and now being made real. It is a portfolio project for a Supabase Support
Engineer job application, so **correctness and honesty matter more than feature
count**. A recruiter with Postgres knowledge will read this code.

### Two databases

- **Project A (control plane)** — this app's own backend. Stores users, target
  connections, scan history, chat history. Connected via `CONTROL_PLANE_DATABASE_URL`.
- **Project B (target)** — a separate, deliberately-broken Supabase project that the
  tool diagnoses. Connected via `TARGET_DATABASE_URL` as a read-only role.

### The read-only role constraint (important)

The tool connects to Project B as `inspector_ro`, which has:
- `pg_read_all_data`
- `usage` on schemas `public` and `storage`
- **NOT** `pg_read_all_stats` — Supabase refuses to grant this; the managed
  `postgres` role lacks ADMIN option on it. This is a real platform limitation,
  not a setup mistake. Document it, don't try to work around it.
- **NOT** a member of `authenticated` — so it is subject to RLS and sees **zero
  rows** on RLS-protected tables.

That last point is the single most important design constraint in this project.
A diagnostic that cannot read rows must report that it could not read them —
never report OK.

### Ground truth for testing

In Project B, `public.orders` has 3 rows:

| id | user_id | note |
|---|---|---|
| 1 | `11111111-1111-1111-1111-111111111111 ` | trailing space |
| 2 | `11111111-1111-1111-1111-111111111111 ` | trailing space |
| 3 | `22222222-2222-2222-2222-222222222222` | clean |

RLS policy: `for select to authenticated using (user_id = auth.uid()::text)`

So user `1111...` should see 2 rows but sees **0**, because of the trailing space.
The policy expression itself looks perfectly correct — the defect is in the data.

---

## Phase 1 — Get it running and connected

**Goal:** prove the backend starts and talks to a real database.

1. Read the whole codebase and report what actually exists vs. what's stubbed.
2. Confirm `.env` exists with `TARGET_DATABASE_URL`, `CONTROL_PLANE_DATABASE_URL`,
   `GEMINI_API_KEY`. (User fills in real values — do not put secrets in chat.)
3. Confirm `.gitignore` excludes `.env`, `__pycache__/`, `.venv/`.
4. Install dependencies, start the server.
5. Write and run a one-off connectivity script that connects via
   `TARGET_DATABASE_URL` and runs `select current_user, version();`. Report the
   actual output. **If this fails, stop and fix it — nothing else matters until
   this works.**

**Done when:** the server runs and a real query returns real output from Project B.

---

## Phase 2 — Fix and verify the RLS module (the centerpiece)

**Goal:** the RLS debugger gives the correct answer on a table with known ground truth.

Known bug in `backend/app/diagnostics/rls_debug.py`:
`reltuples` returns `-1` on never-analyzed tables (a common real state). The
condition `readable_rows_count == 0 and reltuples_count > 0` therefore does not
fire, and the module falls through to reporting **OK** on a table it could not read.

Fix:
1. Treat `reltuples < 0` as "estimate unavailable." When `readable_rows_count == 0`
   and the estimate is unavailable, report INDETERMINATE, not OK.
2. Add a direct privilege check:
   `select has_table_privilege(current_user, 'public.<table>', 'SELECT')` — this
   answers "am I allowed to read this?" far more reliably than inferring from counts.
   Include the result in the output.
3. Note the distinction the module must make: having SELECT privilege but seeing
   zero rows under RLS is *different* from lacking SELECT privilege. Both are
   INDETERMINATE for data-shape purposes, but the explanation differs.

Then run it against `public.orders` and check the result against ground truth:
- **INDETERMINATE (cannot read rows under RLS)** → correct
- **OK** → wrong, the fix didn't work
- **CRITICAL whitespace defect** → investigate *how* it concluded that, since
  `inspector_ro` cannot see those rows

Write a pytest test asserting the module returns INDETERMINATE (not OK) when the
role cannot read rows. This is the most important test in the project.

**Done when:** the module gives the honest answer and a test locks that behavior in.

---

## Phase 3 — Verify the other four modules

Run each against Project B and report the **actual** output. Expect some to be
limited — that is fine and should be documented, not hidden.

1. **`vacuum.py`** — `pg_class` / `age(relfrozenxid)`. Should work. On a fresh
   database everything will report healthy; that is the correct result. Do not
   fabricate a problem.
2. **`connections.py`** — `pg_stat_activity`. Without `pg_read_all_stats`, query
   text for other sessions will show `<insufficient privilege>`. Handle this
   explicitly: report what *can* be seen (connection counts, states) and clearly
   state what cannot. Do not report OK if the data is unavailable.
3. **`storage_audit.py`** — `storage.buckets` and `pg_policies` on
   `storage.objects`. Verify `inspector_ro` can actually read these; if not,
   report INDETERMINATE.
4. **`slow_queries.py`** — `pg_stat_statements` is likely not enabled. Handle the
   missing-extension case gracefully with a clear message, not a crash and not
   a silent empty result.

For each module, apply the same rule as Phase 2: **a check that could not run is
never reported as passing.**

**Done when:** all five modules run without crashing and each reports honestly.

---

## Phase 4 — Control plane (Project A)

1. Apply the SQL migrations against `CONTROL_PLANE_DATABASE_URL`.
2. Verify tables were created and RLS policies are in place.
3. Verify scan results actually persist — run a scan, then query Project A
   directly and confirm the rows are there.
4. Verify auth works end to end (magic link → JWT verification → session).

**Done when:** a scan run against Project B is stored and retrievable from Project A.

---

## Phase 5 — Frontend

1. Verify each page actually calls the backend and renders real results.
2. Confirm the assistant page shows tool calls and their raw results, not just
   the final text — the point is that the investigation is visible and verifiable.
3. Remove any placeholder or lorem-ipsum content.

**Done when:** clicking through the UI produces real diagnostics from Project B.

---

## Phase 6 — Tests

Minimum meaningful coverage:
- `test_rls_debug.py` — asserts INDETERMINATE (not OK) when rows are unreadable;
  asserts correct detection when they are readable
- `test_connections.py` — asserts graceful handling of `<insufficient privilege>`
- `test_slow_queries.py` — asserts graceful handling of a missing extension
- `test_agent_tools.py` — mock the Gemini function_call response, assert the
  correct diagnostic function is dispatched with the correct arguments

**Done when:** `pytest` passes and the tests actually assert behavior, not just
that functions return something.

---

## Phase 7 — Documentation

The README is written by the user, not generated — a recruiter reads it to judge
whether the person understands what they built. Claude Code should prepare the
factual scaffolding (what each module checks, what SQL it runs, what the
limitations are) and leave the reasoning and narrative to the user.

It must cover, honestly:
- Why the diagnostic role is read-only, and the exact GRANT statements
- That `pg_read_all_stats` cannot be granted on Supabase, and what that limits
- That a read-only role is subject to RLS, and why the tool reports INDETERMINATE
  rather than OK when it cannot read rows — this is the most interesting design
  decision in the project
- What the vacuum module would report on an unhealthy production database vs.
  this demo (wraparound cannot be faked; it needs billions of real transactions)
- The GitHub issue mapping — **stated accurately**:
  - RLS module relates to the *class* of problem in issues #49106, #48302, #36260
  - The tool does **not** diagnose Supabase's own platform bugs (e.g. #47438,
    #46225 are hosted-infrastructure issues, not user-database issues) — do not
    claim otherwise
  - Storage module catches misconfiguration symptoms like those in #48015, but
    not the Studio UI bug that causes them
- A "what I'd build next" section

**Done when:** every claim in the README is one the user could defend in an
interview.

---

## Standing rules

1. **Never report OK for a check that could not run.** INDETERMINATE exists for
   this reason.
2. **No mocked, simulated, or hardcoded diagnostic output.** Every result comes
   from a real query against a real database.
3. **Never swallow exceptions with `except: pass`.** Surface the error.
4. **Parameterize all SQL.** Where an identifier must be interpolated (EXPLAIN
   cannot parameterize table names), validate it against `information_schema`
   first.
5. **No writes to the target database, ever.** The role is read-only by design;
   the code should also never attempt a write.
6. **Report actual output when verifying**, not a summary of what should have
   happened. "It works" is not a verification.
7. **Do not overstate progress.** "Compiles" is not "works." "Implemented" means
   run and verified against real data.
