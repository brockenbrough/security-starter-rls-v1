# Steps for Implementing RLS on a Table

This guide shows how to turn on **Row Level Security (RLS)** for the
`myapp_profile` table in Supabase so that each user can only see and change
their own row.

It is written for two audiences:

- **Instructors and students** following along in the Supabase dashboard.
- **A future Claude session** that will turn this guide into a slide deck.
  Everything needed for the slides is in this file; nothing depends on earlier
  conversations.

> **Scope:** These steps are applied to `myapp_profile` only.
> The `unsecure_profile` table is a deliberate copy that stays insecure, so
> students can compare "before" and "after" side by side.
> **Do not run these steps on `unsecure_profile`.**

---

## 1. Background: the problem

### How a Supabase app talks to the database

Every Supabase project exposes the database through an HTTP API. A browser
calls it using two pieces of information:

| Item | Secret? | Notes |
|---|---|---|
| Project URL (`https://<id>.supabase.co`) | No | Visible in every browser request. |
| **anon key** (also called the publishable key) | **No, it is public by design** | It ships to every browser. Anyone can copy it out of the page. |
| **service_role key** (also called the secret key) | **Yes** | Server only. It **bypasses RLS completely**. |

Because the anon key is public, **the database itself must decide which rows
each caller may touch.** That is exactly what RLS does.

### What RLS is

Row Level Security is a PostgreSQL feature. When it is enabled on a table:

1. **Every row is hidden and locked by default** for normal roles.
2. You add **policies**, which are rules that say who may `select`, `insert`,
   `update` or `delete`, and which rows they apply to.
3. Postgres checks those rules on **every** query, no matter which client sent it.

The key building block in Supabase is **`auth.uid()`**: a function that returns
the id of the logged-in user who made the request (taken from their login
token), or `null` when nobody is logged in.

### The two roles that matter

| Postgres role | Who it is |
|---|---|
| `anon` | A visitor who is not logged in (uses only the anon key). |
| `authenticated` | A logged-in user (anon key **plus** their login token). |

---

## 2. Before: proving the table is insecure

The table looks like this:

```sql
create table myapp_profile (
  id         uuid primary key references auth.users(id) on delete cascade,
  username   text not null,
  biography  text not null default '',
  avatar_url text
);
```

`id` is the same value as the user's id in `auth.users`. That is what lets a
policy compare `auth.uid()` with `id`.

### The attack tests

The automated tests in `__tests__/security/` play the role of an attacker. The
setup creates three users:

- **Alice**, the victim, who has a profile.
- **Bob**, the attacker, who has a profile.
- **Carol**, who has no profile yet.

Then, using **only the public anon key**, the tests try five attacks.

| # | Attack | What a secure table must do |
|---|---|---|
| 1 | A visitor who is not logged in lists profiles | Return no rows |
| 2 | Bob reads Alice's profile | Return no rows |
| 3 | Bob changes Alice's biography | Leave it unchanged |
| 4 | Bob creates a profile using Carol's id | Reject the insert |
| 5 | Bob deletes Alice's profile | Leave the row in place |

Each test asserts the **secure** outcome, so a test **fails (red) when the attack works**.

Run them with:

```bash
npm run test:security
```

### Before results (RLS off on both tables)

All 10 tests fail. Each failure names the attack that worked:

```
× myapp_profile    > an anonymous visitor (not logged in) cannot list profiles
  → LEAK: someone who isn't logged in, holding only the public anon key, read 2 profile row(s) from myapp_profile.
× myapp_profile    > Bob cannot read Alice's profile
  → LEAK: Bob read Alice's row in myapp_profile: {"username":"alice_…","biography":"Alice's private bio",…}
× myapp_profile    > Bob cannot change Alice's biography
  → TAMPERING: Bob overwrote Alice's biography in myapp_profile.  (Received: "HACKED BY BOB")
× myapp_profile    > Bob cannot create a profile on behalf of another user
  → IMPERSONATION: Bob created a row in myapp_profile using Carol's user id.
× myapp_profile    > Bob cannot delete Alice's profile
  → DESTRUCTION: Bob deleted Alice's row in myapp_profile.

× unsecure_profile > (the same 5 failures)

Tests  10 failed (10)
```

---

## 3. Design the rules before writing SQL

Decide, for each operation, who should be allowed and on which rows.

| Operation | Rule for `myapp_profile` | Why |
|---|---|---|
| `select` (read) | A logged-in user may read **only their own** row. | Profiles hold private data such as the biography. |
| `insert` (create) | A logged-in user may create a row **only with their own id**. | Stops impersonation (attack 4). |
| `update` (change) | A logged-in user may change **only their own** row, and may not change its id to someone else's. | Stops tampering (attack 3). |
| `delete` (remove) | **Nobody** through the public API. | The app never deletes profiles. Rows are removed automatically when the user account is deleted (`on delete cascade`). |
| Visitors who are not logged in (`anon`) | **Nothing.** | No policy is written for `anon`, so they see nothing. |

**Principle: least privilege.** With RLS enabled, anything you do not
explicitly allow is denied. We write no `delete` policy and no `anon` policy
on purpose.

---

## 4. Steps to enable RLS on `myapp_profile`

### Step 1: Open the SQL Editor

1. Go to <https://supabase.com/dashboard> and open the project.
2. In the left sidebar, click **SQL Editor**.
3. Click **New query** (the `+` button).

> The **Table Editor** can also enable RLS (button "RLS disabled" →
> "Enable RLS") and add policies through a form. The SQL Editor is used here
> because the whole change is one script that can be read, reviewed and re-run.

### Step 2: Paste and run this SQL

Copy the whole block into the editor and click **Run** (or press Ctrl+Enter).

```sql
-- =====================================================================
-- Enable Row Level Security on myapp_profile
-- Each logged-in user may only read, create and update their OWN row.
-- =====================================================================

-- 1. Turn RLS on. From this moment, every row is hidden from the
--    anon and authenticated roles until a policy allows access.
alter table public.myapp_profile enable row level security;

-- (Re-run safety: remove old versions of these policies if they exist.)
drop policy if exists "Users can read their own profile"   on public.myapp_profile;
drop policy if exists "Users can create their own profile" on public.myapp_profile;
drop policy if exists "Users can update their own profile" on public.myapp_profile;

-- 2. READ: a logged-in user can see only the row whose id is their user id.
create policy "Users can read their own profile"
  on public.myapp_profile
  for select
  to authenticated
  using ( auth.uid() = id );

-- 3. CREATE: a logged-in user can insert a row only if its id is their own.
create policy "Users can create their own profile"
  on public.myapp_profile
  for insert
  to authenticated
  with check ( auth.uid() = id );

-- 4. UPDATE: a logged-in user can change only their own row (USING),
--    and the row must still be theirs afterwards (WITH CHECK).
create policy "Users can update their own profile"
  on public.myapp_profile
  for update
  to authenticated
  using      ( auth.uid() = id )
  with check ( auth.uid() = id );

-- 5. DELETE: intentionally NO policy, so nobody can delete through the API.
-- 6. anon (not logged in): intentionally NO policy, so they see nothing.
```

Expected result: **"Success. No rows returned."**

### Step 3: Confirm RLS is on and the policies exist

Run this in the SQL Editor:

```sql
-- Is RLS enabled? Expect: myapp_profile = true, unsecure_profile = false
select relname as table_name, relrowsecurity as rls_enabled
from pg_class
where relname in ('myapp_profile', 'unsecure_profile');

-- Which policies exist? Expect three rows: SELECT, INSERT, UPDATE
select policyname, cmd, roles, qual as using_rule, with_check
from pg_policies
where tablename = 'myapp_profile'
order by cmd;
```

You can also check visually: **Table Editor → `myapp_profile`**. The header
now shows **"RLS enabled"**. Under **Authentication → Policies**, the table
lists the three policies.

### Step 4: Run the attack tests again

```bash
npm run test:security
```

---

## 5. After: expected results

```
✓ myapp_profile    > an anonymous visitor (not logged in) cannot list profiles
✓ myapp_profile    > Bob cannot read Alice's profile
✓ myapp_profile    > Bob cannot change Alice's biography
✓ myapp_profile    > Bob cannot create a profile on behalf of another user
✓ myapp_profile    > Bob cannot delete Alice's profile

× unsecure_profile > (the same 5 failures as before: LEAK, LEAK, TAMPERING, IMPERSONATION, DESTRUCTION)

Tests  5 failed | 5 passed (10)
```

| Attack | `myapp_profile` (RLS on) | `unsecure_profile` (RLS off) |
|---|---|---|
| 1. Visitor who is not logged in lists profiles | ✅ Blocked | ❌ LEAK |
| 2. Bob reads Alice's profile | ✅ Blocked | ❌ LEAK |
| 3. Bob changes Alice's biography | ✅ Blocked | ❌ TAMPERING |
| 4. Bob creates a profile with Carol's id | ✅ Blocked | ❌ IMPERSONATION |
| 5. Bob deletes Alice's profile | ✅ Blocked | ❌ DESTRUCTION |

The 5 remaining failures are **expected**. They are the "before" table,
which shows what happens without RLS.

---

## 6. How each policy stops each attack

| Attack | What Postgres does with RLS on | What the attacker sees |
|---|---|---|
| 1. Visitor not logged in lists profiles | The caller is `anon`. No policy grants `anon` anything, so every row is filtered out. | An **empty list**. No error. |
| 2. Bob reads Alice's row | The `select` policy adds `auth.uid() = id` to the query. Bob's uid is not Alice's id. | An **empty list**. No error. |
| 3. Bob updates Alice's row | The `update` policy's `USING` rule hides Alice's row from Bob, so the update matches 0 rows. | **Success, 0 rows changed.** No error. |
| 4. Bob inserts with Carol's id | The `insert` policy's `WITH CHECK` rule fails because Carol's id is not Bob's uid. | **Error:** `new row violates row-level security policy for table "myapp_profile"` |
| 5. Bob deletes Alice's row | No `delete` policy exists, so no rows are deletable and the delete matches 0 rows. | **Success, 0 rows deleted.** No error. |

**Teaching point: RLS usually fails silently.** For reads, updates and deletes,
RLS does not raise an error. It makes forbidden rows invisible, as if they did
not exist. Only `WITH CHECK` violations (new or changed rows that break the
rule) raise an error.

### `USING` vs `WITH CHECK`

| Clause | Question it answers | Used by |
|---|---|---|
| `USING ( … )` | "Which **existing** rows can this user see or target?" | `select`, `update`, `delete` |
| `WITH CHECK ( … )` | "Is this **new or changed** row allowed to be saved?" | `insert`, `update` |

The `update` policy needs **both**. `USING` stops Bob from targeting Alice's
row. `WITH CHECK` stops Bob from editing his own row and changing its `id` to
Alice's.

---

## 7. Important limits: what RLS does not cover

1. **The service_role key bypasses RLS.** This app's server code
   (`lib/supabase.ts`) uses `SUPABASE_SERVICE_ROLE_KEY` when it is set. All
   API routes in `app/api/profile/` therefore **ignore RLS**. They stay safe only
   because the code filters by the logged-in user (`.eq('id', user.id)`). This
   is also why the app keeps working after RLS is enabled.
   - **Rule:** never expose the service_role key to the browser, and do not
     rely on RLS to protect code that runs with it.
   - **Stronger design (optional follow-up):** have the API routes query the
     database with the anon key **plus the user's login token**, so RLS also
     protects the server code.
2. **The test setup itself uses the service_role key** to create users and
   check results. That is intended. It acts as the "database administrator"
   looking at the real data.
3. **Storage is separate.** The `avatars` storage bucket has its own access
   policies (Storage → Policies). Enabling RLS on `myapp_profile` does not
   protect uploaded files.
4. **New tables.** Every new table that the browser can reach needs RLS enabled
   and its own policies. RLS is per table, not per project.

---

## 8. Optional improvements (not needed for the tests to pass)

- **Performance:** for large tables, Supabase recommends writing
  `( select auth.uid() ) = id` instead of `auth.uid() = id`, so the user id is
  looked up once per query instead of once per row. The behavior is the same.
- **Defense in depth:** remove the `anon` role's table privileges entirely, so
  even a mistakenly broad policy cannot expose data to visitors who are not
  logged in:
  ```sql
  revoke all on public.myapp_profile from anon;
  ```
- **Keep `supabase/schema.sql` in sync:** once the class has seen the
  demo, copy the SQL from Step 2 into `supabase/schema.sql` so new setups are
  secure from the start.

---

## 9. Reset: undo the change to repeat the demo

To return `myapp_profile` to the insecure "before" state (for example before
the next class), run:

```sql
drop policy if exists "Users can read their own profile"   on public.myapp_profile;
drop policy if exists "Users can create their own profile" on public.myapp_profile;
drop policy if exists "Users can update their own profile" on public.myapp_profile;
alter table public.myapp_profile disable row level security;
```

After this, `npm run test:security` shows all 10 tests failing again.

---

## 10. Suggested slide outline (for building the presentation)

1. **Title:** Row Level Security in Supabase.
2. **The setup:** a browser talks straight to the database with a *public* anon key.
3. **The question:** if the key is public, what stops Bob from reading Alice's data?
4. **The attack tests:** Alice, Bob and Carol, and the 5 attacks (Section 2 table).
5. **Live demo, before:** `npm run test:security`. Everything is red: LEAK, TAMPERING, IMPERSONATION, DESTRUCTION.
6. **What is RLS?** Default deny plus policies, checked by Postgres on every query.
7. **`auth.uid()`:** how the database knows who is asking.
8. **Design the rules first:** the table from Section 3 (least privilege).
9. **The SQL:** enable RLS (one line), then the three policies, one per slide or built up step by step.
10. **`USING` vs `WITH CHECK`:** Section 6 table, with the update policy as the example.
11. **Live demo, after:** run the tests. `myapp_profile` is green, `unsecure_profile` is still red.
12. **How each attack is stopped:** Section 6 table. Highlight "RLS fails silently."
13. **What RLS doesn't cover:** the service_role key, Storage, and new tables (Section 7).
14. **Checklist for any new table:** enable RLS → write a policy per operation → test as anon, as another user and as the owner.
