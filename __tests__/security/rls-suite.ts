/**
 * Shared Row Level Security (RLS) attack suite.
 *
 * `describeRlsSuite(table)` runs the same five attacks against any table with
 * the profile shape (id, username, biography, avatar_url). Each
 * `*.rls.test.ts` file in this folder calls it for one table, which gives a
 * side-by-side before/after view.
 *
 * These tests talk to a REAL Supabase project (nothing is mocked). They act
 * the way an attacker would: using only the public anon key, the same key
 * any browser client gets, they try to read and modify OTHER users' rows.
 *
 * Each test asserts what SHOULD happen in a secure app. While RLS is off on a
 * table, its tests FAIL, and each failure message explains the leak. Once RLS
 * is enabled with correct policies, they should all PASS.
 *
 * Run with:  npm run test:security
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createClient, type SupabaseClient } from '@supabase/supabase-js';
import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import ws from 'ws';

// --- Load credentials from .env.local / .env (real values, not mocks) -------
for (const file of ['.env.local', '.env']) {
  const path = resolve(process.cwd(), file);
  if (!existsSync(path)) continue;
  for (const line of readFileSync(path, 'utf8').split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)\s*$/);
    if (!match || process.env[match[1]]) continue;
    process.env[match[1]] = match[2].replace(/^["']|["']$/g, '');
  }
}

const SUPABASE_URL = process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || '';
const ANON_KEY = process.env.SUPABASE_ANON_KEY || '';
const SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || '';

const PASSWORD = 'Rls-Demo-Password-123!';

// `realtime.transport` is needed on Node < 22, which has no built-in WebSocket.
const noSession = {
  auth: { persistSession: false, autoRefreshToken: false },
  realtime: { transport: ws as any },
};

type TestUser = { id: string; email: string };

/** Client with only the public anon key, logged in as nobody. */
function anonClient() {
  return createClient(SUPABASE_URL, ANON_KEY, noSession);
}

/** Client with the public anon key, logged in as `user` (what their browser has). */
async function clientSignedInAs(user: TestUser) {
  const { data, error } = await anonClient().auth.signInWithPassword({
    email: user.email,
    password: PASSWORD,
  });
  if (error || !data.session) throw new Error(`Could not sign in ${user.email}: ${error?.message}`);
  return createClient(SUPABASE_URL, ANON_KEY, {
    ...noSession,
    global: { headers: { Authorization: `Bearer ${data.session.access_token}` } },
  });
}

export function describeRlsSuite(TABLE: string) {
  const runId = `${TABLE.replace(/_/g, '-')}-${Math.random().toString(36).slice(2, 8)}`;

  // The admin client (service role) BYPASSES RLS. It's used only to set up
  // test data and to check what is really in the table.
  let admin: SupabaseClient;

  let alice: TestUser; // the victim
  let bob: TestUser; // the attacker
  let carol: TestUser; // a user with no profile yet

  async function createUser(name: string): Promise<TestUser> {
    const email = `rls-demo-${name}-${runId}@example.com`;
    const { data, error } = await admin.auth.admin.createUser({
      email,
      password: PASSWORD,
      email_confirm: true,
    });
    if (error || !data.user) throw new Error(`Could not create ${name}: ${error?.message}`);
    return { id: data.user.id, email };
  }

  async function profileAsAdmin(id: string) {
    const { data } = await admin.from(TABLE).select('*').eq('id', id).maybeSingle();
    return data;
  }

  describe(`RLS on "${TABLE}": users must not be able to touch each other's rows`, () => {
    beforeAll(async () => {
      if (!SUPABASE_URL || !ANON_KEY || !SERVICE_ROLE_KEY) {
        throw new Error(
          'Missing Supabase credentials. Set SUPABASE_URL, SUPABASE_ANON_KEY and ' +
            'SUPABASE_SERVICE_ROLE_KEY in .env.local (see .env.example).',
        );
      }
      admin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY, noSession);

      alice = await createUser('alice');
      bob = await createUser('bob');
      carol = await createUser('carol');

      const { error } = await admin.from(TABLE).insert([
        { id: alice.id, username: `alice_${runId}`, biography: "Alice's private bio" },
        { id: bob.id, username: `bob_${runId}`, biography: "Bob's bio" },
      ]);
      if (error) {
        throw new Error(
          `Could not seed ${TABLE}: ${error.message}. Has supabase/schema.sql been run?`,
        );
      }
    });

    afterAll(async () => {
      // Deleting the auth users cascades to their profile rows.
      for (const user of [alice, bob, carol]) {
        if (user) await admin.auth.admin.deleteUser(user.id);
      }
    });

    it('an anonymous visitor (not logged in) cannot list profiles', async () => {
      const { data } = await anonClient().from(TABLE).select('*').in('id', [alice.id, bob.id]);

      expect(
        data ?? [],
        `LEAK: someone who isn't logged in, holding only the public anon key, read ` +
          `${data?.length} profile row(s) from ${TABLE}.`,
      ).toHaveLength(0);
    });

    it("Bob cannot read Alice's profile", async () => {
      const asBob = await clientSignedInAs(bob);
      const { data } = await asBob.from(TABLE).select('*').eq('id', alice.id);

      expect(
        data ?? [],
        `LEAK: Bob read Alice's row in ${TABLE}: ${JSON.stringify(data?.[0])}`,
      ).toHaveLength(0);
    });

    it("Bob cannot change Alice's biography", async () => {
      const asBob = await clientSignedInAs(bob);
      await asBob.from(TABLE).update({ biography: 'HACKED BY BOB' }).eq('id', alice.id);

      const after = await profileAsAdmin(alice.id);
      expect(
        after?.biography,
        `TAMPERING: Bob overwrote Alice's biography in ${TABLE}.`,
      ).toBe("Alice's private bio");
    });

    it('Bob cannot create a profile on behalf of another user', async () => {
      const asBob = await clientSignedInAs(bob);
      await asBob.from(TABLE).insert({ id: carol.id, username: 'carol_by_bob', biography: 'fake' });

      const carolProfile = await profileAsAdmin(carol.id);
      expect(
        carolProfile,
        `IMPERSONATION: Bob created a row in ${TABLE} using Carol's user id.`,
      ).toBeNull();
    });

    // Runs last because, while the table is vulnerable, it really deletes Alice's row.
    it("Bob cannot delete Alice's profile", async () => {
      const asBob = await clientSignedInAs(bob);
      await asBob.from(TABLE).delete().eq('id', alice.id);

      const after = await profileAsAdmin(alice.id);
      expect(after, `DESTRUCTION: Bob deleted Alice's row in ${TABLE}.`).not.toBeNull();
    });
  });
}
