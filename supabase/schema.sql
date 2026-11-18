-- Run this whole file in your Supabase SQL editor. It creates myapp_profile
-- and the demo table unsecure_profile. Every statement is safe to re-run.

create table if not exists myapp_profile (
  id         uuid primary key references auth.users(id) on delete cascade,
  username   text not null,
  biography  text not null default '',
  avatar_url text
);

-- Upgrade: tables created by an earlier version of this script have no
-- avatar_url column ("create table if not exists" won't add it). This line
-- adds it, and does nothing if the column is already there.
alter table myapp_profile add column if not exists avatar_url text;

-- ---------------------------------------------------------------------------
-- DEMO ONLY: unsecure_profile, an intentionally INSECURE copy of myapp_profile.
-- It keeps Row Level Security OFF so students can compare it with
-- myapp_profile once that table is secured. Never copy this pattern into a real app.
-- ---------------------------------------------------------------------------
create table if not exists unsecure_profile (
  id         uuid primary key references auth.users(id) on delete cascade,
  username   text not null,
  biography  text not null default '',
  avatar_url text
);

-- Explicitly keep RLS off, even if the project enables it on new tables automatically.
alter table unsecure_profile disable row level security;

-- Make sure the browser-facing roles can reach it (newer Supabase projects
-- may not grant this by default), so the "before" demo always shows the leak.
grant select, insert, update, delete on unsecure_profile to anon, authenticated;

-- Create a public storage bucket for avatar images.
-- In the Supabase dashboard: Storage → New bucket → name "avatars" → check "Public bucket".
