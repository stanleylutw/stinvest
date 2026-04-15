-- Migration for existing projects with older tables
-- Run once in Supabase SQL Editor.

alter table public.sync_logs
  add column if not exists source_ranges text[],
  add column if not exists payload_json jsonb,
  add column if not exists spreadsheet_id text,
  add column if not exists status text,
  add column if not exists started_at timestamptz,
  add column if not exists finished_at timestamptz,
  add column if not exists row_count integer,
  add column if not exists message text,
  add column if not exists error_message text,
  add column if not exists created_at timestamptz not null default now();

notify pgrst, 'reload schema';
