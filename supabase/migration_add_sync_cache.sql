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

create table if not exists public.user_settings (
  user_id uuid primary key references auth.users(id) on delete cascade,
  money_masked boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trg_user_settings_updated_at on public.user_settings;
create trigger trg_user_settings_updated_at
before update on public.user_settings
for each row execute function public.set_updated_at();

alter table public.user_settings enable row level security;

drop policy if exists "user_settings_owner_all" on public.user_settings;
create policy "user_settings_owner_all" on public.user_settings
for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

notify pgrst, 'reload schema';
