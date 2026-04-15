-- STInvest Supabase schema (user-owned data)
-- Run in Supabase SQL Editor.

create extension if not exists pgcrypto;

create table if not exists public.user_sheets (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  sheet_url text not null,
  spreadsheet_id text not null,
  is_active boolean not null default true,
  last_synced_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (user_id, spreadsheet_id)
);

create table if not exists public.sync_logs (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  sheet_id uuid references public.user_sheets(id) on delete set null,
  spreadsheet_id text,
  status text not null,
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  row_count integer,
  source_ranges text[],
  payload_json jsonb,
  message text,
  error_message text,
  created_at timestamptz not null default now()
);

create table if not exists public.portfolio_items (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  sheet_id uuid references public.user_sheets(id) on delete set null,
  sync_log_id uuid references public.sync_logs(id) on delete set null,
  spreadsheet_id text,
  account text,
  item_name text,
  sheet_order integer,
  price numeric,
  move_text text,
  acc_dividend numeric,
  profit_with_dividend numeric,
  profit_with_dividend_rate numeric,
  market_value numeric,
  monthly_income numeric,
  row_json jsonb not null,
  created_at timestamptz not null default now()
);

create index if not exists idx_user_sheets_user_active on public.user_sheets(user_id, is_active);
create index if not exists idx_sync_logs_user_created on public.sync_logs(user_id, created_at desc);
create index if not exists idx_portfolio_items_user_sheet on public.portfolio_items(user_id, sheet_id, sheet_order);

create or replace function public.set_updated_at()
returns trigger
language plpgsql
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trg_user_sheets_updated_at on public.user_sheets;
create trigger trg_user_sheets_updated_at
before update on public.user_sheets
for each row execute function public.set_updated_at();

alter table public.user_sheets enable row level security;
alter table public.sync_logs enable row level security;
alter table public.portfolio_items enable row level security;

drop policy if exists "user_sheets_owner_all" on public.user_sheets;
create policy "user_sheets_owner_all" on public.user_sheets
for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "sync_logs_owner_all" on public.sync_logs;
create policy "sync_logs_owner_all" on public.sync_logs
for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "portfolio_items_owner_all" on public.portfolio_items;
create policy "portfolio_items_owner_all" on public.portfolio_items
for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
