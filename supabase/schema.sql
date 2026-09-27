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

create table if not exists public.user_settings (
  user_id uuid primary key references auth.users(id) on delete cascade,
  money_masked boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.user_google_tokens (
  user_id uuid primary key references auth.users(id) on delete cascade,
  refresh_token text not null,
  scope text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index if not exists idx_user_sheets_user_active on public.user_sheets(user_id, is_active);
create index if not exists idx_sync_logs_user_created on public.sync_logs(user_id, created_at desc);
create index if not exists idx_sync_logs_user_sheet_success_finished
  on public.sync_logs(user_id, sheet_id, finished_at desc, created_at desc)
  where status = 'success';
create index if not exists idx_sync_logs_user_sheet_started
  on public.sync_logs(user_id, sheet_id, started_at desc, created_at desc);
create index if not exists idx_portfolio_items_user_sheet on public.portfolio_items(user_id, sheet_id, sheet_order);
create index if not exists idx_user_google_tokens_updated on public.user_google_tokens(updated_at desc);

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

drop trigger if exists trg_user_settings_updated_at on public.user_settings;
create trigger trg_user_settings_updated_at
before update on public.user_settings
for each row execute function public.set_updated_at();

drop trigger if exists trg_user_google_tokens_updated_at on public.user_google_tokens;
create trigger trg_user_google_tokens_updated_at
before update on public.user_google_tokens
for each row execute function public.set_updated_at();

alter table public.user_sheets enable row level security;
alter table public.sync_logs enable row level security;
alter table public.portfolio_items enable row level security;
alter table public.user_settings enable row level security;
alter table public.user_google_tokens enable row level security;

drop policy if exists "user_sheets_owner_all" on public.user_sheets;
create policy "user_sheets_owner_all" on public.user_sheets
for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "sync_logs_owner_all" on public.sync_logs;
drop policy if exists "sync_logs_owner_select" on public.sync_logs;
create policy "sync_logs_owner_select" on public.sync_logs
for select using (auth.uid() = user_id);

revoke all on table public.sync_logs from public, anon;
revoke insert, update, delete, truncate, references, trigger
  on table public.sync_logs from authenticated;
grant select on table public.sync_logs to authenticated;
grant select, insert, update, delete on table public.sync_logs to service_role;

drop policy if exists "portfolio_items_owner_all" on public.portfolio_items;
create policy "portfolio_items_owner_all" on public.portfolio_items
for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "user_settings_owner_all" on public.user_settings;
create policy "user_settings_owner_all" on public.user_settings
for all using (auth.uid() = user_id) with check (auth.uid() = user_id);

drop policy if exists "user_google_tokens_owner_all" on public.user_google_tokens;
revoke all on table public.user_google_tokens from public, anon, authenticated;
grant select, insert, update, delete on table public.user_google_tokens to service_role;

create or replace function public.apply_portfolio_sync(
  p_user_id uuid,
  p_sheet_id uuid,
  p_sync_log_id uuid,
  p_spreadsheet_id text,
  p_items jsonb,
  p_payload_json jsonb,
  p_source_ranges text[],
  p_finished_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_started_at timestamptz;
  v_row_count integer := 0;
begin
  if jsonb_typeof(coalesce(p_items, '[]'::jsonb)) <> 'array' then
    raise exception 'p_items must be a JSON array';
  end if;

  perform pg_advisory_xact_lock(hashtext(p_user_id::text), hashtext(p_sheet_id::text));

  select started_at
    into v_started_at
    from public.sync_logs
   where id = p_sync_log_id
     and user_id = p_user_id
     and sheet_id = p_sheet_id
   for update;

  if not found then
    raise exception 'Sync log does not belong to the requested user and sheet';
  end if;

  if exists (
    select 1
      from public.sync_logs
     where user_id = p_user_id
       and sheet_id = p_sheet_id
       and status = 'success'
       and started_at > v_started_at
  ) then
    update public.sync_logs
       set status = 'superseded',
           finished_at = p_finished_at,
           row_count = 0,
           message = 'sync superseded by a newer successful request',
           source_ranges = p_source_ranges,
           payload_json = null,
           error_message = null
     where id = p_sync_log_id;

    return jsonb_build_object(
      'applied', false,
      'reason', 'superseded',
      'rowCount', 0
    );
  end if;

  delete from public.portfolio_items
   where user_id = p_user_id
     and sheet_id = p_sheet_id;

  insert into public.portfolio_items (
    user_id,
    sheet_id,
    sync_log_id,
    spreadsheet_id,
    account,
    item_name,
    sheet_order,
    price,
    move_text,
    acc_dividend,
    profit_with_dividend,
    profit_with_dividend_rate,
    market_value,
    monthly_income,
    row_json
  )
  select
    p_user_id,
    p_sheet_id,
    p_sync_log_id,
    p_spreadsheet_id,
    item.account,
    item.item_name,
    item.sheet_order,
    item.price,
    item.move_text,
    item.acc_dividend,
    item.profit_with_dividend,
    item.profit_with_dividend_rate,
    item.market_value,
    item.monthly_income,
    item.row_json
  from jsonb_to_recordset(coalesce(p_items, '[]'::jsonb)) as item(
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
    row_json jsonb
  );

  get diagnostics v_row_count = row_count;

  update public.user_sheets
     set last_synced_at = p_finished_at
   where id = p_sheet_id
     and user_id = p_user_id;

  if not found then
    raise exception 'Linked sheet does not belong to the requested user';
  end if;

  update public.sync_logs
     set status = 'success',
         finished_at = p_finished_at,
         row_count = v_row_count,
         message = 'sync completed',
         source_ranges = p_source_ranges,
         payload_json = p_payload_json,
         error_message = null
   where id = p_sync_log_id
     and user_id = p_user_id
     and sheet_id = p_sheet_id;

  if not found then
    raise exception 'Unable to finalize sync log';
  end if;

  with ranked as (
    select
      id,
      case when status = 'success' then 'success' else 'terminal' end as status_group,
      row_number() over (
        partition by case when status = 'success' then 'success' else 'terminal' end
        order by created_at desc, id desc
      ) as position
    from public.sync_logs
    where user_id = p_user_id
      and sheet_id = p_sheet_id
      and status in ('success', 'failed', 'superseded')
  ), expired as (
    select id
    from ranked
    where (status_group = 'success' and position > 50)
       or (status_group = 'terminal' and position > 20)
  )
  delete from public.sync_logs
   where id in (select id from expired);

  return jsonb_build_object(
    'applied', true,
    'reason', 'updated',
    'rowCount', v_row_count
  );
end;
$$;

revoke all on function public.apply_portfolio_sync(
  uuid, uuid, uuid, text, jsonb, jsonb, text[], timestamptz
) from public, anon, authenticated;

grant execute on function public.apply_portfolio_sync(
  uuid, uuid, uuid, text, jsonb, jsonb, text[], timestamptz
) to service_role;
