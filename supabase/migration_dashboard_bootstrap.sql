-- Consolidate the authenticated dashboard bootstrap into one round trip.
-- Existing table RLS remains the authorization boundary.

begin;

create or replace function public.get_dashboard_bootstrap()
returns jsonb
language sql
stable
security invoker
set search_path = public, pg_temp
as $$
  with active_sheet as (
    select id, sheet_url, spreadsheet_id, last_synced_at
      from public.user_sheets
     where user_id = auth.uid()
       and is_active = true
     order by updated_at desc, id desc
     limit 1
  ), user_setting as (
    select money_masked
      from public.user_settings
     where user_id = auth.uid()
     limit 1
  ), latest_cache as (
    select
      logs.id,
      logs.finished_at,
      logs.row_count,
      logs.spreadsheet_id,
      logs.payload_json
    from public.sync_logs as logs
    join active_sheet as sheet on sheet.id = logs.sheet_id
    where logs.user_id = auth.uid()
      and logs.status = 'success'
    order by logs.finished_at desc nulls last, logs.created_at desc, logs.id desc
    limit 1
  )
  select jsonb_build_object(
    'sheet', (
      select jsonb_build_object(
        'id', id,
        'sheet_url', sheet_url,
        'spreadsheet_id', spreadsheet_id,
        'last_synced_at', last_synced_at
      )
      from active_sheet
    ),
    'settings', coalesce(
      (
        select jsonb_build_object('money_masked', money_masked)
        from user_setting
      ),
      jsonb_build_object('money_masked', false)
    ),
    'cache', (
      select jsonb_build_object(
        'source', 'supabase-bootstrap',
        'cachedAt', finished_at,
        'syncLogId', id,
        'rowCount', row_count,
        'spreadsheetId', spreadsheet_id,
        'data', payload_json
      )
      from latest_cache
    )
  );
$$;

revoke all on function public.get_dashboard_bootstrap() from public, anon;
grant execute on function public.get_dashboard_bootstrap() to authenticated;

commit;

notify pgrst, 'reload schema';
