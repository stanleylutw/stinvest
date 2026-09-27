-- Allow authenticated clients to read only their own sync cache.
-- Backend writes continue to use the service role.

begin;

drop policy if exists "sync_logs_owner_all" on public.sync_logs;
drop policy if exists "sync_logs_owner_select" on public.sync_logs;
create policy "sync_logs_owner_select" on public.sync_logs
for select using (auth.uid() = user_id);

revoke all on table public.sync_logs from public, anon;
revoke insert, update, delete, truncate, references, trigger
  on table public.sync_logs from authenticated;
grant select on table public.sync_logs to authenticated;
grant select, insert, update, delete on table public.sync_logs to service_role;

commit;
