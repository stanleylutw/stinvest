-- Run this manually in the Supabase SQL editor.
-- Enable Realtime for portfolio_items and sync_logs so the frontend
-- can subscribe to changes and refresh without polling.
alter publication supabase_realtime add table portfolio_items;
alter publication supabase_realtime add table sync_logs;
