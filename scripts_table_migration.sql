-- Запусти этот SQL в Supabase Dashboard → SQL Editor (проект hczsybtjcmlqbaxwhgyp)
-- После этого в вики откроется вкладка «🎯 Скрипты», данные будут синхронизироваться.

create table if not exists public.scripts (
  id text primary key,
  data jsonb not null,
  updated_at timestamptz not null default now()
);

alter table public.scripts enable row level security;

-- Публичное чтение (как у cards/glossary/tools)
drop policy if exists "scripts_read_all" on public.scripts;
create policy "scripts_read_all" on public.scripts
  for select using (true);

-- Запись только для залогиненных пользователей
drop policy if exists "scripts_write_authed" on public.scripts;
create policy "scripts_write_authed" on public.scripts
  for all using (auth.role() = 'authenticated')
  with check (auth.role() = 'authenticated');
