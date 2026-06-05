-- ════════════════════════════════════════════════════════════════
-- ЖУРНАЛ АКТИВНОСТИ (входы сотрудников на сайт)
-- Запустить один раз: Supabase Dashboard → SQL Editor → New query → вставить → Run
-- ════════════════════════════════════════════════════════════════

create table if not exists public.activity_log (
  id         bigint generated always as identity primary key,
  user_id    uuid not null references auth.users(id) on delete cascade,
  event      text not null,                       -- 'login' (вход по паролю) | 'visit' (открыл сайт с сохранённой сессией)
  created_at timestamptz not null default now()
);

create index if not exists activity_log_user_idx    on public.activity_log (user_id, created_at desc);
create index if not exists activity_log_created_idx on public.activity_log (created_at desc);

alter table public.activity_log enable row level security;

-- Каждый авторизованный пишет ТОЛЬКО свои события
drop policy if exists "activity insert own" on public.activity_log;
create policy "activity insert own" on public.activity_log
  for insert to authenticated
  with check (auth.uid() = user_id);

-- Читает: юзер — своё, админ — всё (is_admin() уже создана в techniques_migration.sql)
drop policy if exists "activity read own or admin" on public.activity_log;
create policy "activity read own or admin" on public.activity_log
  for select to authenticated
  using (auth.uid() = user_id or public.is_admin());

-- Удалять/менять записи журнала нельзя никому (политик на update/delete нет)
