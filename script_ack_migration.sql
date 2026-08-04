-- =====================================================================
-- ОЗНАКОМЛЕНИЕ СО СКРИПТАМИ ПРОДАЖ
-- Запустить ОДИН РАЗ в Supabase Dashboard → SQL Editor.
-- Безопасно к повторному запуску (idempotent).
-- =====================================================================
-- Сотрудник отмечает «я ознакомился» внизу вкладки скриптов — отдельно
-- по каждому разделу: У кассы (retail) / У столиков (bar) / Общее (common).
-- Руководитель видит отметки в дашборде сотрудников и в карточке сотрудника.

create table if not exists public.script_ack (
  user_id      uuid not null references auth.users(id) on delete cascade,
  section      text not null check (section in ('retail','bar','common')),
  confirmed_at timestamptz not null default now(),
  primary key (user_id, section)
);

alter table public.script_ack enable row level security;

-- Читает: сам себя или админ
drop policy if exists script_ack_read on public.script_ack;
create policy script_ack_read on public.script_ack
  for select using (auth.uid() = user_id or public.is_admin());

-- Отметиться может только сам за себя
drop policy if exists script_ack_insert on public.script_ack;
create policy script_ack_insert on public.script_ack
  for insert with check (auth.uid() = user_id);

-- Снять отметку: сам (ошибся) или админ (скрипты сильно обновились)
drop policy if exists script_ack_delete on public.script_ack;
create policy script_ack_delete on public.script_ack
  for delete using (auth.uid() = user_id or public.is_admin());

-- =====================================================================
-- ПРОВЕРКА
-- =====================================================================
-- select p.full_name, a.section, a.confirmed_at
-- from public.script_ack a join public.profiles p on p.id = a.user_id
-- order by a.confirmed_at desc;
