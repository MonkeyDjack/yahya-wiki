-- =====================================================================
-- QR-КОДЫ ПРОДАВЦОВ (1С) + ДОЛЖНОСТЬ В ПРОФИЛЕ
-- Запустить ОДИН РАЗ в Supabase Dashboard → SQL Editor.
-- Безопасно к повторному запуску (idempotent).
-- =====================================================================

-- 1) Новые поля профиля -----------------------------------------------
-- qr_id    — GUID сотрудника из 1С. Именно он кодируется в QR как {"id":"<guid>"}.
-- job_title — должность из штатки (ПК, бариста, админ, техничка...).
--             Названа job_title, а не position: position — ключевое слово SQL.
alter table public.profiles add column if not exists qr_id     text;
alter table public.profiles add column if not exists job_title text;

comment on column public.profiles.qr_id is
  'GUID сотрудника из 1С. QR на бейдже содержит {"id":"<qr_id>"}. Менять может только админ.';

-- Один GUID = один сотрудник. Дубликат означал бы, что продажи двоих
-- сливаются на один код — ловим это на уровне БД, а не глазами.
create unique index if not exists profiles_qr_id_uniq
  on public.profiles (qr_id) where qr_id is not null;

-- 2) Защита привилегированных полей ------------------------------------
-- Политика profiles_update_self разрешает пользователю править свою строку
-- целиком. Без этого триггера продавец мог бы из консоли браузера:
--   • подставить себе чужой qr_id → продажи коллеги улетают ему в бонус;
--   • выставить себе role='admin' → полный доступ ко всей вики.
-- Триггер режет оба сценария: менять qr_id / role может только админ.
create or replace function public.guard_profile_privileged_fields()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  -- auth.uid() пуст = запрос идёт под service_role или из SQL Editor (наши же
  -- скрипты массового завода сотрудников). Из браузера uid всегда заполнен,
  -- а анонима до profiles всё равно не пускает RLS — дыры здесь нет.
  if auth.uid() is null or public.is_admin() then
    return new;
  end if;
  if new.qr_id is distinct from old.qr_id then
    raise exception 'qr_id может менять только администратор';
  end if;
  if new.role is distinct from old.role then
    raise exception 'role может менять только администратор';
  end if;
  return new;
end;
$$;

drop trigger if exists profiles_guard_privileged on public.profiles;
create trigger profiles_guard_privileged
  before update on public.profiles
  for each row execute procedure public.guard_profile_privileged_fields();

-- =====================================================================
-- ПРОВЕРКА
-- =====================================================================
-- select full_name, branch, job_title, role, qr_id
-- from public.profiles
-- where branch = 'ЦУМ'
-- order by full_name;
