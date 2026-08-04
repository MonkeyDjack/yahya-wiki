-- =====================================================================
-- УПРАВЛЕНИЕ АККАУНТАМИ ИЗ ВИКИ (админ):
--   удаление · сброс пароля · смена логина · список email'ов
-- Запустить ОДИН РАЗ в Supabase Dashboard → SQL Editor.
-- Безопасно к повторному запуску (idempotent) — можно перезапускать
-- после обновлений этого файла.
-- =====================================================================
-- Зачем: anon-ключ в браузере не может удалять пользователей из Auth,
-- менять чужие пароли и логины — это операции service_role. Эти
-- SECURITY DEFINER функции выполняются с правами владельца БД и сами
-- проверяют is_admin(): с пользой вызвать их может только залогиненный
-- админ. Аккаунты с role='admin' функции не трогают — владельца нельзя
-- удалить или перехватить с сайта, только через Supabase Dashboard.

-- 1) Удаление аккаунта сотрудника --------------------------------------
-- profiles / user_progress / quiz_attempts / activity_log / script_ack
-- удаляются каскадом — все ссылаются на auth.users(id) on delete cascade.
create or replace function public.admin_delete_user(target_user uuid)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  target_role text;
begin
  if not public.is_admin() then
    raise exception 'Удалять аккаунты может только администратор';
  end if;
  if target_user = auth.uid() then
    raise exception 'Нельзя удалить собственный аккаунт';
  end if;
  select p.role into target_role from public.profiles p where p.id = target_user;
  if target_role = 'admin' then
    raise exception 'Аккаунт админа удаляется только через Supabase Dashboard';
  end if;
  delete from auth.users where id = target_user;
  if not found then
    raise exception 'Пользователь не найден';
  end if;
end;
$$;

revoke all on function public.admin_delete_user(uuid) from public, anon;
grant execute on function public.admin_delete_user(uuid) to authenticated;

-- 2) Сброс пароля сотрудника -------------------------------------------
-- Продавцы входят по логинам вида name@yahya.local — почты нет, recovery-
-- письмо отправить некуда. Поэтому пароль задаёт админ прямо из дашборда.
-- GoTrue хранит пароль bcrypt-хэшем в auth.users.encrypted_password —
-- пишем туда crypt(...) из pgcrypto (в Supabase живёт в схеме extensions).
create or replace function public.admin_set_user_password(target_user uuid, new_password text)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  target_role text;
begin
  if not public.is_admin() then
    raise exception 'Менять пароли может только администратор';
  end if;
  if length(coalesce(new_password, '')) < 6 then
    raise exception 'Пароль минимум 6 символов';
  end if;
  select p.role into target_role from public.profiles p where p.id = target_user;
  if target_role = 'admin' and target_user <> auth.uid() then
    raise exception 'Пароль другого админа меняется только через Supabase Dashboard';
  end if;
  update auth.users
     set encrypted_password = extensions.crypt(new_password, extensions.gen_salt('bf')),
         updated_at = now()
   where id = target_user;
  if not found then
    raise exception 'Пользователь не найден';
  end if;
end;
$$;

revoke all on function public.admin_set_user_password(uuid, text) from public, anon;
grant execute on function public.admin_set_user_password(uuid, text) to authenticated;

-- 3) Смена логина (email) ----------------------------------------------
-- Старые аккаунты заведены с опечатками и сокращениями — чиним прямо из
-- вики. Кроме auth.users надо обновить копию адреса в auth.identities,
-- иначе вход по новому логину может не сработать.
create or replace function public.admin_set_user_email(target_user uuid, new_email text)
returns void
language plpgsql
security definer
set search_path = public
as $$
declare
  target_role text;
  clean_email text;
begin
  if not public.is_admin() then
    raise exception 'Менять логины может только администратор';
  end if;
  clean_email := lower(trim(coalesce(new_email, '')));
  if clean_email !~ '^[a-z0-9._+-]+@[a-z0-9.-]+\.[a-z]{2,}$' then
    raise exception 'Неверный формат email: %', clean_email;
  end if;
  select p.role into target_role from public.profiles p where p.id = target_user;
  if target_role = 'admin' and target_user <> auth.uid() then
    raise exception 'Логин другого админа меняется только через Supabase Dashboard';
  end if;
  if exists (select 1 from auth.users u where lower(u.email::text) = clean_email and u.id <> target_user) then
    raise exception 'Этот логин уже занят';
  end if;
  update auth.users
     set email = clean_email,
         updated_at = now()
   where id = target_user;
  if not found then
    raise exception 'Пользователь не найден';
  end if;
  update auth.identities
     set identity_data = jsonb_set(identity_data, '{email}', to_jsonb(clean_email)),
         updated_at = now()
   where user_id = target_user and provider = 'email';
end;
$$;

revoke all on function public.admin_set_user_email(uuid, text) from public, anon;
grant execute on function public.admin_set_user_email(uuid, text) to authenticated;

-- 4) Список аккаунтов: email + последний вход ---------------------------
-- profiles не хранит email (он в auth.users, куда фронту нельзя), поэтому
-- дашборд получает логины через эту функцию. Не-админу возвращает пустой
-- список — where-условие, без ошибки.
create or replace function public.admin_list_auth_users()
returns table(id uuid, email text, created_at timestamptz, last_sign_in_at timestamptz)
language sql
security definer
set search_path = public
as $$
  select u.id, u.email::text, u.created_at, u.last_sign_in_at
  from auth.users u
  where public.is_admin();
$$;

revoke all on function public.admin_list_auth_users() from public, anon;
grant execute on function public.admin_list_auth_users() to authenticated;

-- =====================================================================
-- ПРОВЕРКА (под своим админ-аккаунтом из вики, НЕ из SQL Editor —
-- в SQL Editor auth.uid() пуст и is_admin() вернёт false):
--   select * from public.admin_list_auth_users();
--   select public.admin_set_user_password('<uuid>', 'новый_пароль');
-- Список установленных функций (можно из SQL Editor):
--   select proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace
--    where n.nspname = 'public' and proname like 'admin_%';
-- =====================================================================
