-- =====================================================================
-- YAHYA Wiki: Техники продаж — Учебные модули
-- =====================================================================
-- Запустить ОДИН РАЗ в Supabase Dashboard → SQL Editor.
-- Создаёт 5 таблиц + RLS + функцию is_admin() + триггер на регистрацию.
--
-- ПОСЛЕ запуска: внизу файла раскомментируй блок «ПОВЫШЕНИЕ ДО АДМИНА»,
-- подставь свой email (текущий редактор) и запусти этот блок отдельно.
-- =====================================================================

-- ─── Таблицы ─────────────────────────────────────────────────────────

-- Темы (учебный контент)
create table if not exists public.techniques (
  id text primary key,                  -- '1.1', '1.2', '2.5' и т.д.
  data jsonb,                           -- {module, order, title, tagline, what, when, how, template, examples, anti, note}
  updated_at timestamptz not null default now()
);

-- Тесты (по одному на модуль)
create table if not exists public.quizzes (
  id text primary key,                  -- 'module1', 'module2'
  data jsonb,                           -- {title, intro, pass_score, questions:[{q, options:[{text, correct}]}]}
  updated_at timestamptz not null default now()
);

-- Профили (расширение auth.users): имя, филиал, роль
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  branch text,                          -- 'ЦУМ', 'Эркиндик', 'Азия Молл', ...
  role text not null default 'seller',  -- 'seller' | 'admin'
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

-- Прогресс по темам (что изучил юзер)
create table if not exists public.user_progress (
  user_id uuid not null references auth.users(id) on delete cascade,
  technique_id text not null references public.techniques(id) on delete cascade,
  completed_at timestamptz not null default now(),
  primary key (user_id, technique_id)
);

-- Попытки тестов (история всех попыток для аналитики)
create table if not exists public.quiz_attempts (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  quiz_id text not null references public.quizzes(id) on delete cascade,
  score int not null,                   -- кол-во правильных
  total int not null,                   -- всего вопросов
  passed bool not null,                 -- score / total >= порог
  answers jsonb,                        -- {[idx]: option_idx} — для разбора админом
  attempted_at timestamptz not null default now()
);

-- Индексы
create index if not exists idx_user_progress_user on public.user_progress(user_id);
create index if not exists idx_quiz_attempts_user on public.quiz_attempts(user_id);
create index if not exists idx_quiz_attempts_user_quiz_time
  on public.quiz_attempts(user_id, quiz_id, attempted_at desc);

-- ─── Функция: проверка прав админа ───────────────────────────────────

create or replace function public.is_admin()
returns boolean
language sql
security definer
stable
set search_path = public
as $$
  select coalesce((
    select role = 'admin' from public.profiles where id = auth.uid()
  ), false);
$$;

-- ─── Row Level Security ──────────────────────────────────────────────

alter table public.techniques enable row level security;
alter table public.quizzes enable row level security;
alter table public.profiles enable row level security;
alter table public.user_progress enable row level security;
alter table public.quiz_attempts enable row level security;

-- techniques: читает любой; пишет только admin
drop policy if exists techniques_read on public.techniques;
create policy techniques_read on public.techniques
  for select using (true);

drop policy if exists techniques_write on public.techniques;
create policy techniques_write on public.techniques
  for all using (public.is_admin()) with check (public.is_admin());

-- quizzes: читают только authenticated (чтобы вопросы не видели в гостях); пишет admin
drop policy if exists quizzes_read on public.quizzes;
create policy quizzes_read on public.quizzes
  for select using (auth.role() = 'authenticated');

drop policy if exists quizzes_write on public.quizzes;
create policy quizzes_write on public.quizzes
  for all using (public.is_admin()) with check (public.is_admin());

-- profiles: каждый видит свой; admin видит всех; админ менять любые,
-- пользователь — только свои поля (но не role)
drop policy if exists profiles_read_self_or_admin on public.profiles;
create policy profiles_read_self_or_admin on public.profiles
  for select using (auth.uid() = id or public.is_admin());

drop policy if exists profiles_insert_admin on public.profiles;
create policy profiles_insert_admin on public.profiles
  for insert with check (public.is_admin() or auth.uid() = id);

drop policy if exists profiles_update_self on public.profiles;
create policy profiles_update_self on public.profiles
  for update using (auth.uid() = id) with check (auth.uid() = id);

drop policy if exists profiles_admin_all on public.profiles;
create policy profiles_admin_all on public.profiles
  for all using (public.is_admin()) with check (public.is_admin());

drop policy if exists profiles_delete_admin on public.profiles;
create policy profiles_delete_admin on public.profiles
  for delete using (public.is_admin());

-- user_progress: пользователь видит свой, пишет/удаляет свой; admin — всё
drop policy if exists progress_read on public.user_progress;
create policy progress_read on public.user_progress
  for select using (auth.uid() = user_id or public.is_admin());

drop policy if exists progress_insert on public.user_progress;
create policy progress_insert on public.user_progress
  for insert with check (auth.uid() = user_id);

drop policy if exists progress_delete on public.user_progress;
create policy progress_delete on public.user_progress
  for delete using (auth.uid() = user_id or public.is_admin());

-- quiz_attempts: пользователь видит свои, пишет свои; admin — всё
drop policy if exists attempts_read on public.quiz_attempts;
create policy attempts_read on public.quiz_attempts
  for select using (auth.uid() = user_id or public.is_admin());

drop policy if exists attempts_insert on public.quiz_attempts;
create policy attempts_insert on public.quiz_attempts
  for insert with check (auth.uid() = user_id);

-- ─── Триггер: создание profile при регистрации ───────────────────────

create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  insert into public.profiles (id, full_name, role)
  values (
    new.id,
    coalesce(new.raw_user_meta_data->>'full_name', split_part(new.email, '@', 1)),
    'seller'
  )
  on conflict (id) do nothing;
  return new;
end;
$$;

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- =====================================================================
-- ПОВЫШЕНИЕ СУЩЕСТВУЮЩЕГО АККАУНТА ДО АДМИНА
-- =====================================================================
-- Запустить ОТДЕЛЬНО, после основной миграции выше.
-- Создаёт профиль с role=admin, или обновляет существующий.

insert into public.profiles (id, full_name, role)
select id, coalesce(raw_user_meta_data->>'full_name', email), 'admin'
from auth.users
where email = 'muhitdin.yahya@gmail.com'
on conflict (id) do update set role = 'admin', updated_at = now();

-- Проверка результата:
-- select u.email, p.role, p.full_name
-- from auth.users u left join public.profiles p on p.id = u.id;
