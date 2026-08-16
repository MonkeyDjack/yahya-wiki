-- =====================================================================
-- КАБИНЕТ АДМИНИСТРАТОРА ФИЛИАЛА
-- Запустить ОДИН РАЗ в Supabase Dashboard → SQL Editor.
-- Безопасно к повторному запуску (idempotent).
-- =====================================================================
-- Зачем отдельная роль. До этой миграции `role` принимал только 'seller'
-- и 'admin', а is_admin() = (role = 'admin'). То есть администратор точки,
-- заведённый как 'admin', получал права владельца: RLS отдавал ему ВСЕ строки
-- waiter_sales, весь список profiles и функции управления пользователями.
-- Ограничение «видит только свой филиал» в таком виде было бы нарисовано
-- в интерфейсе, но не существовало на деле: ключ и код страницы публичные,
-- любой админ точки вытащил бы всю сеть прямым запросом к API.
--
-- Поэтому роль 'branch_admin' — настоящая граница, проверяемая в политиках.
--
-- ⚠ Ключ ограничения — profiles.branch САМОГО администратора. Это поле
-- заполняется руками и уже врало (у одного сотрудника в профиле ЦУМ, а продажи
-- в Эркиндике). Поставить неверный филиал = показать человеку чужую точку.
-- Расхождение с фактом ловится отдельно: см. branch_staff и представление
-- branch_admin_mismatch в конце файла.

-- ---------------------------------------------------------------------
-- 1. Роль
-- ---------------------------------------------------------------------
-- CHECK добавляем только если текущие данные в него укладываются: иначе
-- миграция упала бы на живой базе из-за одной строки с опечаткой.
do $$
declare bad int;
begin
  select count(*) into bad
    from public.profiles
   where role is not null
     and role not in ('seller', 'admin', 'branch_admin');
  if bad = 0 then
    alter table public.profiles drop constraint if exists profiles_role_check;
    alter table public.profiles
      add constraint profiles_role_check
      check (role in ('seller', 'admin', 'branch_admin'));
  else
    raise notice 'CHECK на role НЕ добавлен: % строк с посторонним значением', bad;
  end if;
end $$;

-- ---------------------------------------------------------------------
-- 2. Функции доступа
-- ---------------------------------------------------------------------
-- SECURITY DEFINER, как и is_admin(): иначе функция читала бы profiles под
-- правами вызывающего и зависела бы от политик на самой profiles.

create or replace function public.is_branch_admin()
returns boolean
language sql
security definer
stable
set search_path = public
as $$
  select coalesce((
    select role = 'branch_admin' from public.profiles where id = auth.uid()
  ), false);
$$;

-- Филиал текущего пользователя, приведённый к сравнимому виду.
-- btrim обязателен: в 1С встречаются имена с хвостовым пробелом («Аэропорт »).
-- upper — потому что в данных филиалы заглавными («АЗИЯ МОЛЛ»), а в профилях
-- их заводили по-человечески («Азия Молл»). Сравнение без регистра снимает
-- этот класс ошибок навсегда: иначе одна строчная буква = пустой кабинет.
create or replace function public.my_branch()
returns text
language sql
security definer
stable
set search_path = public
as $$
  select upper(btrim(coalesce(branch, ''))) from public.profiles where id = auth.uid();
$$;

-- Видит ли текущий пользователь данные филиала. Владелец — все, админ
-- точки — только свой. Пустой филиал не открывает ничего: btrim('') = ''
-- не совпадёт ни с одной строкой, где филиал заполнен.
create or replace function public.can_see_branch(b text)
returns boolean
language sql
security definer
stable
set search_path = public
as $$
  select public.is_admin()
      or (public.is_branch_admin()
          and public.my_branch() <> ''
          and upper(btrim(coalesce(b, ''))) = public.my_branch());
$$;

-- ---------------------------------------------------------------------
-- 3. Выручка филиала по дням
-- ---------------------------------------------------------------------
-- Источник — day_branch_*.csv приватного репозитория (уже выгружается
-- ежедневно). Скидка нужна отдельной колонкой: это точка контроля кассы,
-- и в сумме выручки её не видно.
create table if not exists public.branch_sales (
  day        date        not null,
  branch     text        not null,
  checks     integer     not null default 0,
  revenue    numeric(14,2) not null default 0,   -- «Всего», то есть после скидки
  discount   numeric(14,2) not null default 0,
  updated_at timestamptz not null default now(),
  primary key (day, branch)
);

comment on table public.branch_sales is
  'Выручка, чеки и скидки филиала по дням. Заливает GitHub Action из 1С ЯРОС (day_branch).';

create index if not exists branch_sales_branch_day on public.branch_sales (branch, day);

alter table public.branch_sales enable row level security;

drop policy if exists branch_sales_read on public.branch_sales;
create policy branch_sales_read on public.branch_sales
  for select using (public.can_see_branch(branch));

-- ---------------------------------------------------------------------
-- 4. Топ позиций филиала за месяц
-- ---------------------------------------------------------------------
-- Считается заранее и хранится готовым: day_item_*.csv весит больше мегабайта
-- в месяц, тянуть его в браузер незачем — в кабинете нужны десять строк.
create table if not exists public.branch_top_items (
  month      text        not null,               -- 'YYYY-MM'
  branch     text        not null,
  rank       smallint    not null,               -- 1..10
  item       text        not null,
  qty        numeric(14,3) not null default 0,
  revenue    numeric(14,2) not null default 0,
  updated_at timestamptz not null default now(),
  primary key (month, branch, rank)
);

comment on table public.branch_top_items is
  'Топ-10 позиций филиала за месяц по выручке. Заливает GitHub Action из 1С ЯРОС (day_item).';

alter table public.branch_top_items enable row level security;

drop policy if exists branch_top_items_read on public.branch_top_items;
create policy branch_top_items_read on public.branch_top_items
  for select using (public.can_see_branch(branch));

-- ---------------------------------------------------------------------
-- 5. Состав филиала и пробелы привязки
-- ---------------------------------------------------------------------
-- Филиал определяется ПО ФАКТУ: где за последние 30 дней были чеки человека,
-- та точка и его. В справочнике физлиц 1С филиала нет вообще, так что другого
-- способа не существует — и это же соответствует тому, как считается рейтинг.
--
-- Три состояния, которые нельзя путать (чинятся в разных местах):
--   no_uin      — карточка в 1С есть, UIN пуст: человек физически не может
--                 отсканировать. Чинится в 1С, в карточке физлица.
--   no_account  — UIN есть, аккаунта в вики нет: продажи копятся, владелец
--                 их не видит. Чинится заведением аккаунта.
--   no_qr_link  — аккаунт есть, qr_id пуст: сканы не найдут владельца.
--                 Чинится привязкой карточки в админке.
--   ok          — всё связано.
create table if not exists public.branch_staff (
  branch       text        not null,
  code         text        not null,             -- код карточки физлица в 1С
  full_name    text        not null default '',
  qr_id        text        not null default '',
  status       text        not null check (status in ('ok','no_uin','no_account','no_qr_link')),
  days_worked  integer     not null default 0,   -- дней с чеками за окно
  last_day     date,
  updated_at   timestamptz not null default now(),
  primary key (branch, code)
);

comment on table public.branch_staff is
  'Состав филиала по фактическим чекам за 30 дней и состояние привязки QR/аккаунта. Заливает GitHub Action.';

alter table public.branch_staff enable row level security;

drop policy if exists branch_staff_read on public.branch_staff;
create policy branch_staff_read on public.branch_staff
  for select using (public.can_see_branch(branch));

-- ⚠ Политик на запись у всех трёх таблиц НЕТ намеренно: пишет только
-- service_role, который RLS обходит. Ключ лежит секретом GitHub Action.

-- ---------------------------------------------------------------------
-- 5a. Разовое: привести филиалы в уже залитых строках
-- ---------------------------------------------------------------------
-- waiter_sales наполняется с 15.08.2026 и успел набрать сырые имена из 1С.
-- Заливка теперь нормализует их сама (norm_branch в push_waiter_sales.py),
-- но старые строки надо поправить, иначе рейтинг точки будет разорван на две
-- половины — «ЦУМ» и «Склад ЦУМ» — и ни одна не покажет полную картину.
update public.waiter_sales set branch = 'ЦУМ'       where btrim(branch) = 'Склад ЦУМ';
update public.waiter_sales set branch = 'АЗИЯ МОЛЛ' where btrim(branch) = 'Склад Азия молл';
update public.waiter_sales set branch = 'ЭРКИНДИК'  where btrim(branch) = 'Эркиндик';
update public.waiter_sales set branch = 'АЭРОПОРТ'  where btrim(branch) = 'Аэропорт';
update public.waiter_sales set branch = 'NGROUP'    where btrim(branch) = 'Ngroup';
update public.waiter_sales set branch = 'АЗБУКА'    where btrim(branch) = 'Азбука';
update public.waiter_sales set branch = btrim(branch) where branch <> btrim(branch);

-- ---------------------------------------------------------------------
-- 6. Личные продажи: доступ администратору точки
-- ---------------------------------------------------------------------
-- В waiter_sales филиал хранится В КАЖДОЙ СТРОКЕ и берётся из чека, а не из
-- профиля. Поэтому «кто сканил на этой точке» получается само: вышел на
-- подмену в другой филиал — те дни видит админ той точки, и это правильно.
drop policy if exists waiter_sales_read on public.waiter_sales;
-- can_see_branch уже покрывает и владельца, и админа точки — отдельное
-- условие на is_admin() было бы лишним повторением той же проверки.
create policy waiter_sales_read on public.waiter_sales
  for select using (
    qr_id = public.my_qr_id()
    or public.can_see_branch(branch)
  );

-- ---------------------------------------------------------------------
-- 7. Обучение по СПИСОЧНОМУ составу филиала
-- ---------------------------------------------------------------------
-- Здесь наоборот — не по факту чеков, а по profiles.branch: тесты и скрипты
-- сдаёт тот, кто числится в филиале, даже если он в этом месяце не выходил.
--
-- Отдаём функцией, а не политикой на profiles: политика открыла бы админу
-- точки всю карточку сотрудника, включая qr_id. Функция отдаёт ровно те поля,
-- что нужны кабинету, и ничего сверх.
create or replace function public.branch_training()
returns table (
  user_id        uuid,
  full_name      text,
  role           text,
  techniques     bigint,   -- сколько техник отмечено пройденными
  quizzes_passed bigint,   -- сколько разных тестов сдано
  last_attempt   timestamptz,
  scripts        text[],   -- подтверждённые разделы скриптов
  has_qr         boolean
)
language sql
security definer
stable
set search_path = public
as $$
  select p.id,
         coalesce(p.full_name, ''),
         p.role,
         (select count(*) from public.user_progress up where up.user_id = p.id),
         (select count(distinct qa.quiz_id) from public.quiz_attempts qa
           where qa.user_id = p.id and qa.passed),
         (select max(qa.attempted_at) from public.quiz_attempts qa
           where qa.user_id = p.id),
         coalesce((select array_agg(sa.section order by sa.section)
                     from public.script_ack sa where sa.user_id = p.id), '{}'),
         coalesce(btrim(p.qr_id), '') <> ''
    from public.profiles p
   where public.can_see_branch(p.branch)
     and p.id <> auth.uid()          -- себя админ видит в своём блоке выше
   order by coalesce(p.full_name, '');
$$;

revoke all on function public.branch_training() from public;
grant execute on function public.branch_training() to authenticated;

-- ---------------------------------------------------------------------
-- 8. Расхождение профиля с фактом
-- ---------------------------------------------------------------------
-- Единственная защита от неверного profiles.branch. Смотреть владельцу:
-- если у человека в профиле один филиал, а чеки идут в другом, кабинет
-- покажет ему чужую точку — а при роли branch_admin ещё и чужие продажи.
-- security_invoker обязателен. Обычное представление выполняется с правами
-- своего владельца и RLS нижележащих таблиц не применяет — тогда любой
-- залогиненный пользователь прочитал бы через него весь список сотрудников
-- с филиалами. С этим флагом действуют политики самого читающего.
create or replace view public.branch_admin_mismatch
  with (security_invoker = true) as
  select p.id,
         p.full_name,
         p.role,
         btrim(coalesce(p.branch, '')) as branch_profile,
         s.branch                      as branch_fact,
         s.days_worked,
         s.last_day
    from public.profiles p
    join public.branch_staff s on s.qr_id = p.qr_id and s.qr_id <> ''
   where upper(btrim(coalesce(p.branch, ''))) <> upper(btrim(s.branch));

comment on view public.branch_admin_mismatch is
  'Кому в профиле проставлен не тот филиал, что в чеках. Проверять после заведения аккаунтов.';

-- =====================================================================
-- ПРОВЕРКА
-- =====================================================================
-- Кто сейчас с какой ролью:
-- select role, count(*) from public.profiles group by 1;
--
-- Сделать человека администратором точки (филиал должен быть заполнен!):
-- update public.profiles set role = 'branch_admin', branch = 'Азия Молл'
--  where id = '<uuid>';
--
-- У кого профиль расходится с фактом:
-- select * from public.branch_admin_mismatch;
--
-- Проверить границу под самим админом точки (в SQL Editor не сработает —
-- там auth.uid() пуст): зайти в вики его аккаунтом и выполнить в консоли
--   await supabase.from('branch_sales').select('branch').limit(500)
-- в ответе должен быть ровно один филиал.
