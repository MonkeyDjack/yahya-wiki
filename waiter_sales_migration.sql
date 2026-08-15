-- =====================================================================
-- ЛИЧНЫЕ ПРОДАЖИ ПО QR (данные из 1С ЯРОС)
-- Запустить ОДИН РАЗ в Supabase Dashboard → SQL Editor.
-- Безопасно к повторному запуску (idempotent).
-- =====================================================================
-- Сюда GitHub Action приватного репозитория yahya-yaros-data ежедневно
-- заливает выручку, привязанную СКАНИРОВАНИЕМ QR: сотрудник отсканировал
-- свой код на кассе — чек засчитан ему.
--
-- Почему только сканы. В 1С чек может просто осесть на карточке, которая
-- стояла на кассе (администратор, «Вынос ЦУМ»), — это не личная продажа.
-- Признак скана: шапка чека (Чек.Официант) и табличная часть
-- (ОбслуживающиеЛица) расходятся. Разбор — D:\dashboard\ЯРОС_подключение_и_находки.md §3.
--
-- ⚠ Ключ связи — qr_id, то есть реквизит «UIN» карточки физлица в 1С.
-- Это НЕ ссылка элемента справочника: у человека в 1С два разных GUID,
-- и в продажах лежит именно ссылка. Сопоставление ссылка → UIN делает
-- выгрузка справочника (ref_waiters.csv, колонка UIN). Перепутать их
-- означает показать сотруднику чужие продажи.

create table if not exists public.waiter_sales (
  qr_id      text        not null,          -- = profiles.qr_id (UIN из 1С)
  day        date        not null,
  branch     text        not null default '',
  checks     integer     not null default 0,
  revenue    numeric(14,2) not null default 0,
  updated_at timestamptz not null default now(),
  primary key (qr_id, day, branch)
);

comment on table public.waiter_sales is
  'Выручка сотрудника, привязанная сканированием QR. Заливает GitHub Action из 1С ЯРОС. Ключ — profiles.qr_id (реквизит UIN карточки физлица).';

create index if not exists waiter_sales_qr_day on public.waiter_sales (qr_id, day);

alter table public.waiter_sales enable row level security;

-- ---------------------------------------------------------------------
-- Свой qr_id — через SECURITY DEFINER, а не подзапросом в политике:
-- иначе политика читала бы profiles под правами самого пользователя
-- и зависела от политик на profiles.
-- ---------------------------------------------------------------------
create or replace function public.my_qr_id()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select qr_id from public.profiles where id = auth.uid();
$$;

-- Читает: только свои строки. Админ — все (для дашборда сотрудников).
-- Если qr_id у профиля пуст, сравнение даёт NULL и строк не будет — это и нужно.
drop policy if exists waiter_sales_read on public.waiter_sales;
create policy waiter_sales_read on public.waiter_sales
  for select using (qr_id = public.my_qr_id() or public.is_admin());

-- ⚠ Политик на запись НЕТ намеренно: писать может только service_role,
-- который RLS обходит. Ключ лежит секретом GitHub Action и в вики не попадает —
-- иначе любой посетитель публичного сайта мог бы дорисовать себе выручку.

-- =====================================================================
-- ПРОВЕРКА
-- =====================================================================
-- Сколько всего и за какой период:
-- select count(*), min(day), max(day), sum(revenue) from public.waiter_sales;
--
-- Кто сколько за текущий месяц (под админом):
-- select p.full_name, p.branch, sum(w.checks) checks, sum(w.revenue) revenue
-- from public.waiter_sales w
-- left join public.profiles p on p.qr_id = w.qr_id
-- where w.day >= date_trunc('month', current_date)
-- group by 1,2 order by revenue desc;
--
-- Строки без сотрудника в вики (в 1С скан есть, аккаунта нет):
-- select w.qr_id, sum(w.revenue) from public.waiter_sales w
-- left join public.profiles p on p.qr_id = w.qr_id
-- where p.id is null group by 1 order by 2 desc;
