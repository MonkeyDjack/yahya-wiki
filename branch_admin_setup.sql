-- =====================================================================
-- ПЕРЕВОД АДМИНИСТРАТОРОВ ТОЧЕК В РОЛЬ branch_admin
-- Запускать ПОСЛЕ branch_admin_migration.sql, в SQL Editor.
-- =====================================================================
-- Четыре карточки согласованы с владельцем 15.08.2026 (см. §3 находок по ЯРОС).
-- Филиал у каждого посчитан по фактическим чекам за 30 дней до 16.08.2026.
--
-- Написание филиала — единое по всей системе (приставка «Склад» из 1С срезается
-- на чтении: norm_branch в dashboard_v2/yaros/config.py и push_waiter_sales.py).
-- Регистр не важен, сравнение идёт через upper(). Допустимые значения ровно семь:
--   NGROUP | АЗБУКА | АЭРОПОРТ | Бишкек Парк | АЗИЯ МОЛЛ | ЦУМ | ЭРКИНДИК

-- ---------------------------------------------------------------------
-- ШАГ 1. Посмотреть, кого мы собираемся трогать
-- ---------------------------------------------------------------------
-- Выполнить отдельно и глазами проверить, что нашёлся ровно тот человек.
-- Фамилии сверяем осторожно: в базе есть «Костёрный» и «Костерный» (е/ё),
-- а также однофамильцы — Эсембаева Алия и Эсембаева Альбина.
select id, full_name, role, branch, coalesce(nullif(btrim(qr_id), ''), '(нет QR)') as qr
  from public.profiles
 where full_name ilike '%Костёрн%' or full_name ilike '%Костерн%'
    or full_name ilike '%Абдулаева%'
    or full_name ilike '%Исаев%'
    or full_name ilike '%Ушурова%'
 order by full_name;

-- ---------------------------------------------------------------------
-- ШАГ 2. Перевод
-- ---------------------------------------------------------------------
-- Обновляет по ФИО, но с защитой: если под шаблон попал не один человек,
-- а ноль или несколько — ничего не меняется и выводится ошибка. Переводить
-- «примерно того» нельзя: роль даёт доступ к чужим продажам.
do $$
declare
  target record;
  hit    uuid;
  cnt    int;
begin
  for target in
    select * from (values
      ('%Костёрн%',   'АЭРОПОРТ'),
      ('%Абдулаева%', 'ЭРКИНДИК'),
      ('%Исаев%',     'ЦУМ'),
      ('%Ушурова%',   'АЗИЯ МОЛЛ')
    ) as t(pattern, branch)
  loop
    select count(*) into cnt from public.profiles p where p.full_name ilike target.pattern;

    if cnt = 0 and target.pattern = '%Костёрн%' then
      -- «ё» в базе может быть записана как «е» — пробуем второй вариант
      select count(*) into cnt from public.profiles p where p.full_name ilike '%Костерн%';
      if cnt = 1 then
        select p.id into hit from public.profiles p where p.full_name ilike '%Костерн%';
        update public.profiles
           set role = 'branch_admin', branch = target.branch, updated_at = now()
         where id = hit;
        raise notice 'переведён (через «е»): % -> %', target.pattern, target.branch;
        continue;
      end if;
    end if;

    if cnt = 1 then
      select p.id into hit from public.profiles p where p.full_name ilike target.pattern;
      update public.profiles
         set role = 'branch_admin', branch = target.branch, updated_at = now()
       where id = hit;
      raise notice 'переведён: % -> %', target.pattern, target.branch;
    elsif cnt = 0 then
      raise warning 'НЕ НАЙДЕН: % — аккаунта в вики нет, заведите его сначала', target.pattern;
    else
      raise warning 'НЕОДНОЗНАЧНО: % — подходит % человек, переведите вручную по id',
                    target.pattern, cnt;
    end if;
  end loop;
end $$;

-- ---------------------------------------------------------------------
-- ШАГ 3. Проверка
-- ---------------------------------------------------------------------
select role, branch, count(*), string_agg(full_name, ', ' order by full_name) as кто
  from public.profiles
 group by role, branch
 order by role, branch;

-- Владелец обязан остаться 'admin' — иначе управление пользователями
-- пропадёт у всех сразу:
-- select full_name, role from public.profiles where role = 'admin';

-- Кому филиал в профиле проставлен не так, как показывают чеки
-- (заполнится после первой заливки branch_staff):
-- select * from public.branch_admin_mismatch;

-- ---------------------------------------------------------------------
-- ШАГ 4. Остальные профили — привести филиал к написанию из данных
-- ---------------------------------------------------------------------
-- До сих пор profiles.branch нигде не использовался и заполнялся свободно
-- («ЦУМ», «Азия Молл»). Теперь это ключ ограничения, и написание должно
-- совпадать с 1С. Сначала посмотреть, что вообще стоит:
--
-- select branch, count(*) from public.profiles group by 1 order by 2 desc;
--
-- Потом привести (проверив, что в левой части — реально встречающиеся значения):
-- update public.profiles set branch = 'ЦУМ'       where upper(btrim(branch)) in ('ЦУМ', 'СКЛАД ЦУМ');
-- update public.profiles set branch = 'АЗИЯ МОЛЛ' where upper(btrim(branch)) in ('АЗИЯ МОЛЛ', 'СКЛАД АЗИЯ МОЛЛ');
