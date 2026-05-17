-- =====================================================================
-- Supabase Storage: bucket 'card-photos' для загрузки фото карточек товаров
-- =====================================================================
-- Запустить ОДИН РАЗ в Supabase Dashboard → SQL Editor.

-- 1) Создаём publicбакет (читает любой, пишет только authenticated)
insert into storage.buckets (id, name, public)
values ('card-photos', 'card-photos', true)
on conflict (id) do update set public = true;

-- 2) RLS для storage.objects
-- Чтение — всем (бакет публичный, но политика для security definer тоже нужна)
drop policy if exists "card-photos read" on storage.objects;
create policy "card-photos read" on storage.objects
  for select using (bucket_id = 'card-photos');

-- Загрузка — только authenticated юзеры (любой залогиненный, в т.ч. seller)
-- Если хочешь ограничить только admin/editor — замени auth.role() = 'authenticated'
-- на public.can_edit_content() (но тогда нужно убедиться что функция доступна в этом контексте).
drop policy if exists "card-photos insert" on storage.objects;
create policy "card-photos insert" on storage.objects
  for insert with check (bucket_id = 'card-photos' and auth.role() = 'authenticated');

-- Удаление — только admin (через public.is_admin())
drop policy if exists "card-photos delete" on storage.objects;
create policy "card-photos delete" on storage.objects
  for delete using (bucket_id = 'card-photos' and public.is_admin());

-- Update (на случай replace через upsert)
drop policy if exists "card-photos update" on storage.objects;
create policy "card-photos update" on storage.objects
  for update using (bucket_id = 'card-photos' and auth.role() = 'authenticated');

-- Проверка:
-- select * from storage.buckets where id = 'card-photos';
-- select * from storage.objects where bucket_id = 'card-photos' limit 5;
