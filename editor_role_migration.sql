-- =====================================================================
-- Роль «editor»: может редактировать темы и тесты, НЕ может удалять.
-- Существующие 'admin' остаются с полными правами.
-- 'seller' остаётся read-only.
-- =====================================================================

-- Helper: может ли текущий юзер редактировать контент?
create or replace function public.can_edit_content()
returns boolean
language sql
security definer
stable
set search_path = public
as $$
  select coalesce((
    select role in ('admin', 'editor') from public.profiles where id = auth.uid()
  ), false);
$$;

-- ─── TECHNIQUES ──────────────────────────────────────────────────────
-- Сбрасываем старую общую политику "for all"
drop policy if exists techniques_write on public.techniques;

-- INSERT / UPDATE: admin или editor
drop policy if exists techniques_insert on public.techniques;
create policy techniques_insert on public.techniques
  for insert with check (public.can_edit_content());

drop policy if exists techniques_update on public.techniques;
create policy techniques_update on public.techniques
  for update using (public.can_edit_content()) with check (public.can_edit_content());

-- DELETE: только admin
drop policy if exists techniques_delete on public.techniques;
create policy techniques_delete on public.techniques
  for delete using (public.is_admin());

-- ─── QUIZZES ─────────────────────────────────────────────────────────
drop policy if exists quizzes_write on public.quizzes;

drop policy if exists quizzes_insert on public.quizzes;
create policy quizzes_insert on public.quizzes
  for insert with check (public.can_edit_content());

drop policy if exists quizzes_update on public.quizzes;
create policy quizzes_update on public.quizzes
  for update using (public.can_edit_content()) with check (public.can_edit_content());

drop policy if exists quizzes_delete on public.quizzes;
create policy quizzes_delete on public.quizzes
  for delete using (public.is_admin());

-- Готово. Проверка:
--   select public.can_edit_content();  -- должно вернуть true когда залогинен админ или editor
--   select public.is_admin();          -- только true для admin
