-- ═══════════════════════════════════════════════════════════════════
-- FBSM · Модуль «График смен» — схема БД, версия 1
--
-- Скрипт ИДЕМПОТЕНТНЫЙ: можно запускать повторно без вреда.
-- Существующие таблицы (users, sales, plans, params, adjustments)
-- этот скрипт НЕ читает и НЕ изменяет.
-- ═══════════════════════════════════════════════════════════════════


-- ── 1. Справочник точек ────────────────────────────────────────────
-- shop = магазин из константы SHOPS программы ЗП.
-- NULL = неторговая точка (склад): в отчёты и планы продаж не попадает.

create table if not exists public.schedule_points (
  code   text primary key,
  name   text    not null,
  shop   text,
  city   text    not null,
  color  text    not null default '#185FA5',
  sort   int     not null default 100,
  active boolean not null default true
);

insert into public.schedule_points (code, name, shop, city, color, sort) values
  ('Р',  'Республики 21',  'Республика',   'Астана',    '#185FA5', 10),
  ('А',  'Асфендиярова 1', 'Асфендиярова', 'Астана',    '#639922', 20),
  ('М',  'Манаса 5',       'Манаса',       'Астана',    '#BA7517', 30),
  ('АТ', 'AtakentMALL',    'Алматы',       'Алматы',    '#A32D2D', 40),
  ('ГС', 'GrandStore',     'Караганда',    'Караганда', '#7A4FA3', 50),
  ('СК', 'Склад',           null,          'Астана',    '#888780', 60)
on conflict (code) do update set
  name  = excluded.name,
  shop  = excluded.shop,
  city  = excluded.city,
  color = excluded.color,
  sort  = excluded.sort;


-- ── 2. Справочник типов смены ──────────────────────────────────────
-- k               — коэффициент к окладу за смену (0.5 = полсмены)
-- counts_as_shift — попадает ли в число отработанных смен
-- needs_point     — нужно ли указывать точку (у отпуска и больничного — нет)

create table if not exists public.shift_types (
  code            text primary key,
  name            text    not null,
  short           text    not null,
  k               numeric not null default 1,
  counts_as_shift boolean not null default true,
  needs_point     boolean not null default true,
  color           text    not null default '#185FA5',
  sort            int     not null default 100
);

insert into public.shift_types (code, name, short, k, counts_as_shift, needs_point, color, sort) values
  ('full',     'Полная смена', '1',   1.0, true,  true,  '#185FA5', 10),
  ('half',     'Полсмены',     '½',   0.5, true,  true,  '#5A8FC4', 20),
  ('trainee',  'Стажировка',   'Ст',  1.0, true,  true,  '#BA7517', 30),
  ('vacation', 'Отпуск',       'Отп', 0.0, false, false, '#639922', 40),
  ('sick',     'Больничный',   'Б',   0.0, false, false, '#A32D2D', 50)
on conflict (code) do update set
  name            = excluded.name,
  short           = excluded.short,
  k               = excluded.k,
  counts_as_shift = excluded.counts_as_shift,
  needs_point     = excluded.needs_point,
  color           = excluded.color,
  sort            = excluded.sort;


-- ── 3. График ──────────────────────────────────────────────────────
-- Одна строка = один сотрудник × один день.
--
-- planned_point — поставил человек заранее (ПЛАН)
-- actual_point  — проставилось по факту (ФАКТ)
-- Две колонки специально: иначе автоотметка затрёт план
-- и невыход станет невидимым.
--
-- actual_source: 'sales'  — проставлено автоматически по вводу продаж
--                'manual' — проставлено руками
--
-- Внешнего ключа на users НЕТ намеренно:
--   1) не зависим от типа users.id;
--   2) удаление сотрудника не стирает историю его смен.

create table if not exists public.schedule (
  uid           text not null,
  date          date not null,
  shop          text,
  planned_point text references public.schedule_points(code),
  actual_point  text references public.schedule_points(code),
  shift_type    text not null default 'full' references public.shift_types(code),
  actual_source text,
  note          text,
  updated_at    timestamptz not null default now(),
  updated_by    text,
  primary key (uid, date)
);

create index if not exists schedule_shop_date_idx on public.schedule (shop, date);
create index if not exists schedule_date_idx      on public.schedule (date);
create index if not exists schedule_uid_date_idx  on public.schedule (uid, date);


-- ── 4. Автообновление updated_at ───────────────────────────────────

create or replace function public.schedule_touch()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end $$;

drop trigger if exists schedule_touch_trg on public.schedule;
create trigger schedule_touch_trg
  before update on public.schedule
  for each row execute function public.schedule_touch();


-- ── 5. Права доступа ───────────────────────────────────────────────
-- График: чтение и запись по публичному ключу приложения.
-- Разграничение прав (кто какой магазин правит) — на клиенте,
-- как и во всей остальной программе.
--
-- Справочники: только чтение. Менять их — здесь, в SQL Editor.

alter table public.schedule        enable row level security;
alter table public.schedule_points enable row level security;
alter table public.shift_types     enable row level security;

drop policy if exists p_schedule_rw       on public.schedule;
drop policy if exists p_schedule_points_r on public.schedule_points;
drop policy if exists p_shift_types_r     on public.shift_types;

create policy p_schedule_rw on public.schedule
  for all to anon, authenticated
  using (true) with check (true);

create policy p_schedule_points_r on public.schedule_points
  for select to anon, authenticated using (true);

create policy p_shift_types_r on public.shift_types
  for select to anon, authenticated using (true);

grant usage on schema public to anon, authenticated;
grant select, insert, update, delete on public.schedule        to anon, authenticated;
grant select                        on public.schedule_points  to anon, authenticated;
grant select                        on public.shift_types      to anon, authenticated;


-- ── 6. Проверка ────────────────────────────────────────────────────
-- Ожидается: points = 6, shift_types = 5, schedule = 0

select 'schedule_points' as table_name, count(*) as rows from public.schedule_points
union all
select 'shift_types',     count(*) from public.shift_types
union all
select 'schedule',        count(*) from public.schedule
order by table_name;
