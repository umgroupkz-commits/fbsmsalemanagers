-- ═══════════════════════════════════════════════════════════════════
-- FBSM · Предбанник продаж из 1С
-- Идемпотентно. Существующие таблицы не трогает.
--
-- Смысл: данные из 1С сначала попадают СЮДА, а не сразу в зарплату.
-- Консультант заходит, видит свои цифры за день, правки не может,
-- жмёт «Подтвердить» — и только тогда строка уходит в sales и идёт
-- в расчёт. Не подтвердил — день не засчитан, смены нет.
--
-- Зачем так: заставляет продавца каждый день посмотреть свою
-- выручку и процент выполнения плана, а не узнавать о них в конце
-- месяца из расчётного листа.
-- ═══════════════════════════════════════════════════════════════════

create table if not exists public.sales_pending (
  uid           text not null,
  date          date not null,
  sales         numeric not null default 0,
  checks        integer not null default 0,
  units         integer not null default 0,
  returns       numeric not null default 0,
  source        text    not null default '1c',
  src_updated_at timestamptz,          -- когда 1С в последний раз меняла эти цифры
  confirmed_at  timestamptz,           -- null = ждёт подтверждения
  confirmed_by  text,
  updated_at    timestamptz not null default now(),
  primary key (uid, date)
);

create index if not exists sales_pending_wait_idx
  on public.sales_pending (date) where confirmed_at is null;

create or replace function public.sales_pending_touch()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;

drop trigger if exists sales_pending_touch_trg on public.sales_pending;
create trigger sales_pending_touch_trg
  before update on public.sales_pending
  for each row execute function public.sales_pending_touch();

alter table public.sales_pending enable row level security;
drop policy if exists p_sales_pending_rw on public.sales_pending;
create policy p_sales_pending_rw on public.sales_pending
  for all to anon, authenticated using (true) with check (true);
grant select, insert, update, delete on public.sales_pending to anon, authenticated;

select 'sales_pending' as table_name, count(*) as rows from public.sales_pending;
