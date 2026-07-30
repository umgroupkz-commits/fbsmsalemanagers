-- ═══════════════════════════════════════════════════════════════════
-- FBSM · Очередь новых сотрудников из 1С
-- Идемпотентно. Существующие таблицы не трогает.
--
-- Смысл: новый человек из 1С НЕ появляется в программе сам. Он висит
-- в очереди, пока главный администратор не назначит ему роль и
-- магазин и не подтвердит. Не подтвердил — висит бесконечно.
--
-- Зачем: в 1С есть служебные учётки (Loyal, obmen, Prosystems,
-- Менеджер ИМ) и люди с другой мотивацией, которых в зарплатную
-- программу заводить нельзя. Автоматическое создание засорило бы
-- список сотрудников и сломало бы расчёт по магазинам.
-- ═══════════════════════════════════════════════════════════════════

create table if not exists public.import_queue (
  ext_id      text primary key,          -- GUID сотрудника в 1С
  source      text not null default '1c',
  name        text not null,
  ext_shop    text,                      -- магазин, как его назвала 1С
  position    text,
  sugg_shop   text,                      -- предложенный магазин из наших SHOPS
  sugg_role   text not null default 'seller',
  status      text not null default 'pending',   -- pending | approved | ignored
  uid         text,                      -- id созданного у нас сотрудника
  note        text,
  first_seen  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  decided_at  timestamptz,
  decided_by  text,
  constraint import_queue_status_chk check (status in ('pending','approved','ignored'))
);

create index if not exists import_queue_pending_idx
  on public.import_queue (first_seen) where status = 'pending';
create index if not exists import_queue_uid_idx on public.import_queue (uid);

create or replace function public.import_queue_touch()
returns trigger language plpgsql as $$
begin new.updated_at = now(); return new; end $$;

drop trigger if exists import_queue_touch_trg on public.import_queue;
create trigger import_queue_touch_trg
  before update on public.import_queue
  for each row execute function public.import_queue_touch();

alter table public.import_queue enable row level security;
drop policy if exists p_import_queue_rw on public.import_queue;
create policy p_import_queue_rw on public.import_queue
  for all to anon, authenticated using (true) with check (true);
grant select, insert, update, delete on public.import_queue to anon, authenticated;

select 'import_queue' as table_name, count(*) as rows from public.import_queue;
