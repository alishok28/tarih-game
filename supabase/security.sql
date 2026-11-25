-- =====================================================================
--  Тарих Race KZ — базаның қауіпсіздік баптаулары
--
--  ОРЫНДАУ ТӘРТІБІ:
--   1) Supabase → Authentication → Users → "Add user" → "Create new user":
--      админ email-і мен мықты құпиясөз жазып, "Auto Confirm User" белгілеңіз.
--   2) Төмендегі ADMIN_EMAIL_HERE орнына сол email-ді жазыңыз (тырнақшалар қалсын).
--   3) Бүкіл мәтінді SQL Editor-ға қойып, Run басыңыз.
--
--  Скриптті қайта іске қосуға болады. Қате шықса, ештеңе өзгермейді.
--
--  НӘТИЖЕСІ:
--   * ойыншылар (anon) тек нәтиже ҚОСА алады: оқи да, өзгерте де, өшіре де алмайды;
--   * нәтижелерді тек бір админ оқиды және өшіреді, онда да тек
--     құпиясөз + телефондағы код (2FA, aal2) арқылы кіргеннен кейін;
--   * ұпайды сервер өзі есептейді, мәндердің шегі тексеріледі;
--   * бір желіден келетін спамға шек қойылады.
-- =====================================================================
begin;

-- 0. Сырттан (Data API арқылы) көрінбейтін қызметтік схема
create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated;

-- 1. Жалғыз админ
create table if not exists private.admins (
  user_id  uuid primary key references auth.users (id) on delete cascade,
  added_at timestamptz not null default now()
);
revoke all on private.admins from public, anon, authenticated;

do $$
declare
  admin_email text := 'ADMIN_EMAIL_HERE';   -- <<< ОСЫ ЖЕРГЕ АДМИН EMAIL-ІН ЖАЗЫҢЫЗ
  admin_id uuid;
begin
  select id into admin_id from auth.users where lower(email) = lower(btrim(admin_email));
  if admin_id is null then
    raise exception 'Админ табылмады (%). Алдымен Authentication → Users бөлімінде осы email-мен қолданушы жасаңыз, сосын скриптті қайта іске қосыңыз.', admin_email;
  end if;
  delete from private.admins where user_id <> admin_id;          -- админ әрқашан біреу ғана
  insert into private.admins (user_id) values (admin_id) on conflict (user_id) do nothing;
end $$;

-- Админ тексеруі: тізімде болу + екі сатылы кіру (aal2) міндетті
create or replace function private.is_admin()
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce((select auth.jwt() ->> 'aal') = 'aal2', false)
     and exists (select 1 from private.admins a where a.user_id = (select auth.uid()));
$$;
revoke all on function private.is_admin() from public, anon;
grant execute on function private.is_admin() to authenticated;

-- 2. Кестеге жаңа бағандар мен шектеулер (ескі жазбаларға тиіспейді: NOT VALID)
alter table public.scores add column if not exists coins int;
alter table public.scores add column if not exists arts  int;

alter table public.scores drop constraint if exists scores_correct_check;  -- бұрын 0..4 еді, енді 5 сұрақ
alter table public.scores drop constraint if exists name_clean;
alter table public.scores drop constraint if exists scores_rules_v2;
alter table public.scores add constraint scores_rules_v2 check (
      coins is not null and coins between 0 and 500
  and arts  is not null and arts  between 0 and 7
  and correct between 0 and 5
  and time_s  between 30 and 900
  and uid  ~ '^[0-9a-f]{32}$'
  and name ~ '^[^<>[:cntrl:]]{2,20}$'
  and name = btrim(name)
) not valid;

-- 3. Спамнан қорғау үшін қызметтік кестелер (IP өзі сақталмайды, тек тұзды хэш)
create table if not exists private.settings (k text primary key, v text not null);
insert into private.settings (k, v)
values ('salt', md5(random()::text || clock_timestamp()::text) || md5(gen_random_uuid()::text))
on conflict (k) do nothing;
revoke all on private.settings from public, anon, authenticated;

create table if not exists private.rate_log (
  ip_hash text not null,
  at      timestamptz not null default now()
);
create index if not exists rate_log_ip_at on private.rate_log (ip_hash, at);
create index if not exists rate_log_at    on private.rate_log (at);
revoke all on private.rate_log from public, anon, authenticated;

-- 4. Әр жаңа нәтижені сервер тексереді: ұпайды өзі есептейді, уақытты өзі қояды, спамды шектейді
drop trigger  if exists scores_limit on public.scores;      -- алдыңғы нұсқадан қалғаны
drop function if exists public.scores_limit();

create or replace function private.scores_guard()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  hdr      jsonb;
  ip       text;
  h        text;
  per_min  int;
  per_hour int;
begin
  new.name       := btrim(new.name);
  new.created_at := now();
  new.score      := new.coins * 10 + new.arts * 100 + new.correct * 200
                  + case new.place when 1 then 500 when 2 then 250 when 3 then 100 else 0 end
                  + greatest(0, round((100 - new.time_s::numeric) * 10))::int;

  if (select count(*) from public.scores) >= 200000 then
    raise exception 'scores table is full';
  end if;

  begin
    hdr := nullif(current_setting('request.headers', true), '')::jsonb;
    ip  := coalesce(nullif(hdr ->> 'cf-connecting-ip', ''),
                    nullif(btrim(split_part(hdr ->> 'x-forwarded-for', ',', 1)), ''),
                    nullif(hdr ->> 'x-real-ip', ''));
  exception when others then
    ip := null;
  end;

  if ip is not null then
    h := encode(sha256(convert_to(left(ip, 64) || '|' || current_date::text || '|' ||
                 (select v from private.settings where k = 'salt'), 'UTF8')), 'hex');
    select count(*) filter (where at > now() - interval '1 minute'), count(*)
      into per_min, per_hour
      from private.rate_log
     where ip_hash = h and at > now() - interval '1 hour';
    if per_min >= 40 or per_hour >= 600 then
      raise exception 'too many results from this network, try again later';
    end if;
    insert into private.rate_log (ip_hash) values (h);
    if random() < 0.02 then
      delete from private.rate_log where at < now() - interval '1 day';
    end if;
  end if;

  return new;
end;
$$;
revoke all on function private.scores_guard() from public, anon, authenticated;

drop trigger if exists scores_guard on public.scores;
create trigger scores_guard
  before insert on public.scores
  for each row execute function private.scores_guard();

-- 5. Кіру ережелері (RLS)
alter table public.scores enable row level security;

drop policy if exists "read scores"    on public.scores;   -- бұрынғы ашық оқу ережесі жойылады
drop policy if exists "add scores"     on public.scores;
drop policy if exists "players insert" on public.scores;
drop policy if exists "admin read"     on public.scores;
drop policy if exists "admin delete"   on public.scores;

create policy "players insert" on public.scores
  for insert to anon
  with check (true);

create policy "admin read" on public.scores
  for select to authenticated
  using ((select private.is_admin()));

create policy "admin delete" on public.scores
  for delete to authenticated
  using ((select private.is_admin()));

-- 6. Құқықтар: ойыншыға тек нақты бағандарға жазу, админге оқу мен өшіру
revoke all on public.scores from public, anon, authenticated;
grant insert (uid, name, track, time_s, place, correct, coins, arts, ch) on public.scores to anon;
grant select, delete on public.scores to authenticated;

commit;

select 'Дайын: база қорғалды' as "Нәтиже",
       (select count(*) from private.admins) as "Админ саны",
       (select count(*) from public.scores)  as "Сақталған нәтижелер";
