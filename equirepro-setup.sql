-- =====================================================================
-- EquiRepro server setup  ·  run ONCE in Supabase → SQL Editor → New query → Run
-- Safe to run again (it updates functions and policies).
-- Roles: admin (vet), accountant, clinic_owner, owner (mare owner), buyer (semen buyer)
-- =====================================================================

create extension if not exists pgcrypto with schema extensions;

-- ---------- tables ----------
create table if not exists public.profiles(
  user_id uuid primary key references auth.users(id) on delete cascade,
  username text,
  display_name text default '',
  role text not null default 'none',
  owner_link text default '',          -- owner: owner name on mare files · buyer: buyer name on semen files
  created_at timestamptz default now()
);
alter table public.profiles drop constraint if exists profiles_role_check;
alter table public.profiles add constraint profiles_role_check
  check (role in ('none','admin','accountant','clinic_owner','owner','buyer'));

create table if not exists public.records(
  kind text not null,                  -- mares, exams, ais, ev, bill, et, rscr, rchk, visits, semen, media, settings, prices
  id text not null,
  data jsonb not null,
  mare_ids text[] not null default '{}',   -- which mare / semen file a record belongs to (drives owner & buyer access)
  deleted boolean not null default false,
  updated_at timestamptz not null default now(),
  updated_by uuid,
  primary key(kind,id)
);
create index if not exists records_updated_at on public.records(updated_at);
create index if not exists records_mare_ids on public.records using gin(mare_ids);

-- extra single files linked to one account (mare id, or 'semen:<id>' for a semen file)
create table if not exists public.mare_access(
  user_id uuid references public.profiles(user_id) on delete cascade,
  mare_id text,
  primary key(user_id,mare_id)
);

-- ---------- helper functions ----------
create or replace function public.my_role() returns text
language sql stable security definer set search_path=public as $$
  select coalesce((select role from profiles where user_id=auth.uid()),'none')
$$;

-- every mare id (owners) or 'semen:<id>' (buyers) this account may open
create or replace function public.my_mares() returns text[]
language sql stable security definer set search_path=public as $$
  select coalesce(array_agg(distinct m),'{}') from (
    select mare_id m from mare_access where user_id=auth.uid()
    union
    select r.id from records r join profiles p on p.user_id=auth.uid()
     where p.role='owner' and coalesce(trim(p.owner_link),'')<>'' and r.kind='mares' and not r.deleted
       and lower(trim(r.data->>'owner'))=lower(trim(p.owner_link))
    union
    select 'semen:'||r.id from records r join profiles p on p.user_id=auth.uid()
     where p.role='buyer' and coalesce(trim(p.owner_link),'')<>'' and r.kind='semen' and not r.deleted
       and lower(trim(r.data->>'buyer'))=lower(trim(p.owner_link))
  ) x
$$;

create or replace function public.can_write(k text) returns boolean
language sql stable security definer set search_path=public as $$
  select case my_role() when 'admin' then true when 'accountant' then k in ('bill','prices') else false end
$$;

create or replace function public.touch_record() returns trigger language plpgsql as $$
begin new.updated_at=clock_timestamp(); new.updated_by=auth.uid(); return new; end $$;
drop trigger if exists records_touch on public.records;
create trigger records_touch before insert or update on public.records
  for each row execute function public.touch_record();

-- a profile row for every new login (role 'none' = no access until the admin sets one)
create or replace function public.on_new_user() returns trigger
language plpgsql security definer set search_path=public as $$
begin
  insert into profiles(user_id,username,display_name)
  values(new.id, coalesce(new.raw_user_meta_data->>'username', split_part(new.email,'@',1)),
         coalesce(new.raw_user_meta_data->>'display_name',''))
  on conflict do nothing;
  return new;
end $$;
drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.on_new_user();

-- first-time setup: the first account to call this becomes admin (only while no admin exists)
create or replace function public.admin_exists() returns boolean
language sql stable security definer set search_path=public as $$
  select exists(select 1 from profiles where role='admin')
$$;
create or replace function public.claim_admin() returns boolean
language plpgsql security definer set search_path=public as $$
begin
  if exists(select 1 from profiles where role='admin') then return false; end if;
  update profiles set role='admin' where user_id=auth.uid();
  return found;
end $$;

-- admin sets (or resets) another account's password; also marks the account confirmed
create or replace function public.admin_set_password(uid uuid, pw text) returns void
language plpgsql security definer set search_path=public, extensions as $$
begin
  if public.my_role()<>'admin' then raise exception 'Only the admin can do this'; end if;
  if length(coalesce(pw,''))<6 then raise exception 'Password must be at least 6 characters'; end if;
  update auth.users set encrypted_password=extensions.crypt(pw, extensions.gen_salt('bf')),
         email_confirmed_at=coalesce(email_confirmed_at, now()), updated_at=now()
   where id=uid;
end $$;

grant execute on function public.admin_exists() to anon, authenticated;
grant execute on function public.claim_admin(), public.admin_set_password(uuid,text),
  public.my_role(), public.my_mares(), public.can_write(text) to authenticated;

-- ---------- row level security ----------
alter table public.profiles enable row level security;
alter table public.records enable row level security;
alter table public.mare_access enable row level security;

drop policy if exists "profiles read" on public.profiles;
drop policy if exists "profiles admin update" on public.profiles;
create policy "profiles read" on public.profiles for select to authenticated
  using (user_id=auth.uid() or (select public.my_role())='admin');
create policy "profiles admin update" on public.profiles for update to authenticated
  using ((select public.my_role())='admin') with check ((select public.my_role())='admin');

drop policy if exists "records read" on public.records;
drop policy if exists "records insert" on public.records;
drop policy if exists "records update" on public.records;
create policy "records read" on public.records for select to authenticated using (
  (select public.my_role()) in ('admin','accountant','clinic_owner')
  or ((select public.my_role())='owner' and (kind='settings'
       or (kind in ('mares','exams','ais','et','ev','visits','media') and mare_ids && (select public.my_mares()))))
  or ((select public.my_role())='buyer' and (kind='settings'
       or (kind in ('semen','media') and mare_ids && (select public.my_mares()))))
);
create policy "records insert" on public.records for insert to authenticated with check (public.can_write(kind));
create policy "records update" on public.records for update to authenticated
  using (public.can_write(kind)) with check (public.can_write(kind));

drop policy if exists "access read" on public.mare_access;
drop policy if exists "access admin write" on public.mare_access;
create policy "access read" on public.mare_access for select to authenticated
  using (user_id=auth.uid() or (select public.my_role())='admin');
create policy "access admin write" on public.mare_access for all to authenticated
  using ((select public.my_role())='admin') with check ((select public.my_role())='admin');

-- ---------- private storage for videos and photos (50 MB per file) ----------
-- paths: mare/<mare id>/<file>   and   semen/<semen file id>/<file>
insert into storage.buckets(id,name,public,file_size_limit)
values('media','media',false,52428800)
on conflict (id) do update set public=false, file_size_limit=52428800;

drop policy if exists "eq media read" on storage.objects;
drop policy if exists "eq media upload" on storage.objects;
drop policy if exists "eq media delete" on storage.objects;
create policy "eq media read" on storage.objects for select to authenticated using (
  bucket_id='media' and (
    (select public.my_role()) in ('admin','accountant','clinic_owner')
    or ((storage.foldername(name))[1]='mare' and array[(storage.foldername(name))[2]] && (select public.my_mares()))
    or ((storage.foldername(name))[1]='semen' and array['semen:'||(storage.foldername(name))[2]] && (select public.my_mares()))
  ));
create policy "eq media upload" on storage.objects for insert to authenticated
  with check (bucket_id='media' and (select public.my_role())='admin');
create policy "eq media delete" on storage.objects for delete to authenticated
  using (bucket_id='media' and (select public.my_role())='admin');

-- done. Next: Authentication → Sign In / Providers → Email → turn OFF "Confirm email".
