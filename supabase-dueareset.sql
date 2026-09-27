-- DueAReset – database setup
-- Run once: Supabase → SQL Editor → New query → paste this whole file → Run.
-- Safe to run again: it only creates things that are missing and replaces the functions.
--
-- How the privacy works, in plain English:
--   * Each page is one row: a random 12-letter code, the page itself, and (only if the person signed in) who owns it.
--   * Nobody can read the table directly. The website can only call the five functions below.
--   * A page that nobody has signed in to can be opened by whoever has its code (its secret link).
--   * Once someone signs in, the page belongs to them: only they can open, change or delete it, even with the link.
--   * There is no way to list pages or search them. Deleting a page removes the row for good; deleting while
--     signed in also removes the sign-in (the email address).

create table if not exists public.dar_pages (
  code        text primary key check (code ~ '^[a-z0-9]{12}$'),
  owner       uuid references auth.users(id) on delete cascade,
  data        jsonb not null,
  updated_at  timestamptz not null default now()
);
create index if not exists dar_pages_owner_idx on public.dar_pages (owner);

-- Lock the table: no direct reading or writing from the website, only through the functions.
alter table public.dar_pages enable row level security;
revoke all on public.dar_pages from anon, authenticated;

-- Open a page by its code. Returns {data, owned}, {locked:true} if it belongs to someone else, or null.
create or replace function public.dar_get(p_code text)
returns jsonb language plpgsql security definer set search_path = public as $$
declare r public.dar_pages;
begin
  select * into r from public.dar_pages where code = p_code;
  if not found then return null; end if;
  if r.owner is not null and r.owner is distinct from auth.uid() then
    return jsonb_build_object('locked', true);
  end if;
  return jsonb_build_object('data', r.data, 'owned', r.owner is not null);
end $$;

-- Save a page. A new page belongs to whoever is signed in (or nobody). A page that belongs to someone
-- can only be saved by them.
create or replace function public.dar_save(p_code text, p_data jsonb)
returns boolean language plpgsql security definer set search_path = public as $$
begin
  if p_code !~ '^[a-z0-9]{12}$' then raise exception 'bad code'; end if;
  if octet_length(p_data::text) > 2000000 then raise exception 'page too big'; end if;
  insert into public.dar_pages (code, owner, data, updated_at)
  values (p_code, auth.uid(), p_data, now())
  on conflict (code) do update set data = excluded.data, updated_at = now()
    where public.dar_pages.owner is null or public.dar_pages.owner = auth.uid();
  if not found then raise exception 'locked'; end if;
  return true;
end $$;

-- After signing in: attach the page on this phone to your account.
create or replace function public.dar_claim(p_code text)
returns boolean language plpgsql security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  update public.dar_pages set owner = auth.uid(), updated_at = now()
   where code = p_code and (owner is null or owner = auth.uid());
  return found;
end $$;

-- Signed in on a new phone: fetch your page.
create or replace function public.dar_mine()
returns jsonb language plpgsql security definer set search_path = public as $$
declare r public.dar_pages;
begin
  if auth.uid() is null then return null; end if;
  select * into r from public.dar_pages where owner = auth.uid() order by updated_at desc limit 1;
  if not found then return null; end if;
  return jsonb_build_object('code', r.code, 'data', r.data);
end $$;

-- Delete a page (one nobody has signed in to, or your own).
create or replace function public.dar_delete(p_code text)
returns boolean language plpgsql security definer set search_path = public as $$
begin
  delete from public.dar_pages where code = p_code and (owner is null or owner = auth.uid());
  return found;
end $$;

-- Signed in: delete your pages and your sign-in (your email address) for good.
create or replace function public.dar_delete_account()
returns boolean language plpgsql security definer set search_path = public, auth as $$
begin
  if auth.uid() is null then raise exception 'not signed in'; end if;
  delete from public.dar_pages where owner = auth.uid();
  delete from auth.users where id = auth.uid();
  return true;
end $$;

revoke all on function public.dar_get(text), public.dar_save(text, jsonb), public.dar_claim(text),
  public.dar_mine(), public.dar_delete(text), public.dar_delete_account() from public;
grant execute on function public.dar_get(text), public.dar_save(text, jsonb), public.dar_claim(text),
  public.dar_mine(), public.dar_delete(text), public.dar_delete_account() to anon, authenticated;

-- Check it worked: this should show one row, "dar_pages", with rls_on = true.
select tablename, rowsecurity as rls_on from pg_tables where schemaname = 'public' and tablename = 'dar_pages';
