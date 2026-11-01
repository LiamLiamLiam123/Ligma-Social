-- Ligma-Social: initial schema, RLS, triggers, storage
create extension if not exists citext;

-- ========== TABLES ==========
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username citext unique not null check (username ~ '^[A-Za-z0-9_]{3,15}$'),
  display_name text not null check (char_length(display_name) between 1 and 40),
  bio text not null default '' check (char_length(bio) <= 160),
  avatar_url text,
  banner_url text,
  is_private boolean not null default false,
  is_verified boolean not null default false,
  created_at timestamptz not null default now()
);

create table public.posts (
  id uuid primary key default gen_random_uuid(),
  author_id uuid not null references public.profiles(id) on delete cascade,
  body text not null default '' check (char_length(body) <= 500),
  media jsonb not null default '[]',            -- [{"type":"image|video","url":"..."}]
  parent_id uuid references public.posts(id) on delete cascade,  -- set = comment/reply
  created_at timestamptz not null default now()
);
create index on public.posts (created_at desc);
create index on public.posts (author_id);
create index on public.posts (parent_id);

create table public.likes (
  user_id uuid references public.profiles(id) on delete cascade,
  post_id uuid references public.posts(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, post_id)
);
create table public.reposts (like public.likes including all);
alter table public.reposts add foreign key (user_id) references public.profiles(id) on delete cascade;
alter table public.reposts add foreign key (post_id) references public.posts(id) on delete cascade;
create table public.bookmarks (like public.likes including all);
alter table public.bookmarks add foreign key (user_id) references public.profiles(id) on delete cascade;
alter table public.bookmarks add foreign key (post_id) references public.posts(id) on delete cascade;

create table public.follows (
  follower_id uuid references public.profiles(id) on delete cascade,
  following_id uuid references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (follower_id, following_id),
  check (follower_id <> following_id)
);
create table public.blocks (
  blocker_id uuid references public.profiles(id) on delete cascade,
  blocked_id uuid references public.profiles(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (blocker_id, blocked_id),
  check (blocker_id <> blocked_id)
);
create table public.messages (
  id uuid primary key default gen_random_uuid(),
  sender_id uuid not null references public.profiles(id) on delete cascade,
  recipient_id uuid not null references public.profiles(id) on delete cascade,
  body text not null check (char_length(body) between 1 and 1000),
  read_at timestamptz,
  created_at timestamptz not null default now()
);
create index on public.messages (recipient_id, created_at desc);
create index on public.messages (sender_id, created_at desc);

create table public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  actor_id uuid not null references public.profiles(id) on delete cascade,
  type text not null check (type in ('follow','like','comment','repost','mention','message')),
  post_id uuid references public.posts(id) on delete cascade,
  read_at timestamptz,
  created_at timestamptz not null default now()
);
create index on public.notifications (user_id, created_at desc);

create table public.reports (
  id uuid primary key default gen_random_uuid(),
  reporter_id uuid not null references public.profiles(id) on delete cascade,
  post_id uuid not null references public.posts(id) on delete cascade,
  reason text not null check (char_length(reason) between 1 and 300),
  created_at timestamptz not null default now()
);

-- ========== HELPERS ==========
create function public.is_blocked(a uuid, b uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from blocks
    where (blocker_id = a and blocked_id = b) or (blocker_id = b and blocked_id = a))
$$;

create function public.can_view(author uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select author = auth.uid() or (
    not is_blocked(auth.uid(), author)
    and (not (select is_private from profiles where id = author)
         or exists (select 1 from follows where follower_id = auth.uid() and following_id = author)))
$$;

-- ========== NEW USER -> PROFILE ==========
create function public.handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into profiles (id, username, display_name)
  values (new.id, new.raw_user_meta_data->>'username', new.raw_user_meta_data->>'username');
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- ========== NOTIFICATION TRIGGERS ==========
create function public.make_notification() returns trigger
language plpgsql security definer set search_path = public as $$
declare tgt uuid; act uuid; typ text; pid uuid;
begin
  if tg_table_name = 'likes' or tg_table_name = 'reposts' then
    select author_id into tgt from posts where id = new.post_id;
    act := new.user_id; pid := new.post_id; typ := case tg_table_name when 'likes' then 'like' else 'repost' end;
  elsif tg_table_name = 'follows' then
    tgt := new.following_id; act := new.follower_id; typ := 'follow';
  elsif tg_table_name = 'messages' then
    tgt := new.recipient_id; act := new.sender_id; typ := 'message';
  elsif tg_table_name = 'posts' and new.parent_id is not null then
    select author_id into tgt from posts where id = new.parent_id;
    act := new.author_id; pid := new.id; typ := 'comment';
  end if;
  if tgt is not null and tgt <> act then
    insert into notifications (user_id, actor_id, type, post_id) values (tgt, act, typ, pid);
  end if;
  return new;
end $$;
create trigger n_likes after insert on likes for each row execute function make_notification();
create trigger n_reposts after insert on reposts for each row execute function make_notification();
create trigger n_follows after insert on follows for each row execute function make_notification();
create trigger n_messages after insert on messages for each row execute function make_notification();
create trigger n_comments after insert on posts for each row execute function make_notification();

-- ========== ROW LEVEL SECURITY ==========
alter table profiles enable row level security;
alter table posts enable row level security;
alter table likes enable row level security;
alter table reposts enable row level security;
alter table bookmarks enable row level security;
alter table follows enable row level security;
alter table blocks enable row level security;
alter table messages enable row level security;
alter table notifications enable row level security;
alter table reports enable row level security;

create policy "profiles readable" on profiles for select to authenticated
  using (id = auth.uid() or not is_blocked(auth.uid(), id));
create policy "own profile update" on profiles for update to authenticated
  using (id = auth.uid()) with check (id = auth.uid());
-- users may not change is_verified themselves (set it from the dashboard / service role)
revoke update on profiles from authenticated;
grant update (username, display_name, bio, avatar_url, banner_url, is_private) on profiles to authenticated;

create policy "posts visible" on posts for select to authenticated using (can_view(author_id));
create policy "posts insert own" on posts for insert to authenticated with check (author_id = auth.uid());
create policy "posts delete own" on posts for delete to authenticated using (author_id = auth.uid());

create policy "likes read" on likes for select to authenticated using (true);
create policy "likes insert" on likes for insert to authenticated with check (user_id = auth.uid());
create policy "likes delete" on likes for delete to authenticated using (user_id = auth.uid());
create policy "reposts read" on reposts for select to authenticated using (true);
create policy "reposts insert" on reposts for insert to authenticated with check (user_id = auth.uid());
create policy "reposts delete" on reposts for delete to authenticated using (user_id = auth.uid());
create policy "bookmarks own" on bookmarks for all to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy "follows read" on follows for select to authenticated using (true);
create policy "follows insert" on follows for insert to authenticated
  with check (follower_id = auth.uid() and not is_blocked(auth.uid(), following_id));
create policy "follows delete" on follows for delete to authenticated using (follower_id = auth.uid());

create policy "blocks own" on blocks for all to authenticated
  using (blocker_id = auth.uid()) with check (blocker_id = auth.uid());

create policy "messages read" on messages for select to authenticated
  using (sender_id = auth.uid() or recipient_id = auth.uid());
create policy "messages send" on messages for insert to authenticated
  with check (sender_id = auth.uid() and not is_blocked(auth.uid(), recipient_id));
create policy "messages mark read" on messages for update to authenticated
  using (recipient_id = auth.uid()) with check (recipient_id = auth.uid());

create policy "notifs read" on notifications for select to authenticated using (user_id = auth.uid());
create policy "notifs mark read" on notifications for update to authenticated
  using (user_id = auth.uid()) with check (user_id = auth.uid());

create policy "reports insert" on reports for insert to authenticated with check (reporter_id = auth.uid());
-- no select policy on reports: only the service role / dashboard can read them

-- ========== REALTIME ==========
alter publication supabase_realtime add table messages, notifications;

-- ========== STORAGE ==========
insert into storage.buckets (id, name, public) values
  ('avatars','avatars',true), ('banners','banners',true), ('media','media',true)
on conflict do nothing;

create policy "public read media" on storage.objects for select
  using (bucket_id in ('avatars','banners','media'));
create policy "upload to own folder" on storage.objects for insert to authenticated
  with check (bucket_id in ('avatars','banners','media') and (storage.foldername(name))[1] = auth.uid()::text);
create policy "delete own files" on storage.objects for delete to authenticated
  using (bucket_id in ('avatars','banners','media') and (storage.foldername(name))[1] = auth.uid()::text);
