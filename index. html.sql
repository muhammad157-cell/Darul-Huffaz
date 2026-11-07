-- Darul Huffaz Academy: database schema with row-level security
-- Paste this whole file into Supabase > SQL Editor > New query, then click Run.

-- ========== TABLES ==========
create table profiles (
  id uuid primary key references auth.users on delete cascade,
  full_name text not null default '',
  role text not null default 'parent' check (role in ('admin','principal','teacher','parent','student')),
  status text not null default 'pending' check (status in ('pending','active','suspended')),
  created_at timestamptz default now()
);

create table classes (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  teacher_id uuid references profiles(id)
);

create table students (
  id uuid primary key default gen_random_uuid(),
  profile_id uuid references profiles(id),
  full_name text not null,
  class_id uuid references classes(id),
  created_at timestamptz default now()
);

create table parent_students (
  parent_id uuid references profiles(id) on delete cascade,
  student_id uuid references students(id) on delete cascade,
  primary key (parent_id, student_id)
);

create table attendance (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references students(id) on delete cascade,
  date date not null default current_date,
  present boolean not null,
  unique (student_id, date)
);

create table results (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references students(id) on delete cascade,
  subject text not null,
  term text not null,
  marks numeric not null check (marks between 0 and 100)
);

create table hifz_logs (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references students(id) on delete cascade,
  date date not null default current_date,
  sabaq text,
  sabqi text,
  manzil text
);

create table assignments (
  id uuid primary key default gen_random_uuid(),
  class_id uuid not null references classes(id) on delete cascade,
  title text not null,
  due_date date,
  created_by uuid default auth.uid()
);

create table fees (
  id uuid primary key default gen_random_uuid(),
  student_id uuid not null references students(id) on delete cascade,
  month text not null,
  amount_due numeric not null default 0,
  amount_paid numeric not null default 0
);

create table announcements (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  body text,
  audience text not null default 'all' check (audience in ('all','parents','teachers','class')),
  class_id uuid references classes(id),
  pinned boolean default false,
  created_by uuid default auth.uid(),
  created_at timestamptz default now()
);

create table events (
  id uuid primary key default gen_random_uuid(),
  title text not null,
  starts_at timestamptz not null,
  location text,
  audience text not null default 'all' check (audience in ('all','parents','teachers','class')),
  class_id uuid references classes(id),
  created_by uuid default auth.uid()
);

create table audit_log (
  id bigserial primary key,
  actor uuid,
  action text,
  table_name text,
  record jsonb,
  at timestamptz default now()
);

-- ========== NEW SIGN-UPS: always a pending parent ==========
-- The role is never taken from the sign-up form, so nobody can make themselves admin.
create function handle_new_user() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  insert into profiles (id, full_name)
  values (new.id, coalesce(new.raw_user_meta_data->>'full_name', ''));
  return new;
end $$;

create trigger on_auth_user_created
after insert on auth.users
for each row execute function handle_new_user();

-- ========== HELPER FUNCTIONS ==========
-- Returns the role only for ACTIVE accounts. Pending or suspended users get null = no access.
create function app_role() returns text
language sql stable security definer set search_path = public as $$
  select role from profiles where id = auth.uid() and status = 'active'
$$;

create function teaches(sid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from students s join classes c on c.id = s.class_id
                 where s.id = sid and c.teacher_id = auth.uid())
$$;

create function is_parent_of(sid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from parent_students where student_id = sid and parent_id = auth.uid())
$$;

create function is_student(sid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from students where id = sid and profile_id = auth.uid())
$$;

create function can_read(sid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select app_role() in ('admin','principal')
      or (app_role() = 'teacher' and teaches(sid))
      or (app_role() = 'parent'  and is_parent_of(sid))
      or (app_role() = 'student' and is_student(sid))
$$;

create function can_edit(sid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select app_role() = 'admin' or (app_role() = 'teacher' and teaches(sid))
$$;

create function can_see_audience(aud text, cid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select case app_role()
    when 'admin' then true
    when 'principal' then true
    when 'teacher' then aud in ('all','teachers')
      or (aud = 'class' and exists (select 1 from classes where id = cid and teacher_id = auth.uid()))
    when 'parent' then aud in ('all','parents')
      or (aud = 'class' and exists (select 1 from students s join parent_students ps on ps.student_id = s.id
                                    where s.class_id = cid and ps.parent_id = auth.uid()))
    when 'student' then aud = 'all'
      or (aud = 'class' and exists (select 1 from students where class_id = cid and profile_id = auth.uid()))
    else false end
$$;

create function teaches_class(cid uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from classes where id = cid and teacher_id = auth.uid())
$$;

-- ========== TURN ON ROW-LEVEL SECURITY ==========
alter table profiles        enable row level security;
alter table classes         enable row level security;
alter table students        enable row level security;
alter table parent_students enable row level security;
alter table attendance      enable row level security;
alter table results         enable row level security;
alter table hifz_logs       enable row level security;
alter table assignments     enable row level security;
alter table fees            enable row level security;
alter table announcements   enable row level security;
alter table events          enable row level security;
alter table audit_log       enable row level security;

-- ========== POLICIES ==========
-- Profiles: everyone sees their own; admin and principal see all; admin edits all; principal edits teachers only.
create policy "own profile"        on profiles for select using (id = auth.uid());
create policy "staff see profiles" on profiles for select using (app_role() in ('admin','principal'));
create policy "admin manages profiles" on profiles for all
  using (app_role() = 'admin') with check (app_role() = 'admin');
create policy "principal edits teachers" on profiles for update
  using (app_role() = 'principal' and role = 'teacher')
  with check (app_role() = 'principal' and role = 'teacher');

-- Classes
create policy "active users read classes" on classes for select using (app_role() is not null);
create policy "admin manages classes" on classes for all
  using (app_role() = 'admin') with check (app_role() = 'admin');

-- Students and parent links
create policy "read students" on students for select using (can_read(id));
create policy "admin manages students" on students for all
  using (app_role() = 'admin') with check (app_role() = 'admin');
create policy "parent sees own links" on parent_students for select using (parent_id = auth.uid());
create policy "staff see links" on parent_students for select using (app_role() in ('admin','principal'));
create policy "admin manages links" on parent_students for all
  using (app_role() = 'admin') with check (app_role() = 'admin');

-- Attendance, results, Hifz logs: admin and the student's teacher edit; parents, students and principal read.
do $$
declare t text;
begin
  foreach t in array array['attendance','results','hifz_logs'] loop
    execute format('create policy "read" on %I for select using (can_read(student_id))', t);
    execute format('create policy "write" on %I for all using (can_edit(student_id)) with check (can_edit(student_id))', t);
  end loop;
end $$;

-- Fees: admin edits; others read what they are allowed to see.
create policy "read fees" on fees for select using (can_read(student_id));
create policy "admin manages fees" on fees for all
  using (app_role() = 'admin') with check (app_role() = 'admin');

-- Assignments: admin and the class teacher edit; the class reads.
create policy "read assignments" on assignments for select using (can_see_audience('class', class_id));
create policy "write assignments" on assignments for all
  using (app_role() = 'admin' or (app_role() = 'teacher' and teaches_class(class_id)))
  with check (app_role() = 'admin' or (app_role() = 'teacher' and teaches_class(class_id)));

-- Announcements: admin and principal post to anyone; teachers post to their own classes only.
create policy "read announcements" on announcements for select using (can_see_audience(audience, class_id));
create policy "staff post announcements" on announcements for insert
  with check (app_role() in ('admin','principal')
    or (app_role() = 'teacher' and audience = 'class' and teaches_class(class_id)));
create policy "staff change announcements" on announcements for update
  using (app_role() in ('admin','principal') or (app_role() = 'teacher' and created_by = auth.uid()));
create policy "staff delete announcements" on announcements for delete
  using (app_role() in ('admin','principal') or (app_role() = 'teacher' and created_by = auth.uid()));

-- Events: same audience rules; admin and principal manage them.
create policy "read events" on events for select using (can_see_audience(audience, class_id));
create policy "staff manage events" on events for all
  using (app_role() in ('admin','principal')) with check (app_role() in ('admin','principal'));

-- Audit log: only admin can read it. Nobody can edit or delete entries.
create policy "admin reads audit" on audit_log for select using (app_role() = 'admin');

-- ========== AUDIT LOG: records every insert, update and delete ==========
create function audit() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if tg_op = 'DELETE' then
    insert into audit_log (actor, action, table_name, record) values (auth.uid(), tg_op, tg_table_name, to_jsonb(old));
    return old;
  end if;
  insert into audit_log (actor, action, table_name, record) values (auth.uid(), tg_op, tg_table_name, to_jsonb(new));
  return new;
end $$;

do $$
declare t text;
begin
  foreach t in array array['profiles','students','parent_students','attendance','results','hifz_logs','assignments','fees','announcements','events'] loop
    execute format('create trigger audit_%I after insert or update or delete on %I for each row execute function audit()', t, t);
  end loop;
end $$;

-- ========== MAKE YOURSELF THE FIRST ADMIN ==========
-- 1) In your website (or Supabase > Authentication > Users > Add user), create your own account.
-- 2) Replace the email below with yours, then run ONLY these lines:
--
-- update profiles set role = 'admin', status = 'active'
-- where id = (select id from auth.users where email = 'YOUR_EMAIL_HERE');
