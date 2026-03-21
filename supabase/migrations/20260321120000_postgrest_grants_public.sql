-- Droits PostgreSQL pour PostgREST (clés anon / JWT utilisateur / service_role).
-- Sans GRANT sur les tables, l’API REST renvoie 403 « permission denied for table … »
-- même avec la service_role (RLS est contournée, mais il faut les privilèges sur les relations).

GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.users TO anon, authenticated, service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.admins TO anon, authenticated, service_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.players TO anon, authenticated, service_role;
