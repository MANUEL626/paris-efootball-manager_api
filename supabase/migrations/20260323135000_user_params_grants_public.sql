-- Permissions PostgREST pour `public.user_params`
-- Sans ces GRANT, l'API peut répondre "permission denied" (403) même en service role.

GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE public.user_params TO anon, authenticated, service_role;

