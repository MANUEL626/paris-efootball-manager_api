-- Supprime la RPC agrégée profil utilisateur (plus d’exposition PostgREST sur ce nom).

DROP FUNCTION IF EXISTS public.get_user_profile_by_id(uuid);
