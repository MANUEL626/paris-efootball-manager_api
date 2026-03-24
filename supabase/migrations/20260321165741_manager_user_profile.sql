-- Profil utilisateur agrégé (users + players ou admins selon user_type), retourné en JSON.

DROP FUNCTION IF EXISTS public.get_user_profile_by_id(uuid);

CREATE OR REPLACE FUNCTION public.get_user_profile_by_id(p_user_id uuid)
RETURNS jsonb
LANGUAGE sql
STABLE
SECURITY INVOKER
SET search_path = public
AS $$
    SELECT jsonb_build_object(
        'user_id', u.id,
        'email', u.email,
        'first_name', u.first_name,
        'last_name', u.last_name,
        'phone', u.phone,
        'user_type', u.user_type::text,
        'activity_status', u.activity_status,
        'profile_picture', u.profile_picture,
        'created_at', u.created_at,
        'player_id', p.id,
        'username', p.username,
        'admin_id', a.id
    )
    FROM public.users u
    LEFT JOIN public.players p ON p.user_id = u.id
    LEFT JOIN public.admins a ON a.user_id = u.id
    WHERE u.id = p_user_id;
$$;

GRANT EXECUTE ON FUNCTION public.get_user_profile_by_id(uuid) TO authenticated, service_role;
