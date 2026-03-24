-- =============================================================================
-- Correction : RPC public.get_user_profile_by_id (PostgREST / clients Flutter)
-- =============================================================================
-- Problème visé :
--   Avec SECURITY INVOKER, le SELECT joint users / players / admins sous RLS.
--   Les policies croisées (users ↔ admins) peuvent provoquer des erreurs ou
--   des réponses anormales côté API, parfois vues côté client comme HTTP 520.
--
-- Ce que fait cette migration :
--   - Passe la fonction en SECURITY DEFINER : le corps du SELECT s’exécute sans
--     être bloqué / perturbé par la RLS sur les JOIN.
--   - Réintroduit explicitement la même autorisation qu’avant : un JWT avec
--     auth.uid() ne peut lire que son propre p_user_id ou tout profil s’il a
--     une ligne dans public.admins ; sans JWT (ex. service_role), pas de
--     filtre dans ce bloc (anon n’a pas EXECUTE sur cette fonction).
-- =============================================================================

CREATE OR REPLACE FUNCTION public.get_user_profile_by_id(p_user_id uuid)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    result jsonb;
BEGIN
    IF auth.uid() IS NOT NULL THEN
        IF auth.uid() IS DISTINCT FROM p_user_id
           AND NOT EXISTS (
               SELECT 1
               FROM public.admins a
               WHERE a.user_id = auth.uid()
           ) THEN
            RETURN NULL;
        END IF;
    END IF;

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
    INTO result
    FROM public.users u
    LEFT JOIN public.players p ON p.user_id = u.id
    LEFT JOIN public.admins a ON a.user_id = u.id
    WHERE u.id = p_user_id;

    RETURN result;
END;
$$;

GRANT EXECUTE ON FUNCTION public.get_user_profile_by_id(uuid) TO authenticated, service_role;
