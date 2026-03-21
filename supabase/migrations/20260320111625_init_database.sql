-- ============================
-- ENUM TYPES
-- ============================

-- Type d'utilisateur
DO $$ BEGIN
    CREATE TYPE user_type_enum AS ENUM ('player', 'admin', 'super_admin');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;


-- ============================
-- TABLE users
-- ============================
CREATE TABLE IF NOT EXISTS users (
    id uuid PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
    email text UNIQUE NOT NULL,
    first_name varchar(50) NOT NULL,
    last_name varchar(50) NOT NULL,
    phone varchar(20),
    user_type user_type_enum NOT NULL,
    activity_status boolean NOT NULL DEFAULT true,
    profile_picture text,
    created_at timestamptz DEFAULT now()
);

-- ============================
-- TABLE admins
-- ============================
CREATE TABLE IF NOT EXISTS admins (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE
);

-- ============================
-- TABLE players
-- ============================
CREATE TABLE IF NOT EXISTS players (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL UNIQUE REFERENCES users(id) ON DELETE CASCADE,
    username varchar(50) UNIQUE NOT NULL
);

-- ============================
-- ENABLE ROW LEVEL SECURITY
-- ============================
DO $$
BEGIN
    ALTER TABLE users ENABLE ROW LEVEL SECURITY;
EXCEPTION
    WHEN OTHERS THEN NULL;
END $$;

DO $$
BEGIN
    ALTER TABLE admins ENABLE ROW LEVEL SECURITY;
EXCEPTION
    WHEN OTHERS THEN NULL;
END $$;


DO $$
BEGIN
    ALTER TABLE players ENABLE ROW LEVEL SECURITY;
EXCEPTION
    WHEN OTHERS THEN NULL;
END $$;

-- ============================
-- Protection `super_admin` (1 seul, pas supprimable si dernier)
-- ============================

CREATE OR REPLACE FUNCTION public.enforce_single_super_admin()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- Empêche d'ajouter/activer plus d'un super_admin
    IF TG_OP IN ('INSERT', 'UPDATE') THEN
        IF NEW.user_type = 'super_admin' THEN
            IF EXISTS (
                SELECT 1
                FROM public.users u
                WHERE u.user_type = 'super_admin'
                  AND u.id <> NEW.id
            ) THEN
                RAISE EXCEPTION 'Impossible d''avoir plus d''un super_admin';
            END IF;
        END IF;
        RETURN NEW;
    END IF;

    -- Empêche de supprimer le super_admin si c'est le dernier
    IF TG_OP = 'DELETE' THEN
        IF OLD.user_type = 'super_admin' THEN
            IF NOT EXISTS (
                SELECT 1
                FROM public.users u
                WHERE u.user_type = 'super_admin'
                  AND u.id <> OLD.id
            ) THEN
                RAISE EXCEPTION 'Suppression refusée : il doit toujours exister au moins un super_admin';
            END IF;
        END IF;
        RETURN OLD;
    END IF;

    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS enforce_single_super_admin_insupd ON public.users;
CREATE TRIGGER enforce_single_super_admin_insupd
BEFORE INSERT OR UPDATE OF user_type
ON public.users
FOR EACH ROW
EXECUTE FUNCTION public.enforce_single_super_admin();

DROP TRIGGER IF EXISTS enforce_single_super_admin_del ON public.users;
CREATE TRIGGER enforce_single_super_admin_del
BEFORE DELETE
ON public.users
FOR EACH ROW
EXECUTE FUNCTION public.enforce_single_super_admin();

-- ============================
-- POLICIES FOR owners
-- ============================

-- ============================
-- POLICIES (RLS)
-- ============================

-- La logique "admin" est volontairement différente selon les cas:
-- - Pour `public.users` (SELECT/UPDATE), on s'appuie sur `public.admins`.
-- - Pour `public.admins` / `public.players` (SELECT all), on s'appuie sur `public.users.user_type`
--   afin d'éviter des auto-références problématiques côté RLS.

-- ----------------------------
-- public.users
-- ----------------------------

-- Les admins peuvent voir tous les utilisateurs (et les non-admin voient seulement eux-mêmes)
CREATE POLICY "admins_can_select_all_users"
ON public.users
FOR SELECT
TO authenticated
USING (
    id = auth.uid()
    OR EXISTS (
        SELECT 1
        FROM public.admins a
        WHERE a.user_id = auth.uid()
    )
);

-- Les admins peuvent mettre à jour les lignes `public.users` (toutes colonnes visibles par la policy).
-- Note: `FOR UPDATE OF colonne` (politique RLS par colonne) nécessite PostgreSQL récent ;
-- sur les instances Supabase plus anciennes, utiliser `FOR UPDATE` uniquement.
CREATE POLICY "admins_can_update_activity_status_all_users"
ON public.users
FOR UPDATE
TO authenticated
USING (
    EXISTS (
        SELECT 1
        FROM public.admins a
        WHERE a.user_id = auth.uid()
    )
)
WITH CHECK (
    EXISTS (
        SELECT 1
        FROM public.admins a
        WHERE a.user_id = auth.uid()
    )
);

-- ----------------------------
-- public.admins
-- ----------------------------

-- Les utilisateurs peuvent voir/mettre à jour leur propre ligne
CREATE POLICY "users_can_select_own_admin_profile"
ON public.admins
FOR SELECT
TO authenticated
USING (user_id = auth.uid());

CREATE POLICY "users_can_insert_own_admin_profile"
ON public.admins
FOR INSERT
TO authenticated
WITH CHECK (
    user_id = auth.uid()
    AND EXISTS (
        SELECT 1
        FROM public.users u
        WHERE u.id = auth.uid()
          AND u.user_type IN ('admin', 'super_admin')
    )
);

CREATE POLICY "users_can_update_own_admin_profile"
ON public.admins
FOR UPDATE
TO authenticated
USING (user_id = auth.uid())
WITH CHECK (
    user_id = auth.uid()
    AND EXISTS (
        SELECT 1
        FROM public.users u
        WHERE u.id = auth.uid()
          AND u.user_type IN ('admin', 'super_admin')
    )
);

-- Les admins peuvent voir toutes les lignes `admins`
-- (utile pour savoir qui est admin, notamment dans les JOIN.)
CREATE POLICY "admins_can_select_all_admin_profiles"
ON public.admins
FOR SELECT
TO authenticated
USING (
    EXISTS (
        SELECT 1
        FROM public.users u
        WHERE u.id = auth.uid()
          AND u.user_type IN ('admin', 'super_admin')
    )
);

-- ----------------------------
-- public.players
-- ----------------------------

-- Les utilisateurs peuvent voir/mettre à jour leur propre ligne
CREATE POLICY "users_can_select_own_player_profile"
ON public.players
FOR SELECT
TO authenticated
USING (user_id = auth.uid());

CREATE POLICY "users_can_insert_own_player_profile"
ON public.players
FOR INSERT
TO authenticated
WITH CHECK (
    user_id = auth.uid()
    AND EXISTS (
        SELECT 1
        FROM public.users u
        WHERE u.id = auth.uid()
          AND u.user_type = 'player'
    )
);

CREATE POLICY "users_can_update_own_player_profile"
ON public.players
FOR UPDATE
TO authenticated
USING (user_id = auth.uid())
WITH CHECK (
    user_id = auth.uid()
    AND EXISTS (
        SELECT 1
        FROM public.users u
        WHERE u.id = auth.uid()
          AND u.user_type = 'player'
    )
);

-- Les admins peuvent voir toutes les lignes `players`
CREATE POLICY "admins_can_select_all_player_profiles"
ON public.players
FOR SELECT
TO authenticated
USING (
    EXISTS (
        SELECT 1
        FROM public.users u
        WHERE u.id = auth.uid()
          AND u.user_type IN ('admin', 'super_admin')
    )
);

-- ============================
-- Fonctions (helpers)
-- ============================
-- (Supprimées : `public.add_user` et `public.get_user_type`)
-- Le flux recommandé est :
-- - trigger `public.handle_new_auth_user` (profil de base dans public.users)
-- - RPC `public.create_user_profile` (tables spécialisées players/admins)

-- ============================
-- Trigger + RPC (procédé guide)
-- ============================

-- 1) Trigger: crée le profil applicatif de base après insertion dans `auth.users`.
-- Le trigger n'est responsable que du "profil de base" dans `public.users`.
-- Les entités spécialisées (players/admins) sont gérées par RPC (`create_user_profile`).
CREATE OR REPLACE FUNCTION public.handle_new_auth_user()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_first_name text;
    v_last_name text;
    v_phone text;
    v_user_type_text text;
    v_profile_picture text;
    v_user_type public.user_type_enum;
BEGIN
    -- Récupération des métadonnées fournies lors de la création Auth
    v_first_name := COALESCE(NEW.raw_user_meta_data->>'first_name', NEW.raw_user_meta_data->>'firstname', '');
    v_last_name := COALESCE(NEW.raw_user_meta_data->>'last_name', NEW.raw_user_meta_data->>'lastname', '');
    v_phone := COALESCE(NEW.raw_user_meta_data->>'phone', NEW.raw_user_meta_data->>'tel', NULL);
    v_profile_picture := COALESCE(
        NEW.raw_user_meta_data->'profile_data'->>'profile_picture',
        NEW.raw_user_meta_data->'profile_data'->>'profilePicture',
        NEW.raw_user_meta_data->>'profile_picture',
        NEW.raw_user_meta_data->>'profilePicture',
        NULL
    );

    v_user_type_text := COALESCE(
        NEW.raw_user_meta_data->>'user_type',
        NEW.raw_user_meta_data->>'usertype',
        NEW.raw_user_meta_data->>'category'
    );

    IF v_user_type_text IS NULL OR length(trim(v_user_type_text)) = 0 THEN
        v_user_type := 'player'::public.user_type_enum;
    ELSE
        v_user_type := v_user_type_text::public.user_type_enum;
    END IF;

    INSERT INTO public.users (
        id,
        email,
        first_name,
        last_name,
        phone,
        user_type,
        profile_picture
    )
    VALUES (
        NEW.id,
        NEW.email,
        v_first_name,
        v_last_name,
        v_phone,
        v_user_type,
        v_profile_picture
    )
    ON CONFLICT (id) DO NOTHING;

    RETURN NEW;
EXCEPTION
    WHEN others THEN
        -- Ne bloque jamais l'inscription Auth si un champ de meta est manquant.
        RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS handle_new_auth_user_trigger ON auth.users;
CREATE TRIGGER handle_new_auth_user_trigger
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE FUNCTION public.handle_new_auth_user();

-- 2) RPC: crée la ligne spécialisée (players/admins) + s'assure de la cohérence base.
-- Signature conforme au guide:
-- public.create_user_profile(p_user_id, p_email, p_firstname, p_lastname, p_user_type, p_phone, p_profile_data jsonb)
CREATE OR REPLACE FUNCTION public.create_user_profile(
    p_user_id uuid,
    p_email text,
    p_firstname text,
    p_lastname text,
    p_user_type public.user_type_enum,
    p_phone varchar(20),
    p_profile_data jsonb DEFAULT NULL
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
AS $$
DECLARE
    v_profile_picture text;
    v_username text;
BEGIN
    -- Vérifie l'existence dans Auth
    IF NOT EXISTS (
        SELECT 1
        FROM auth.users au
        WHERE au.id = p_user_id
    ) THEN
        RAISE EXCEPTION 'Utilisateur % introuvable dans auth.users', p_user_id;
    END IF;

    -- Crée le profil de base si absent
    v_profile_picture := COALESCE(
        p_profile_data->>'profile_picture',
        p_profile_data->>'profilePicture'
    );

    INSERT INTO public.users (
        id,
        email,
        first_name,
        last_name,
        phone,
        user_type,
        profile_picture
    )
    VALUES (
        p_user_id,
        p_email,
        p_firstname,
        p_lastname,
        p_phone,
        p_user_type,
        v_profile_picture
    )
    ON CONFLICT (id) DO UPDATE
    SET
        email = EXCLUDED.email,
        first_name = EXCLUDED.first_name,
        last_name = EXCLUDED.last_name,
        phone = COALESCE(EXCLUDED.phone, public.users.phone),
        user_type = EXCLUDED.user_type,
        profile_picture = COALESCE(EXCLUDED.profile_picture, public.users.profile_picture);

    -- Crée ensuite l'enregistrement spécialisé
    IF p_user_type = 'player' THEN
        v_username := COALESCE(
            p_profile_data->>'username',
            p_profile_data->>'user_name',
            p_profile_data->>'login'
        );

        IF v_username IS NULL OR length(trim(v_username)) = 0 THEN
            RAISE EXCEPTION 'username est requis pour un user de type player';
        END IF;

        INSERT INTO public.players (user_id, username)
        VALUES (p_user_id, v_username)
        ON CONFLICT (user_id) DO NOTHING;

    ELSIF p_user_type IN ('admin', 'super_admin') THEN
        INSERT INTO public.admins (user_id)
        VALUES (p_user_id)
        ON CONFLICT (user_id) DO NOTHING;
    END IF;
END;
$$;

-- ============================
-- Seed super_admin par défaut
-- ============================

DO $$
DECLARE
    v_user_id uuid;
    v_email text := 'test@test.com';
    v_password text := 'e_f00t@2026';
BEGIN
    SELECT id INTO v_user_id
    FROM auth.users
    WHERE email = v_email
    LIMIT 1;

    IF v_user_id IS NULL THEN
        CREATE EXTENSION IF NOT EXISTS "pgcrypto";

        v_user_id := gen_random_uuid();

        -- Crée l'utilisateur dans Supabase Auth (GoTrue)
        -- email_confirmed_at est positionné => pas de confirmation email
        INSERT INTO auth.users (
            id,
            instance_id,
            aud,
            role,
            email,
            encrypted_password,
            email_confirmed_at,
            raw_app_meta_data,
            raw_user_meta_data,
            created_at,
            updated_at
        )
        VALUES (
            v_user_id,
            '00000000-0000-0000-0000-000000000000'::uuid,
            'authenticated',
            'authenticated',
            v_email,
            crypt(v_password, gen_salt('bf')),
            now(),
            '{}'::jsonb,
            jsonb_build_object(
                'firstname', 'admin',
                'lastname', 'admin',
                'user_type', 'super_admin'
            ),
            now(),
            now()
        );

        -- Ajoute l'identité email (nécessaire pour la connexion par mot de passe)
        INSERT INTO auth.identities (
            id,
            user_id,
            provider,
            provider_id,
            identity_data,
            created_at,
            last_sign_in_at,
            updated_at
        )
        VALUES (
            v_user_id,
            v_user_id,
            'email',
            v_user_id::text,
            jsonb_build_object('sub', v_user_id::text, 'email', v_email),
            now(),
            NULL,
            now()
        );
    END IF;

    -- Assure la création/présence du profil applicatif + ligne admins
    PERFORM public.create_user_profile(
        v_user_id,
        v_email,
        'admin',
        'admin',
        'super_admin'::public.user_type_enum,
        NULL,
        NULL
    );
END;
$$;