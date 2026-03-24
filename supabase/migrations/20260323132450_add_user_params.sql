-- ============================
-- TYPE theme pour user_params
-- ============================
DO $$ BEGIN
    CREATE TYPE theme_user_params_enum AS ENUM ('light', 'dark');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- ============================
-- TABLE user_params (un enregistrement par utilisateur)
-- ============================
CREATE TABLE IF NOT EXISTS user_params (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE UNIQUE,
    country varchar(100) NOT NULL,
    language_setting varchar(100) NOT NULL,
    notification boolean NOT NULL DEFAULT true,
    theme theme_user_params_enum NOT NULL,
    is_params_done boolean NOT NULL DEFAULT false,
    created_at timestamptz DEFAULT now(),
    updated_at timestamptz DEFAULT now()
);