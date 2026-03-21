"""
Configuration du client Supabase pour le projet
Ce fichier peut être importé dans n'importe quel module du projet
"""

from supabase import create_client, Client
import os
from dotenv import load_dotenv

# Charger les variables d'environnement depuis un fichier .env
load_dotenv()

# Configuration Supabase depuis les variables d'environnement
SUPABASE_URL = os.getenv(
    "SUPABASE_URL",
    "http://127.0.0.1:54321"  # URL par défaut pour Supabase local
)

SUPABASE_ANON_KEY = os.getenv(
    "SUPABASE_ANON_KEY",
    # Clé anon par défaut pour Supabase local (développement uniquement)
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6ImFub24iLCJleHAiOjE5ODM4MTI5OTZ9.CRXP1A7WOeoJeXxjNni43kdQwgnWNReilDMblYTn_I0"
)

SUPABASE_SERVICE_KEY = os.getenv(
    "SUPABASE_SERVICE_KEY",
    # Clé service par défaut pour Supabase local (développement uniquement)
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZS1kZW1vIiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImV4cCI6MTk4MzgxMjk5Nn0.EGIM96RAZx35lJzdJsyH-qQwv8Hdp7fsn3W0YpN81IU"
)


def get_supabase_client(use_service_key: bool = False) -> Client:
    """
    Crée et retourne une instance du client Supabase

    Args:
        use_service_key (bool): Si True, utilise la SERVICE_KEY (bypass RLS).
                                Si False, utilise la ANON_KEY (respecte RLS).
                                Par défaut: False

    Returns:
        Client: Instance du client Supabase

    Note:
        - ANON_KEY: Pour les opérations normales qui respectent les politiques RLS
        - SERVICE_KEY: Pour les opérations administratives qui bypassent RLS
                      ⚠️ À utiliser avec précaution, uniquement côté serveur !
    """
    key = SUPABASE_SERVICE_KEY if use_service_key else SUPABASE_ANON_KEY
    return create_client(SUPABASE_URL, key)


def get_supabase_client_with_token(access_token: str) -> Client:
    """
    Crée et retourne une instance du client Supabase configurée avec un token JWT.
    Ce client respecte les politiques RLS avec l'identité de l'utilisateur authentifié.

    Args:
        access_token: Token JWT de l'utilisateur authentifié (format: "Bearer <token>" ou juste "<token>")

    Returns:
        Client: Instance du client Supabase configurée avec le token

    Note:
        Ce client permet aux politiques RLS d'identifier l'utilisateur via auth.uid()
    """
    # Nettoyer le token (enlever "Bearer " si présent)
    token = access_token.replace("Bearer ", "").strip() if access_token else ""

    if not token:
        # Si pas de token, retourner le client normal
        return create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

    # Créer le client
    client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

    # Configurer la session avec le token pour que RLS fonctionne
    # Essayer d'abord set_session, puis modifier les headers si nécessaire
    try:
        # set_session attend (access_token, refresh_token)
        # On utilise le même token pour les deux car on n'a que l'access_token
        client.auth.set_session(token, token)
    except Exception:
        # Si set_session échoue, modifier les headers HTTP directement
        # Le client Supabase utilise postgrest qui a une session HTTP
        try:
            # Accéder au client postgrest interne et modifier ses headers
            if hasattr(client, 'table'):
                # Créer une table temporaire pour accéder au client interne
                temp_table = client.table('_dummy_table_for_header_config')
                if hasattr(temp_table, '_client') and hasattr(temp_table._client, 'session'):
                    temp_table._client.session.headers.update({
                        'Authorization': f'Bearer {token}',
                        'apikey': SUPABASE_ANON_KEY
                    })
        except Exception:
            # Si tout échoue, on retourne le client tel quel
            # L'utilisateur devra utiliser supabase_admin à la place
            pass

    return client


# Instance globale du client avec ANON_KEY (par défaut, respecte RLS)
# Pour les opérations normales de l'application
supabase: Client = get_supabase_client(use_service_key=False)

# Instance globale du client avec SERVICE_KEY (bypass RLS)
# ⚠️ À utiliser uniquement pour les opérations administratives côté serveur
supabase_admin: Client = get_supabase_client(use_service_key=True)

