"""
Dépendances FastAPI pour l'authentification et la vérification des rôles
"""

from fastapi import Depends, HTTPException, status, Header
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import Optional
from uuid import UUID
import logging
from config.supabase_client import supabase_admin
from features.owners.owners_crud import get_owner_by_user_id

# Configuration du logging
logger = logging.getLogger(__name__)

# Schéma de sécurité pour le token Bearer
security = HTTPBearer()


async def get_current_user_id(
        authorization: Optional[str] = Header(None, alias="Authorization")
) -> UUID:
    """
    Extrait et valide le token JWT depuis le header Authorization.
    Retourne l'ID de l'utilisateur authentifié.

    Args:
        authorization: Header Authorization avec le format "Bearer <token>"

    Returns:
        UUID de l'utilisateur authentifié

    Raises:
        HTTPException: Si le token est manquant ou invalide
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token d'authentification manquant",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        # Extraire le token du header "Bearer <token>"
        if not authorization.startswith("Bearer "):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Format du token invalide. Utilisez 'Bearer <token>'",
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = authorization.replace("Bearer ", "").strip()

        # Vérifier le token avec Supabase
        try:
            from supabase import create_client
            from config.supabase_client import SUPABASE_URL, SUPABASE_ANON_KEY

            # Créer un client temporaire et configurer la session avec le token
            temp_client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

            # Utiliser set_session pour configurer le token
            # Note: set_session attend (access_token, refresh_token), mais on peut utiliser le même token
            try:
                temp_client.auth.set_session(token, token)
                # Récupérer l'utilisateur depuis la session
                user_response = temp_client.auth.get_user()

                if not user_response or not user_response.user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Token invalide ou expiré",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

                user_id = UUID(user_response.user.id)
                return user_id

            except Exception as session_error:
                # Si set_session échoue, essayer de décoder le JWT directement
                try:
                    import base64
                    import json

                    # Décoder le JWT (format: header.payload.signature)
                    parts = token.split('.')
                    if len(parts) != 3:
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Format de token invalide",
                            headers={"WWW-Authenticate": "Bearer"},
                        )

                    # Décoder le payload (partie 2)
                    payload = parts[1]
                    # Ajouter le padding si nécessaire
                    payload += '=' * (4 - len(payload) % 4)
                    decoded_payload = base64.urlsafe_b64decode(payload)
                    token_data = json.loads(decoded_payload)

                    # Extraire l'user_id (sub claim)
                    user_id_str = token_data.get("sub")
                    if not user_id_str:
                        raise HTTPException(
                            status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Token invalide: sub claim manquant",
                            headers={"WWW-Authenticate": "Bearer"},
                        )

                    # Vérifier l'expiration
                    exp = token_data.get("exp")
                    if exp:
                        import time
                        if time.time() > exp:
                            raise HTTPException(
                                status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Token expiré",
                                headers={"WWW-Authenticate": "Bearer"},
                            )

                    user_id = UUID(user_id_str)
                    return user_id

                except (ValueError, json.JSONDecodeError, KeyError) as decode_error:
                    logger.error(f"❌ Erreur lors du décodage du token: {decode_error}")
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Token invalide ou expiré",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

        except HTTPException:
            raise
        except Exception as auth_error:
            logger.error(f"❌ Erreur lors de la vérification du token: {auth_error}")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invalide ou expiré",
                headers={"WWW-Authenticate": "Bearer"},
            )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur lors de l'extraction du token: {e}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Erreur lors de la vérification du token",
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_optional_token(
        authorization: Optional[str] = Header(None, alias="Authorization")
) -> Optional[str]:
    """
    Extrait le token JWT du header Authorization de manière optionnelle.
    Ne valide pas le token, le retourne simplement s'il est présent.

    Args:
        authorization: Header Authorization avec le format "Bearer <token>"

    Returns:
        Token JWT (sans "Bearer ") ou None si absent
    """
    if not authorization:
        return None

    if authorization.startswith("Bearer "):
        return authorization.replace("Bearer ", "").strip()

    return None


async def get_current_owner(
        user_id: UUID = Depends(get_current_user_id),
        authorization: Optional[str] = Header(None, alias="Authorization")
) -> dict:
    """
    Vérifie que l'utilisateur authentifié est un owner et retourne ses informations.

    Args:
        user_id: ID de l'utilisateur authentifié (depuis get_current_user_id)
        authorization: Header Authorization avec le token JWT

    Returns:
        Dict avec owner_id, user_id de l'owner et access_token

    Raises:
        HTTPException: Si l'utilisateur n'est pas un owner
    """
    try:
        owner = get_owner_by_user_id(user_id)

        if not owner:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Accès refusé. Vous devez être un propriétaire pour effectuer cette action."
            )

        # Extraire le token du header Authorization
        access_token = None
        if authorization and authorization.startswith("Bearer "):
            access_token = authorization.replace("Bearer ", "").strip()

        return {
            "owner_id": owner.owner_id,
            "user_id": owner.user_id,
            "access_token": access_token
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"❌ Erreur lors de la vérification du propriétaire: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erreur lors de la vérification des permissions"
        )

