"""
Routes FastAPI pour l'authentification et l'inscription
"""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from uuid import UUID

from config.supabase_client import supabase_admin
from features.auth.auth_service import AuthService
from features.auth.internal_bearer import require_internal_bearer
from features.users.users_model import UserProfileAggregatedResponse, UserType
from features.auth.auth_models import (
    SignUpRequest,
    SignUpResponse,
    ResendEmailRequest,
    ResendEmailResponse,
    ConfirmationStatusResponse,
    UpdatePasswordChangedRequest,
    UpdatePasswordChangedResponse,
)

# Création du routeur FastAPI
router = APIRouter(prefix="/api/v1/auth", tags=["Auth"])

# Instance du service d'authentification
auth_service = AuthService()


def _fetch_aggregate_profile(client, user_id: UUID) -> Optional[Dict[str, Any]]:
    """Assemble users + players ou admins. Retourne None si aucune ligne `users` pour cet id."""
    ures = (
        client.table("users")
        .select("*")
        .eq("id", str(user_id))
        .limit(1)
        .execute()
    )
    rows = ures.data or []
    if not rows:
        return None
    user = rows[0]

    uid = str(user_id)
    utype = user.get("user_type")
    player_id = None
    username = None
    admin_id = None

    # user_params peut ne pas exister si l'onboarding n'a pas été fait.
    upres = (
        client.table("user_params")
        .select("is_params_done")
        .eq("user_id", uid)
        .limit(1)
        .execute()
    )
    up_rows = upres.data or []
    is_params_done = (up_rows[0].get("is_params_done") if up_rows else False)

    if utype == UserType.player.value:
        pres = client.table("players").select("id,username").eq("user_id", uid).limit(1).execute()
        row = (pres.data or [None])[0]
        if row:
            player_id = row.get("id")
            username = row.get("username")
    elif utype in (UserType.admin.value, UserType.super_admin.value):
        ares = client.table("admins").select("id").eq("user_id", uid).limit(1).execute()
        row = (ares.data or [None])[0]
        if row:
            admin_id = row.get("id")

    return {
        "user_id": user["id"],
        "email": user["email"],
        "first_name": user["first_name"],
        "last_name": user["last_name"],
        "phone": user.get("phone"),
        "user_type": user["user_type"],
        "activity_status": user["activity_status"],
        "profile_picture": user.get("profile_picture"),
        "created_at": user["created_at"],
        "is_params_done": is_params_done,
        "player_id": player_id,
        "username": username,
        "admin_id": admin_id,
    }


@router.get("/profile/{user_id}", response_model=UserProfileAggregatedResponse)
def get_user_profile_aggregate(
    user_id: UUID,
    _: None = Depends(require_internal_bearer),
):
    """
    Profil agrégé (`public.users` + `players` ou `admins`).

    **Auth :** `Authorization: Bearer <INTERNAL_API_BEARER>` (secret partagé configuré côté serveur,
    défaut dev : `dev-internal-bearer`). Ce n’est pas le JWT Supabase utilisateur.

    Données lues avec la **service role** (bypass RLS). En prod : définir `INTERNAL_API_BEARER` dans `.env`.
    """
    payload = _fetch_aggregate_profile(supabase_admin, user_id)
    if not payload:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur non trouvé")
    return UserProfileAggregatedResponse.model_validate(payload)


@router.post("/signup", response_model=SignUpResponse, status_code=status.HTTP_201_CREATED)
async def signup_endpoint(signup_data: SignUpRequest):
    """
    Crée un nouvel utilisateur avec confirmation email requise.

    Cet endpoint crée uniquement les données de base de l'utilisateur :
    - Email et mot de passe (auth.users)
    - Prénom, nom, téléphone, type d'utilisateur (public.users)
    - Enregistrement de base dans la table spécialisée (tenants, owners, etc.)

    Les données d'onboarding (date_of_birth, id_card_number, emergency_contact, etc.)
    doivent être ajoutées séparément via l'endpoint /onboarding.

    Le processus :
    1. Crée l'utilisateur dans auth.users (avec email_confirm=False)
    2. Crée le profil dans public.users via create_user_profile()
    3. Crée l'enregistrement de base dans la table spécialisée (sans données d'onboarding)
    4. Supabase envoie automatiquement un email de confirmation

    Le compte reste INACTIF jusqu'à ce que l'utilisateur confirme son email.

    Args:
        signup_data: Données d'inscription (email, password, first_name, last_name, user_type, phone)
                    Note: Les données d'onboarding ne doivent PAS être incluses ici.

    Returns:
        SignUpResponse avec les informations de l'utilisateur créé (user_id nécessaire pour l'onboarding)

    Raises:
        HTTPException: Si la création échoue
    """
    try:
        result = await auth_service.create_typed_user(
            email=signup_data.email,
            password=signup_data.password,
            first_name=signup_data.first_name,
            last_name=signup_data.last_name,
            user_type=signup_data.user_type.value,  # Convertir l'enum en string
            phone=signup_data.phone,
            profile_data=signup_data.profile_data or {}
        )

        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result["message"]
            )

        return SignUpResponse(**result)

    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erreur lors de la création de l'utilisateur: {str(e)}"
        )


@router.post("/resend-confirmation", response_model=ResendEmailResponse)
async def resend_confirmation_endpoint(request: ResendEmailRequest):
    """
    Renvoie l'email de confirmation à un utilisateur.

    Args:
        request: Email de l'utilisateur

    Returns:
        ResendEmailResponse avec le résultat de l'opération

    Raises:
        HTTPException: Si le renvoi échoue
    """
    result = auth_service.resend_confirmation_email(request.email)

    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["message"]
        )

    return ResendEmailResponse(**result)


@router.get("/confirmation-status/{user_id}", response_model=ConfirmationStatusResponse)
async def check_confirmation_status_endpoint(user_id: UUID):
    """
    Vérifie si l'email d'un utilisateur a été confirmé.

    Args:
        user_id: UUID de l'utilisateur

    Returns:
        ConfirmationStatusResponse avec le statut de confirmation

    Raises:
        HTTPException: Si l'utilisateur n'est pas trouvé
    """
    result = auth_service.check_email_confirmation_status(user_id)

    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result.get("message", "Utilisateur non trouvé")
        )

    return ConfirmationStatusResponse(**result)


@router.get("/account-active/{user_id}")
async def check_account_active_endpoint(user_id: UUID):
    """
    Vérifie si un compte est actif (email confirmé).

    Args:
        user_id: UUID de l'utilisateur

    Returns:
        Dict avec account_active: bool
    """
    is_active = auth_service.is_account_active(user_id)

    return {
        "user_id": user_id,
        "account_active": is_active
    }


@router.post("/update-password-changed", response_model=UpdatePasswordChangedResponse)
async def update_password_changed_endpoint(body: UpdatePasswordChangedRequest):
    """
    Marque le mot de passe comme changé après le premier changement (mot de passe temporaire).
    Met à jour auth.users : user_metadata.must_change_password = false.
    À appeler côté frontend après supabase.auth.updateUser({ password: newPassword }).

    Body: { "userId": "uuid-supabase" }
    """
    result = auth_service.update_password_changed(body.userId)
    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["message"],
        )
    return UpdatePasswordChangedResponse(**result)