"""
Modèles Pydantic pour l'authentification et l'inscription
"""

from datetime import date
from typing import Optional, Dict, Any
from pydantic import BaseModel, EmailStr, Field
from uuid import UUID
from features.users.users_model import UserType


class SignUpRequest(BaseModel):
    """Requête d'inscription : mot de passe choisi par l'utilisateur (stocké dans Supabase Auth)."""
    email: EmailStr
    password: str = Field(..., min_length=6, description="Mot de passe choisi par l'utilisateur (connexion signInWithPassword)")
    first_name: str = Field(..., max_length=50)
    last_name: str = Field(..., max_length=50)
    user_type: UserType
    phone: Optional[str] = Field(None, max_length=20)
    profile_data: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Données supplémentaires selon le type d'utilisateur")


class SignUpResponse(BaseModel):
    """Modèle pour la réponse d'inscription"""
    success: bool
    user_id: Optional[UUID] = None
    email: Optional[str] = None
    user_type: Optional[str] = None
    needs_email_confirmation: bool = True
    email_confirmed_at: Optional[str] = None
    message: str
    # Réservé (ex. flux admin avec mot de passe généré) ; inscription standard = mot de passe dans la requête uniquement
    temp_password: Optional[str] = None


class ResendEmailRequest(BaseModel):
    """Modèle pour la requête de renvoi d'email"""
    email: EmailStr


class ResendEmailResponse(BaseModel):
    """Modèle pour la réponse de renvoi d'email"""
    success: bool
    message: str


class ConfirmationStatusResponse(BaseModel):
    """Modèle pour la réponse du statut de confirmation"""
    success: bool
    user_id: Optional[UUID] = None
    email: Optional[str] = None
    email_confirmed: bool
    email_confirmed_at: Optional[str] = None
    account_active: bool
    message: Optional[str] = None


class OnboardingRequest(BaseModel):
    """Modèle pour la requête d'onboarding (finalisation du profil utilisateur)"""
    user_id: UUID = Field(..., description="UUID de l'utilisateur")
    date_of_birth: Optional[date] = Field(None, description="Date de naissance")
    id_card_number: Optional[str] = Field(None, max_length=50, description="Numéro de pièce d'identité")
    emergency_contact_name: Optional[str] = Field(None, max_length=100, description="Nom du contact d'urgence")
    emergency_contact_phone: Optional[str] = Field(None, max_length=20, description="Téléphone du contact d'urgence")


class OnboardingResponse(BaseModel):
    """Modèle pour la réponse d'onboarding"""
    success: bool
    message: str
    user_id: Optional[UUID] = None


class UpdatePasswordChangedRequest(BaseModel):
    """Requête pour marquer le mot de passe comme changé (après premier changement obligatoire)"""
    userId: UUID = Field(..., description="UUID Supabase de l'utilisateur (auth.users)")
class UpdatePasswordChangedResponse(BaseModel):
    """Réponse de la route update-password-changed"""
    success: bool
    message: str