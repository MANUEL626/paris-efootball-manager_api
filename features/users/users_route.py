from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from typing import Any, Dict, List
from uuid import UUID

from config.supabase_client import get_supabase_client_with_token

security = HTTPBearer()

router = APIRouter(prefix="/api/v1/users", tags=["Users"])


@router.get("/", response_model=List[Dict[str, Any]])
def get_all_users(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Retourne la liste des profils `public.users`.
    Le filtre est appliqué par les RLS (admins = tout, utilisateurs = soi-même).
    """
    client = get_supabase_client_with_token(credentials.credentials)
    res = client.table("users").select("*").order("created_at", desc=True).execute()
    return res.data or []


@router.get("/get_by_id/{user_id}", response_model=Dict[str, Any])
def get_user_by_id(user_id: UUID, credentials: HTTPAuthorizationCredentials = Depends(security)):
    """
    Retourne un utilisateur par son `id`.
    La visibilité est gérée par les RLS.
    """
    client = get_supabase_client_with_token(credentials.credentials)
    try:
        res = (
            client.table("users")
            .select("*")
            .eq("id", str(user_id))
            .single()
            .execute()
        )
        return res.data
    except Exception:
        raise HTTPException(status_code=404, detail="Utilisateur non trouvé")

