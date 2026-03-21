from enum import Enum


class UserType(str, Enum):
    """Types d'utilisateurs compatibles avec le schéma applicatif (public.user_type_enum)."""

    player = "player"
    admin = "admin"
    super_admin = "super_admin"
