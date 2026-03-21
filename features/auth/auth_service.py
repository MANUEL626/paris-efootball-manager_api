"""
Service d'authentification Supabase pour la création d'utilisateurs.
- player / admin / super_admin : inscription sans email de confirmation ; mot de passe
  fourni par l'utilisateur (API) et enregistré dans Supabase Auth pour signInWithPassword.
"""

import os
import logging
from types import SimpleNamespace
from typing import Dict, Optional, Any
from uuid import UUID
from supabase import Client
from config.supabase_client import supabase_admin, SUPABASE_URL, SUPABASE_SERVICE_KEY
from config.redirect_urls import get_redirect_url_for_user_type

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Types créés sans email de confirmation (compte actif tout de suite).
USER_TYPES_WITHOUT_CONFIRMATION = ("player", "admin", "super_admin")


class AuthService:
    """Service d'authentification Supabase pour Python"""

    def __init__(self):
        """Initialise le service avec le client Supabase admin"""
        self.supabase: Client = supabase_admin
        self.supabase_url = SUPABASE_URL
        self.service_role_key = SUPABASE_SERVICE_KEY

        if not self.supabase_url or not self.service_role_key:
            raise ValueError(
                "SUPABASE_URL et SUPABASE_SERVICE_KEY doivent être définis "
                "dans les variables d'environnement"
            )

        logger.info("✅ Service d'authentification initialisé avec succès")

    def _admin_get_user_by_email(self, email: str) -> Optional[SimpleNamespace]:
        """
        Remplace get_user_by_email (non disponible sur SyncGoTrueAdminAPI en supabase-py).
        Utilise GET /auth/v1/admin/users avec le paramètre `filter` (GoTrue).
        """
        import requests

        try:
            # Le paramètre `filter` est une sous-chaîne (LIKE sur email / full_name), pas PostgREST.
            r = requests.get(
                f"{self.supabase_url}/auth/v1/admin/users",
                headers={
                    "apikey": self.service_role_key,
                    "Authorization": f"Bearer {self.service_role_key}",
                },
                params={
                    "page": 1,
                    "per_page": 100,
                    "filter": email,
                },
                timeout=15,
            )
            if r.status_code != 200:
                logger.warning("admin list users: %s %s", r.status_code, r.text)
                return None
            users = (r.json() or {}).get("users") or []
            email_norm = (email or "").strip().lower()
            for u in users:
                if (u.get("email") or "").lower() == email_norm:
                    return SimpleNamespace(user=SimpleNamespace(**u))
            return None
        except Exception as e:
            logger.warning("recherche utilisateur par email (admin): %s", e)
            return None

    async def create_typed_user(
            self,
            email: str,
            password: str,
            first_name: str,
            last_name: str,
            user_type: str,
            phone: Optional[str] = None,
            profile_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Crée un utilisateur typé. Le mot de passe est celui envoyé par le client (min. 6 caractères)
        et sert à `signInWithPassword` côté application.

        Args:
            email: Email de l'utilisateur
            password: Mot de passe choisi par l'utilisateur
            first_name: Prénom
            last_name: Nom
            user_type: Type d'utilisateur ('player', 'admin', 'super_admin')
            phone: Numéro de téléphone (optionnel)
            profile_data: Données supplémentaires selon le type d'utilisateur

        Returns:
            Dict contenant success, user_id, email, needs_email_confirmation, message, etc.
        """

        # Validation des données
        if not email or not first_name or not last_name:
            raise ValueError("Email, prénom et nom sont requis")
        if not password or len(password) < 6:
            raise ValueError("Le mot de passe est requis (minimum 6 caractères)")

        is_without_confirmation = user_type in USER_TYPES_WITHOUT_CONFIRMATION

        valid_user_types = ['player', 'admin', 'super_admin']
        if user_type not in valid_user_types:
            raise ValueError(f"Type d'utilisateur invalide. Types valides: {valid_user_types}")

        if profile_data is None:
            profile_data = {}

        actual_password = password
        if is_without_confirmation:
            logger.info(f"🔄 Création utilisateur '{user_type}' sans confirmation (mot de passe utilisateur)")
        else:
            logger.info(f"🔄 Début de la création d'un utilisateur de type '{user_type}' (avec confirmation email)")

        created_user_id = None

        try:
            # ============================================
            # ÉTAPE 0 : Vérifier si l'email existe déjà
            # ============================================
            logger.info("📝 ÉTAPE 0 : Vérification de l'existence de l'email...")
            try:
                existing_user = self._admin_get_user_by_email(email)
                if existing_user and existing_user.user:
                    error_message = f"Un compte avec l'email {email} existe déjà (ID: {existing_user.user.id})"
                    logger.warning(f"⚠️ {error_message}")
                    return {
                        "success": False,
                        "message": "Un compte avec cet email existe déjà",
                        "error": error_message,
                        "existing_user_id": existing_user.user.id
                    }
            except Exception as check_error:
                # Si l'erreur est "User not found", c'est OK, on peut continuer
                error_str = str(check_error).lower()
                if "not found" not in error_str and "does not exist" not in error_str:
                    # Autre type d'erreur lors de la vérification, on continue quand même
                    logger.warning(f"⚠️ Erreur lors de la vérification de l'email: {check_error}")

            # ============================================
            # ÉTAPE 1 : Créer l'utilisateur dans auth.users
            # ============================================
            logger.info("📝 ÉTAPE 1 : Création dans auth.users...")

            # Obtenir l'URL de redirection (utilisée seulement pour tenant avec confirmation)
            redirect_url = get_redirect_url_for_user_type(user_type)
            if not is_without_confirmation:
                logger.info(f"   URL de redirection pour {user_type}: {redirect_url}")

            # Préparer les métadonnées utilisateur
            user_metadata = {
                "signup_source": "python_backend",
                "firstname": first_name,
                "lastname": last_name,
                "user_type": user_type,
                "full_name": f"{first_name} {last_name}",
                "profile_data": profile_data
            }
            if phone:
                user_metadata["phone"] = phone
            if is_without_confirmation:
                # Mot de passe défini à l'inscription : pas d'obligation de changement à la 1re connexion
                user_metadata["must_change_password"] = False

            # Créer l'utilisateur dans auth.users
            # Tenant : email_confirm=False + email de confirmation
            # Owner/commercial/admin : email_confirm=True, pas d'email
            create_user_params = {
                "email": email,
                "password": actual_password,
                "email_confirm": is_without_confirmation,  # True = compte actif sans confirmation
                "user_metadata": user_metadata,
            }
            if not is_without_confirmation:
                create_user_params["email_redirect_to"] = redirect_url

            auth_response = self.supabase.auth.admin.create_user(create_user_params)

            if not auth_response.user:
                raise Exception("Échec de la création du compte d'authentification")

            created_user_id = auth_response.user.id

            logger.info(f"✅ ÉTAPE 1 : Utilisateur créé dans auth.users avec l'ID: {created_user_id}")
            logger.info(f"   Email: {email}")
            logger.info(f"   Email confirmé: {auth_response.user.email_confirmed_at is not None}")

            # ============================================
            # ÉTAPE 2 : Créer le profil dans public.users
            # ============================================
            logger.info("📝 ÉTAPE 2 : Création du profil dans public.users...")

            profile_created = False
            profile_already_exists = False

            # Essayer d'abord avec la fonction RPC create_user_profile
            try:
                profile_params = {
                    "p_user_id": str(created_user_id),
                    "p_email": email,
                    "p_firstname": first_name,
                    "p_lastname": last_name,
                    "p_user_type": user_type,
                    "p_phone": phone,
                    "p_profile_data": profile_data
                }

                profile_response = self.supabase.rpc(
                    "create_user_profile",
                    profile_params
                ).execute()

                # create_user_profile est conçu comme "SECURITY DEFINER" et peut
                # retourner `void`. Si l'appel ne lève pas d'exception, on considère
                # que le profil a été créé/assuré.
                logger.info("✅ ÉTAPE 2 : Profil utilisateur géré via create_user_profile()")
                profile_created = True

            except Exception as rpc_error:
                # Vérifier si l'erreur indique que le profil existe déjà
                error_message = str(rpc_error)
                if isinstance(rpc_error, dict):
                    error_message = rpc_error.get("message", str(rpc_error))

                if "existe déjà" in error_message or "already exists" in error_message.lower():
                    logger.info(f"ℹ️ Le profil existe déjà: {error_message}")
                    # Vérifier que le profil existe vraiment dans la base
                    try:
                        existing_user = self.supabase.table("users").select("id").eq("id",
                                                                                     str(created_user_id)).execute()
                        if existing_user.data and len(existing_user.data) > 0:
                            logger.info("✅ Profil vérifié: existe déjà dans public.users")
                            profile_already_exists = True
                        else:
                            logger.warning("⚠️ Message indique que le profil existe, mais non trouvé dans la base")
                            profile_already_exists = False
                    except Exception as check_error:
                        logger.warning(f"⚠️ Erreur lors de la vérification du profil: {check_error}")
                        profile_already_exists = False
                else:
                    logger.warning(f"⚠️ Fonction create_user_profile non disponible ou erreur: {rpc_error}")

                # Si le profil n'existe pas encore, créer manuellement
                if not profile_created and not profile_already_exists:
                    logger.info("📝 Création manuelle du profil...")

                    try:
                        # Créer le profil dans public.users
                        user_profile = {
                            "id": str(created_user_id),
                            "email": email,
                            "first_name": first_name,
                            "last_name": last_name,
                            "phone": phone,
                            "user_type": user_type,
                            "profile_picture": (
                                profile_data.get("profile_picture")
                                or profile_data.get("profilePicture")
                                or None
                            )
                        }

                        user_response = self.supabase.table("users").insert(user_profile).execute()
                        if user_response.data:
                            logger.info("✅ Profil créé dans public.users")
                            profile_created = True
                        else:
                            raise Exception("Échec de la création du profil dans public.users")
                    except Exception as insert_error:
                        # Vérifier si l'erreur est due à une clé dupliquée (profil existe déjà)
                        error_str = str(insert_error).lower()
                        if "duplicate key" in error_str or "already exists" in error_str or "23505" in str(
                                insert_error):
                            logger.info("ℹ️ Le profil existe déjà (erreur de clé dupliquée)")
                            profile_already_exists = True
                        else:
                            raise insert_error

            # Créer l'enregistrement dans la table spécialisée
            # Vérifier d'abord si l'enregistrement existe déjà (éviter les doublons)
            # create_user_profile() a déjà inséré players/admins pour ces types.
            if profile_created and user_type in ("player", "admin", "super_admin"):
                logger.info(
                    "✅ Ligne spécialisée (%s) déjà gérée par create_user_profile()",
                    user_type,
                )
            elif user_type == "tenant":
                # Vérifier si le tenant existe déjà
                existing_tenant = self.supabase.table("tenants").select("tenant_id").eq("user_id",
                                                                                        str(created_user_id)).execute()
                if existing_tenant.data and len(existing_tenant.data) > 0:
                    logger.info("✅ Tenant existe déjà, pas de création nécessaire")
                else:
                    # Créer le tenant avec seulement user_id (sans données d'onboarding)
                    # Les données d'onboarding seront ajoutées via l'endpoint /onboarding
                    tenant_data = {
                        "user_id": str(created_user_id)
                    }

                    tenant_response = self.supabase.table("tenants").insert(tenant_data).execute()
                    if tenant_response.data:
                        logger.info("✅ Tenant créé avec succès")
                    else:
                        logger.warning("⚠️ Échec création tenant")

            elif user_type == "owner":
                # Vérifier si l'owner existe déjà
                existing_owner = self.supabase.table("owners").select("owner_id").eq("user_id",
                                                                                     str(created_user_id)).execute()
                if existing_owner.data and len(existing_owner.data) > 0:
                    logger.info("✅ Owner existe déjà, pas de création nécessaire")
                else:
                    owner_data = {
                        "user_id": str(created_user_id)
                    }
                    if profile_data.get("address"):
                        owner_data["address"] = profile_data["address"]
                    if profile_data.get("commercial_id"):
                        # commercial_id peut être un UUID string ou un UUID object
                        comm_id = profile_data["commercial_id"]
                        owner_data["commercial_id"] = str(comm_id) if comm_id else None

                    owner_response = self.supabase.table("owners").insert(owner_data).execute()
                    if owner_response.data:
                        logger.info("✅ Owner créé avec succès")
                    else:
                        logger.warning("⚠️ Échec création owner")

            elif user_type == "commercial":
                # Vérifier si le commercial existe déjà
                existing_commercial = self.supabase.table("commercials").select("id").eq("user_id",
                                                                                         str(created_user_id)).execute()
                if existing_commercial.data and len(existing_commercial.data) > 0:
                    logger.info("✅ Commercial existe déjà, pas de création nécessaire")
                else:
                    commercial_data = {"user_id": str(created_user_id)}
                    commercial_response = self.supabase.table("commercials").insert(commercial_data).execute()
                    if commercial_response.data:
                        logger.info("✅ Commercial créé avec succès")
                    else:
                        logger.warning("⚠️ Échec création commercial")

            elif user_type == "player":
                username = (
                    profile_data.get("username")
                    or profile_data.get("user_name")
                    or profile_data.get("login")
                )
                if not username:
                    raise ValueError("username est requis pour un user de type player")

                existing_player = self.supabase.table("players").select("id").eq("user_id",
                                                                                     str(created_user_id)).execute()
                if existing_player.data and len(existing_player.data) > 0:
                    logger.info("✅ Player existe déjà, pas de création nécessaire")
                else:
                    player_data = {
                        "user_id": str(created_user_id),
                        "username": username
                    }
                    player_response = self.supabase.table("players").insert(player_data).execute()
                    if player_response.data:
                        logger.info("✅ Player créé avec succès")
                    else:
                        logger.warning("⚠️ Échec création player")

            elif user_type in ("admin", "super_admin"):
                # Vérifier si l'admin existe déjà
                existing_admin = self.supabase.table("admins").select("id").eq("user_id",
                                                                               str(created_user_id)).execute()
                if existing_admin.data and len(existing_admin.data) > 0:
                    logger.info("✅ Admin existe déjà, pas de création nécessaire")
                else:
                    admin_data = {"user_id": str(created_user_id)}
                    admin_response = self.supabase.table("admins").insert(admin_data).execute()
                    if admin_response.data:
                        logger.info("✅ Admin créé avec succès")
                    else:
                        logger.warning("⚠️ Échec création admin")

            if profile_created or profile_already_exists:
                logger.info("✅ ÉTAPE 2 : Profil et enregistrement spécialisé gérés avec succès")
            else:
                logger.warning("⚠️ ÉTAPE 2 : Problème lors de la création/gestion du profil")

            # ============================================
            # ÉTAPE 3 : Envoi de l'email de confirmation (tenants uniquement)
            # ============================================
            if not is_without_confirmation:
                logger.info("📧 ÉTAPE 3 : Envoi de l'email de confirmation...")
                logger.info("   URL à ajouter dans Supabase → Auth → URL Configuration → Redirect URLs: %s",
                            redirect_url)
                if redirect_url == "http://localhost:3000":
                    logger.warning(
                        "   ⚠️ Vous utilisez l'URL par défaut (localhost:3000). Pour une autre redirection, définissez AUTH_CONFIRM_BASE_URL ou ajoutez les URLs dans config/redirect_urls.py et dans Supabase.")
                try:
                    import requests
                    resend_body = {
                        "type": "signup",
                        "email": email,
                        "redirect_to": redirect_url,
                        "options": {"email_redirect_to": redirect_url},
                    }
                    email_response = requests.post(
                        f"{self.supabase_url}/auth/v1/resend",
                        headers={
                            "apikey": self.service_role_key,
                            "Authorization": f"Bearer {self.service_role_key}",
                            "Content-Type": "application/json",
                        },
                        json=resend_body,
                        timeout=15,
                    )
                    if email_response.status_code == 200:
                        logger.info("✅ Email envoyé. Redirection prévue: %s", redirect_url)
                    else:
                        logger.warning("⚠️ Resend %s: %s", email_response.status_code, email_response.text)
                except Exception as email_error:
                    logger.warning("⚠️ Erreur envoi email: %s", email_error)
            else:
                logger.info("✅ Compte actif sans envoi d'email (création sans confirmation)")

            # ============================================
            # RÉSULTAT FINAL
            # ============================================
            confirmed = auth_response.user.email_confirmed_at
            result = {
                "success": True,
                "user_id": created_user_id,
                "email": email,
                "user_type": user_type,
                "needs_email_confirmation": not is_without_confirmation,
                "email_confirmed_at": confirmed.isoformat() if confirmed else None,
                "message": (
                    "Compte créé avec succès. "
                    "Un email de confirmation a été envoyé. "
                    "Veuillez vérifier votre boîte mail et cliquer sur le lien de confirmation "
                    "avant de pouvoir vous connecter."
                )
            }
            if is_without_confirmation:
                result["message"] = (
                    "Compte créé avec succès. Compte actif immédiatement. "
                    "Connexion possible avec cet email et le mot de passe choisi."
                )
            return result

        except Exception as error:
            logger.error(f"❌ Erreur lors de la création de l'utilisateur: {error}")

            # ============================================
            # ROLLBACK : Supprimer l'utilisateur si le profil a échoué
            # ============================================
            if created_user_id:
                logger.warning("⚠️ Rollback : Suppression de l'utilisateur orphelin...")
                try:
                    self.supabase.auth.admin.delete_user(created_user_id)
                    logger.info("✅ Utilisateur orphelin supprimé avec succès")
                except Exception as rollback_error:
                    logger.error(f"❌ Erreur lors du rollback: {rollback_error}")

            # Gestion des erreurs spécifiques
            error_message = "Erreur lors de la création du compte"

            error_str = str(error).lower()
            if "already exists" in error_str or "already registered" in error_str:
                error_message = "Un compte avec cet email existe déjà"
            elif "password" in error_str and ("at least" in error_str or "too short" in error_str):
                error_message = "Le mot de passe doit contenir au moins 6 caractères"
            elif "invalid email" in error_str:
                error_message = "Adresse email invalide"
            elif "doit d'abord être créé dans auth.users" in error_str:
                error_message = "Erreur lors de la création du profil. L'utilisateur d'authentification existe mais le profil n'a pas pu être créé."

            return {
                "success": False,
                "message": error_message,
                "error": str(error)
            }

    def resend_confirmation_email(self, email: str) -> Dict[str, Any]:
        """
        Renvoie l'email de confirmation à un utilisateur.

        Args:
            email: Email de l'utilisateur

        Returns:
            Dict contenant success et message
        """
        try:
            logger.info(f"📧 Renvoi de l'email de confirmation pour: {email}")

            # Vérifier que l'utilisateur existe et n'a pas déjà confirmé
            auth_user = self._admin_get_user_by_email(email)

            if not auth_user or not auth_user.user:
                return {
                    "success": False,
                    "message": "Aucun utilisateur trouvé avec cet email"
                }

            if auth_user.user.email_confirmed_at:
                return {
                    "success": False,
                    "message": "Cet email a déjà été confirmé"
                }

            # Récupérer le type d'utilisateur pour la bonne URL de redirection
            user_meta = getattr(auth_user.user, "user_metadata", None) or {}
            user_type = (user_meta.get("user_type") or "tenant").lower()
            redirect_url = get_redirect_url_for_user_type(user_type)

            import requests

            response = requests.post(
                f"{self.supabase_url}/auth/v1/resend",
                headers={
                    "apikey": self.service_role_key,
                    "Authorization": f"Bearer {self.service_role_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "type": "signup",
                    "email": email,
                    "redirect_to": redirect_url,
                    "options": {"email_redirect_to": redirect_url},
                },
                timeout=15,
            )

            if response.status_code == 200:
                logger.info("✅ Email de confirmation renvoyé avec succès")
                return {
                    "success": True,
                    "message": "Email de confirmation renvoyé avec succès"
                }
            else:
                error_text = response.text
                logger.error(f"❌ Erreur renvoi email: {error_text}")
                return {
                    "success": False,
                    "message": f"Erreur lors du renvoi de l'email: {error_text}"
                }

        except Exception as error:
            logger.error(f"❌ Erreur lors du renvoi de l'email: {error}")
            return {
                "success": False,
                "message": f"Erreur lors du renvoi de l'email: {str(error)}"
            }

    def check_email_confirmation_status(self, user_id: UUID) -> Dict[str, Any]:
        """
        Vérifie si l'email d'un utilisateur a été confirmé.

        Args:
            user_id: UUID de l'utilisateur

        Returns:
            Dict contenant le statut de confirmation
        """
        try:
            auth_user = self.supabase.auth.admin.get_user_by_id(str(user_id))

            if not auth_user.user:
                return {
                    "success": False,
                    "message": "Utilisateur non trouvé"
                }

            is_confirmed = auth_user.user.email_confirmed_at is not None

            return {
                "success": True,
                "user_id": user_id,
                "email": auth_user.user.email,
                "email_confirmed": is_confirmed,
                "email_confirmed_at": auth_user.user.email_confirmed_at.isoformat() if auth_user.user.email_confirmed_at else None,
                "account_active": is_confirmed  # Le compte est actif seulement si confirmé
            }

        except Exception as error:
            logger.error(f"❌ Erreur lors de la vérification: {error}")
            return {
                "success": False,
                "message": f"Erreur lors de la vérification: {str(error)}"
            }

    def is_account_active(self, user_id: UUID) -> bool:
        """
        Vérifie si un compte est actif (email confirmé).

        Args:
            user_id: UUID de l'utilisateur

        Returns:
            True si le compte est actif, False sinon
        """
        try:
            auth_user = self.supabase.auth.admin.get_user_by_id(str(user_id))

            if not auth_user.user:
                return False

            # Le compte est actif seulement si email_confirmed_at n'est pas None
            return auth_user.user.email_confirmed_at is not None

        except Exception as error:
            logger.error(f"❌ Erreur lors de la vérification: {error}")
            return False

    def update_password_changed(self, user_id: UUID) -> Dict[str, Any]:
        """
        Met à jour le flag must_change_password à False après le premier changement de mot de passe.
        Appelé par le frontend après que l'utilisateur a changé son mot de passe temporaire.

        Args:
            user_id: UUID de l'utilisateur (auth.users)

        Returns:
            Dict avec success et message
        """
        import requests
        try:
            uid = str(user_id)
            auth_user = self.supabase.auth.admin.get_user_by_id(uid)
            if not auth_user.user:
                return {"success": False, "message": "Utilisateur non trouvé"}

            # Fusionner avec les métadonnées existantes pour ne pas écraser le reste
            current_meta = getattr(auth_user.user, "user_metadata", None) or {}
            if isinstance(current_meta, dict):
                new_metadata = {**current_meta, "must_change_password": False}
            else:
                new_metadata = {"must_change_password": False}

            # API Admin GoTrue : PUT /auth/v1/admin/users/:id
            response = requests.put(
                f"{self.supabase_url}/auth/v1/admin/users/{uid}",
                headers={
                    "apikey": self.service_role_key,
                    "Authorization": f"Bearer {self.service_role_key}",
                    "Content-Type": "application/json",
                },
                json={"user_metadata": new_metadata},
                timeout=15,
            )
            if response.status_code in (200, 201):
                logger.info("✅ must_change_password mis à False pour user_id %s", uid)
                return {"success": True, "message": "Mot de passe marqué comme changé"}
            logger.warning("⚠️ update_password_changed %s: %s", response.status_code, response.text)
            return {
                "success": False,
                "message": response.text or f"Erreur HTTP {response.status_code}",
            }
        except Exception as error:
            logger.error("❌ Erreur update_password_changed: %s", error)
            return {
                "success": False,
                "message": f"Erreur lors de la mise à jour: {str(error)}",
            }