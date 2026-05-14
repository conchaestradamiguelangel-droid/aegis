"""
AEGIS — Capa 2: Campo de Minas
================================
Señuelos invisibles distribuidos en todas las capas del sistema.

FILOSOFÍA:
    Ningún usuario legítimo toca jamás un señuelo.
    Si algo lo toca → es un intruso → detección instantánea sin falsos positivos.
    El señuelo no bloquea — registra, alimenta información falsa y alerta.

CINCO TIPOS DE SEÑUELOS:
    Tipo 1 — Archivos y rutas falsas
    Tipo 2 — Credenciales falsas
    Tipo 3 — Endpoints y APIs falsas
    Tipo 4 — Datos falsos en memoria
    Tipo 5 — Identidades falsas completas (perfil máximo atractivo para atacante)

REGLA ABSOLUTA:
    Ningún legítimo toca ningún señuelo jamás.
    Contacto = intruso. Detección instantánea. Cero falsos positivos.

CONECTORES:
    → Capa 3 (detección): dispara evento de detección al primer contacto
    → Capa 7 (forense): registro completo de cada contacto
    → Capa 8 (aprendizaje): patrón de contacto para aprendizaje colectivo
"""

import asyncio
import hashlib
import json
import logging
import secrets
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional, Callable

logger = logging.getLogger("aegis.minefield")


# ─────────────────────────────────────────────
# ENUMS
# ─────────────────────────────────────────────

class MineType(str, Enum):
    FILE        = "FILE"        # archivos y rutas falsas
    CREDENTIAL  = "CREDENTIAL"  # credenciales falsas
    ENDPOINT    = "ENDPOINT"    # endpoints y APIs falsas
    MEMORY      = "MEMORY"      # datos falsos en memoria
    IDENTITY    = "IDENTITY"    # identidades falsas completas


class ContactSeverity(str, Enum):
    CRITICAL = "CRITICAL"   # identidad o credencial tocada — máxima prioridad
    HIGH     = "HIGH"       # endpoint o archivo de config tocado
    MEDIUM   = "MEDIUM"     # archivo genérico o dato en memoria tocado


# ─────────────────────────────────────────────
# EVENTO DE CONTACTO — lo que se genera al tocar una mina
# ─────────────────────────────────────────────

@dataclass
class MineContact:
    """Registro completo de un contacto con un señuelo."""
    contact_id:   str
    timestamp:    datetime
    mine_id:      str
    mine_type:    MineType
    mine_name:    str           # nombre del señuelo tocado
    severity:     ContactSeverity
    source_ip:    str
    source_port:  int
    method:       str           # GET / POST / READ / CONNECT / SCAN...
    payload:      bytes         # datos enviados por el atacante (max 256B)
    fingerprint:  str           # hash del perfil del atacante
    response_sent:str           # qué respuesta falsa se envió

    def to_dict(self) -> dict:
        d = asdict(self)
        d["timestamp"]  = self.timestamp.isoformat()
        d["mine_type"]  = self.mine_type.value
        d["severity"]   = self.severity.value
        d["payload"]    = self.payload.hex()
        return d


# ─────────────────────────────────────────────
# TIPO 1 — ARCHIVOS Y RUTAS FALSAS
# ─────────────────────────────────────────────

class FakeFileSystem:
    """
    Archivos y rutas falsas con contenido internamente coherente pero completamente falso.
    Nombres diseñados para atraer a cualquier atacante que escanee el sistema.
    """

    # Catálogo de señuelos — nombre → contenido falso coherente
    FILES: dict = {
        "backup.json": json.dumps({
            "database": {
                "host": "db-prod-01.internal",
                "port": 5432,
                "name": "production_db",
                "user": "db_admin",
                "password": "Xk9#mP2$vL8nQ4wR",
                "backup_schedule": "0 2 * * *",
                "last_backup": "2026-04-09T02:00:00Z"
            },
            "storage": {
                "bucket": "aegis-prod-backups",
                "region": "eu-west-1",
                "access_key": "AKIAIOSFODNN7EXAMPLE",
                "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
            }
        }, indent=2),

        "admin/database/credentials.env": (
            "DB_HOST=db-prod-01.internal\n"
            "DB_PORT=5432\n"
            "DB_NAME=production_db\n"
            "DB_USER=db_admin\n"
            "DB_PASSWORD=Xk9#mP2$vL8nQ4wR\n"
            "DB_SSL=true\n"
            "REDIS_URL=redis://:hN3$kP9mQ2vL@redis-prod:6379/0\n"
            "MONGO_URI=mongodb://admin:Jw7#xK4nM9pQ@mongo-prod:27017/admin\n"
        ),

        ".env.production": (
            "NODE_ENV=production\n"
            "API_SECRET=sk_live_9xKm2pQw4vL8nR3jH7tY5uB\n"
            "JWT_SECRET=ey9xKm2pQw4vL8nR3jH7tY5uBmN6kP1qW\n"
            "STRIPE_SECRET_KEY=sk_live_51NxKm2pQw4vL8nR3j\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "ENCRYPTION_KEY=aes256:Xk9mP2vL8nQ4wR7jH3tY5uBmN6kP1qW\n"
        ),

        "config/secrets.yaml": (
            "production:\n"
            "  database:\n"
            "    master_password: 'Xk9#mP2$vL8nQ4wR'\n"
            "    replica_password: 'Jw7#xK4nM9pQ2vL'\n"
            "  api_keys:\n"
            "    internal: 'int_9xKm2pQw4vL8nR3jH7tY5uB'\n"
            "    external: 'ext_sk_live_51NxKm2pQw4vL8nR3j'\n"
            "  certificates:\n"
            "    private_key_path: '/etc/ssl/private/prod.key'\n"
            "    passphrase: 'cert_Xk9mP2vL8n'\n"
        ),

        "logs/admin_access.log": (
            "[2026-04-08 08:14:22] admin LOGIN OK ip=10.0.1.5\n"
            "[2026-04-08 09:30:11] admin ACCESS /admin/users ip=10.0.1.5\n"
            "[2026-04-08 11:45:33] sysadmin LOGIN OK ip=10.0.1.8\n"
            "[2026-04-09 02:00:01] backup_user LOGIN OK ip=10.0.1.10\n"
            "[2026-04-09 02:00:05] backup_user ACCESS /admin/database/export ip=10.0.1.10\n"
            "[2026-04-09 02:03:44] backup_user LOGOUT ip=10.0.1.10\n"
        ),

        "keys/master.pem": (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29P2rFj7yjXzGi\n"
            "nDPMRCGBEMQdLNSaGhCFdGFiVBGFkqfXaXCMVjHOQbTlmMJOmcHmXFbqHKFMMXC\n"
            "AEGIS-FAKE-KEY-DO-NOT-USE-IN-PRODUCTION-THIS-IS-A-TRAP-SEQUENCE\n"
            "-----END RSA PRIVATE KEY-----\n"
        ),
    }

    def get(self, path: str) -> Optional[str]:
        """Retorna contenido del archivo señuelo si existe."""
        return self.FILES.get(path)

    def exists(self, path: str) -> bool:
        return path in self.FILES

    def list_paths(self) -> list:
        return list(self.FILES.keys())

    def register_contact(
        self,
        path: str,
        source_ip: str,
        source_port: int,
        method: str = "READ",
        payload: bytes = b""
    ) -> tuple:
        """
        Registra contacto con un archivo señuelo.
        Retorna (MineContact, respuesta_falsa).
        """
        content      = self.FILES.get(path, "")
        contact_id   = secrets.token_hex(6).upper()
        fingerprint  = hashlib.sha256(
            f"{source_ip}|{path}|{payload.hex()}".encode()
        ).hexdigest()[:16]

        contact = MineContact(
            contact_id   = contact_id,
            timestamp    = datetime.now(timezone.utc),
            mine_id      = f"file:{path}",
            mine_type    = MineType.FILE,
            mine_name    = path,
            severity     = (ContactSeverity.CRITICAL
                            if any(k in path for k in ("credential", ".env", "secret", "key"))
                            else ContactSeverity.HIGH),
            source_ip    = source_ip,
            source_port  = source_port,
            method       = method,
            payload      = payload[:256],
            fingerprint  = fingerprint,
            response_sent= content[:80],
        )
        logger.warning(
            f"[MINE.FILE] ⚠ CONTACTO — path='{path}' "
            f"ip={source_ip} id={contact_id} sev={contact.severity.value}"
        )
        return contact, content   # devuelve contenido falso para engañar al atacante


# ─────────────────────────────────────────────
# TIPO 2 — CREDENCIALES FALSAS
# ─────────────────────────────────────────────

class FakeCredentials:
    """
    Credenciales falsas con formato correcto pero completamente inútiles.
    Formato válido — datos falsos.
    """

    CREDENTIALS: dict = {
        "admin":        {"password": "Adm1n#Secure2026!", "role": "superadmin",   "mfa": "TOTP:BASE32SECRET3232"},
        "db_admin":     {"password": "Xk9#mP2$vL8nQ4wR",  "role": "dba",         "mfa": None},
        "sysadmin":     {"password": "Sys@dm1n$2026Prod",  "role": "sysadmin",    "mfa": "TOTP:BASE32SECRET6464"},
        "backup_user":  {"password": "Bkp#Usr$Safe2026",   "role": "backup",      "mfa": None},
        "api_service":  {"password": "Api$Svc#Token2026",  "role": "service",     "mfa": None},
    }

    API_TOKENS: dict = {
        "sk_live_9xKm2pQw4vL8nR3jH7tY5uB":      {"scope": "full_access",   "owner": "admin"},
        "int_9xKm2pQw4vL8nR3jH7tY5uB":           {"scope": "internal_api",  "owner": "api_service"},
        "ext_sk_live_51NxKm2pQw4vL8nR3j":        {"scope": "external_api",  "owner": "api_service"},
        "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.AEGISFAKE": {
            "scope": "admin_panel", "owner": "sysadmin"
        },
    }

    def validate_credential(self, username: str, password: str) -> Optional[dict]:
        """
        'Valida' una credencial falsa.
        Siempre retorna datos que parecen correctos — para mantener al atacante engañado.
        """
        cred = self.CREDENTIALS.get(username)
        if cred and cred["password"] == password:
            return {
                "authenticated": True,
                "user":          username,
                "role":          cred["role"],
                "session_token": f"sess_{secrets.token_hex(16)}",
                "expires_in":    3600,
            }
        return None

    def validate_token(self, token: str) -> Optional[dict]:
        """'Valida' un token falso — siempre parece válido para tokens conocidos."""
        tk = self.API_TOKENS.get(token)
        if tk:
            return {"valid": True, "scope": tk["scope"], "owner": tk["owner"]}
        return None

    def list_usernames(self) -> list:
        return list(self.CREDENTIALS.keys())

    def list_tokens(self) -> list:
        return list(self.API_TOKENS.keys())

    def register_contact(
        self,
        resource: str,
        source_ip: str,
        source_port: int,
        method: str,
        payload: bytes = b""
    ) -> tuple:
        contact_id  = secrets.token_hex(6).upper()
        fingerprint = hashlib.sha256(
            f"{source_ip}|{resource}|{payload.hex()}".encode()
        ).hexdigest()[:16]

        # Respuesta falsa convincente
        response = json.dumps({
            "authenticated": True,
            "session":       secrets.token_hex(16),
            "expires_in":    3600,
        })

        contact = MineContact(
            contact_id   = contact_id,
            timestamp    = datetime.now(timezone.utc),
            mine_id      = f"credential:{resource}",
            mine_type    = MineType.CREDENTIAL,
            mine_name    = resource,
            severity     = ContactSeverity.CRITICAL,
            source_ip    = source_ip,
            source_port  = source_port,
            method       = method,
            payload      = payload[:256],
            fingerprint  = fingerprint,
            response_sent= response[:80],
        )
        logger.warning(
            f"[MINE.CRED] ⚠ CONTACTO — resource='{resource}' "
            f"ip={source_ip} id={contact_id} sev=CRITICAL"
        )
        return contact, response


# ─────────────────────────────────────────────
# TIPO 3 — ENDPOINTS Y APIS FALSAS
# ─────────────────────────────────────────────

class FakeEndpoints:
    """
    Endpoints y APIs falsas que responden correctamente hasta cierto punto,
    luego detectan y registran.
    Parecen llevar a recursos valiosos — responden con datos falsos convincentes.
    """

    ENDPOINTS: dict = {
        "/admin":                   {"service": "Admin Panel",      "auth_required": True},
        "/admin/users":             {"service": "User Management",  "auth_required": True},
        "/admin/database/export":   {"service": "DB Export",        "auth_required": True},
        "/api/v1/keys":             {"service": "Key Management",   "auth_required": True},
        "/api/v1/tokens":           {"service": "Token Service",    "auth_required": True},
        "/api/internal/config":     {"service": "Config API",       "auth_required": True},
        "/api/internal/secrets":    {"service": "Secrets API",      "auth_required": True},
        "/.git/config":             {"service": "Git Config",       "auth_required": False},
        "/wp-admin":                {"service": "WordPress Admin",  "auth_required": True},
        "/phpmyadmin":              {"service": "phpMyAdmin",       "auth_required": True},
        "/actuator/env":            {"service": "Spring Actuator",  "auth_required": False},
        "/actuator/health":         {"service": "Health Check",     "auth_required": False},
    }

    # Respuestas falsas por endpoint
    RESPONSES: dict = {
        "/admin": json.dumps({
            "status": "ok", "users_online": 3,
            "last_backup": "2026-04-09T02:03:44Z",
            "system_health": "nominal"
        }),
        "/admin/users": json.dumps({
            "users": [
                {"id": 1, "username": "admin",       "role": "superadmin", "last_login": "2026-04-10T08:14:22Z"},
                {"id": 2, "username": "sysadmin",    "role": "sysadmin",   "last_login": "2026-04-09T11:45:33Z"},
                {"id": 3, "username": "backup_user", "role": "backup",     "last_login": "2026-04-09T02:00:01Z"},
            ]
        }),
        "/api/v1/keys": json.dumps({
            "keys": [
                {"id": "key_001", "name": "master_key",    "created": "2026-01-01", "active": True},
                {"id": "key_002", "name": "backup_key",    "created": "2026-02-15", "active": True},
                {"id": "key_003", "name": "service_key",   "created": "2026-03-20", "active": True},
            ]
        }),
        "/.git/config": (
            "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n"
            "[remote \"origin\"]\n\turl = git@github.com:company/production-backend.git\n"
            "[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n"
        ),
        "/actuator/env": json.dumps({
            "activeProfiles": ["production"],
            "propertySources": [{"name": "applicationConfig", "properties": {
                "server.port": {"value": "8443"},
                "spring.datasource.url": {"value": "jdbc:postgresql://db-prod-01:5432/production_db"},
            }}]
        }),
    }

    def exists(self, path: str) -> bool:
        return path in self.ENDPOINTS

    def get_response(self, path: str) -> str:
        return self.RESPONSES.get(path, json.dumps({"status": "ok", "data": []}))

    def list_paths(self) -> list:
        return list(self.ENDPOINTS.keys())

    def register_contact(
        self,
        path: str,
        source_ip: str,
        source_port: int,
        method: str = "GET",
        payload: bytes = b""
    ) -> tuple:
        contact_id  = secrets.token_hex(6).upper()
        fingerprint = hashlib.sha256(
            f"{source_ip}|{path}|{method}".encode()
        ).hexdigest()[:16]

        response = self.get_response(path)

        severity = (ContactSeverity.CRITICAL
                    if any(k in path for k in ("secret", "key", "token", "export"))
                    else ContactSeverity.HIGH)

        contact = MineContact(
            contact_id   = contact_id,
            timestamp    = datetime.now(timezone.utc),
            mine_id      = f"endpoint:{path}",
            mine_type    = MineType.ENDPOINT,
            mine_name    = path,
            severity     = severity,
            source_ip    = source_ip,
            source_port  = source_port,
            method       = method,
            payload      = payload[:256],
            fingerprint  = fingerprint,
            response_sent= response[:80],
        )
        logger.warning(
            f"[MINE.ENDPOINT] ⚠ CONTACTO — path='{path}' method={method} "
            f"ip={source_ip} id={contact_id} sev={contact.severity.value}"
        )
        return contact, response


# ─────────────────────────────────────────────
# TIPO 4 — DATOS FALSOS EN MEMORIA
# ─────────────────────────────────────────────

class FakeMemoryData:
    """
    Datos falsos en memoria — visibles para un atacante que escanea,
    completamente inútiles en la práctica.
    Claves de sesión con formato válido, tokens de auth, contextos falsos.
    """

    def __init__(self):
        # Generamos en init para que parezcan dinámicos — como datos reales en memoria
        self._session_keys: dict = {
            f"sess_{secrets.token_hex(8)}": {
                "user":       "admin",
                "created_at": "2026-04-10T08:14:22Z",
                "expires_at": "2026-04-10T09:14:22Z",
                "ip":         "10.0.1.5",
                "scopes":     ["read", "write", "admin"],
            },
            f"sess_{secrets.token_hex(8)}": {
                "user":       "sysadmin",
                "created_at": "2026-04-10T07:30:00Z",
                "expires_at": "2026-04-10T08:30:00Z",
                "ip":         "10.0.1.8",
                "scopes":     ["read", "write"],
            },
        }
        self._auth_tokens: dict = {
            f"Bearer {secrets.token_hex(32)}": {
                "subject":    "admin",
                "issuer":     "aegis-auth",
                "scope":      "full_access",
                "exp":        9999999999,
            },
            f"Bearer {secrets.token_hex(32)}": {
                "subject":    "api_service",
                "issuer":     "aegis-auth",
                "scope":      "internal_api",
                "exp":        9999999999,
            },
        }
        self._crypto_contexts: dict = {
            "master_context": {
                "algorithm":  "AES-256-GCM",
                "key_id":     f"key_{secrets.token_hex(8)}",
                "nonce":      secrets.token_hex(12),
                "created_at": "2026-04-10T00:00:00Z",
            }
        }

    def get_session_keys(self) -> dict:
        return dict(self._session_keys)

    def get_auth_tokens(self) -> dict:
        return dict(self._auth_tokens)

    def get_crypto_contexts(self) -> dict:
        return dict(self._crypto_contexts)

    def register_contact(
        self,
        resource: str,
        source_ip: str,
        source_port: int,
        method: str = "SCAN",
        payload: bytes = b""
    ) -> tuple:
        contact_id  = secrets.token_hex(6).upper()
        fingerprint = hashlib.sha256(
            f"{source_ip}|{resource}".encode()
        ).hexdigest()[:16]

        response = json.dumps({"sessions": list(self._session_keys.keys())[:2]})

        contact = MineContact(
            contact_id   = contact_id,
            timestamp    = datetime.now(timezone.utc),
            mine_id      = f"memory:{resource}",
            mine_type    = MineType.MEMORY,
            mine_name    = resource,
            severity     = ContactSeverity.HIGH,
            source_ip    = source_ip,
            source_port  = source_port,
            method       = method,
            payload      = payload[:256],
            fingerprint  = fingerprint,
            response_sent= response[:80],
        )
        logger.warning(
            f"[MINE.MEMORY] ⚠ CONTACTO — resource='{resource}' "
            f"ip={source_ip} id={contact_id}"
        )
        return contact, response


# ─────────────────────────────────────────────
# TIPO 5 — IDENTIDADES FALSAS COMPLETAS
# Perfil máximo — el más atractivo para un atacante
# ─────────────────────────────────────────────

class FakeIdentities:
    """
    Identidades falsas completas con historial de actividad convincente.
    Cuentas con permisos aparentes sobre recursos valiosos.
    Perfil diseñado para ser el objetivo más atractivo posible para un atacante.
    """

    # La identidad más atractiva: admin con historial completo y permisos totales
    IDENTITIES: dict = {
        "admin_master": {
            "user_id":      "usr_00001",
            "username":     "admin",
            "email":        "admin@company.internal",
            "role":         "superadmin",
            "permissions":  [
                "database.read", "database.write", "database.export",
                "users.manage", "keys.manage", "config.edit",
                "billing.view", "audit.view", "system.restart"
            ],
            "resources": {
                "databases":    ["production_db", "analytics_db", "backup_db"],
                "servers":      ["web-prod-01", "web-prod-02", "db-prod-01", "redis-prod"],
                "repositories": ["production-backend", "production-frontend", "infrastructure"],
                "secrets":      ["master_key", "backup_key", "cert_private_key"],
            },
            "credentials": {
                "password":      "Adm1n#Secure2026!",
                "api_key":       "sk_live_9xKm2pQw4vL8nR3jH7tY5uB",
                "ssh_key_id":    "key_admin_rsa_4096",
                "mfa_secret":    "JBSWY3DPEHPK3PXP",
                "recovery_code": "AEGIS-FAKE-8842-TRAP-2291",
            },
            "login_history": [
                {"ts": "2026-04-10T08:14:22Z", "ip": "10.0.1.5",  "success": True,  "ua": "Mozilla/5.0"},
                {"ts": "2026-04-09T09:30:11Z", "ip": "10.0.1.5",  "success": True,  "ua": "Mozilla/5.0"},
                {"ts": "2026-04-08T17:22:44Z", "ip": "10.0.1.5",  "success": True,  "ua": "curl/7.88.0"},
                {"ts": "2026-04-07T11:05:33Z", "ip": "10.0.1.8",  "success": False, "ua": "Python/requests"},
                {"ts": "2026-04-06T08:00:01Z", "ip": "10.0.1.5",  "success": True,  "ua": "Mozilla/5.0"},
            ],
            "activity_pattern": {
                "typical_hours":  "08:00-18:00 UTC+1",
                "typical_ips":    ["10.0.1.5", "10.0.1.8"],
                "last_actions":   [
                    "Exported production database backup",
                    "Rotated master API key",
                    "Added new server to monitoring",
                    "Viewed billing dashboard",
                    "Modified firewall rules",
                ],
                "active_sessions": 1,
            },
            "profile_score": "MAXIMUM_VALUE",   # señal para el atacante de que esto es el objetivo
        },

        "sysadmin_infra": {
            "user_id":   "usr_00002",
            "username":  "sysadmin",
            "email":     "sysadmin@company.internal",
            "role":      "sysadmin",
            "permissions": [
                "servers.manage", "network.configure",
                "deploy.production", "logs.access", "monitoring.admin"
            ],
            "credentials": {
                "password":   "Sys@dm1n$2026Prod",
                "ssh_key_id": "key_sysadmin_rsa_4096",
                "api_key":    "int_9xKm2pQw4vL8nR3jH7tY5uB",
            },
            "login_history": [
                {"ts": "2026-04-10T09:15:00Z", "ip": "10.0.1.8", "success": True},
                {"ts": "2026-04-09T11:45:33Z", "ip": "10.0.1.8", "success": True},
            ],
        },
    }

    def get_profile(self, identity_id: str) -> Optional[dict]:
        return self.IDENTITIES.get(identity_id)

    def get_most_attractive(self) -> dict:
        """Retorna el perfil más atractivo para un atacante — admin_master."""
        return self.IDENTITIES["admin_master"]

    def list_identities(self) -> list:
        return list(self.IDENTITIES.keys())

    def register_contact(
        self,
        identity_id: str,
        source_ip: str,
        source_port: int,
        method: str = "ACCESS",
        payload: bytes = b""
    ) -> tuple:
        contact_id  = secrets.token_hex(6).upper()
        fingerprint = hashlib.sha256(
            f"{source_ip}|{identity_id}|{payload.hex()}".encode()
        ).hexdigest()[:16]

        profile  = self.IDENTITIES.get(identity_id, {})
        response = json.dumps({
            "user":        profile.get("username", "unknown"),
            "role":        profile.get("role", "unknown"),
            "permissions": profile.get("permissions", [])[:3],
            "token":       f"sess_{secrets.token_hex(16)}",
        })

        contact = MineContact(
            contact_id   = contact_id,
            timestamp    = datetime.now(timezone.utc),
            mine_id      = f"identity:{identity_id}",
            mine_type    = MineType.IDENTITY,
            mine_name    = identity_id,
            severity     = ContactSeverity.CRITICAL,
            source_ip    = source_ip,
            source_port  = source_port,
            method       = method,
            payload      = payload[:256],
            fingerprint  = fingerprint,
            response_sent= response[:80],
        )
        logger.warning(
            f"[MINE.IDENTITY] ⚠ CONTACTO CRÍTICO — identity='{identity_id}' "
            f"ip={source_ip} id={contact_id} sev=CRITICAL"
        )
        return contact, response


# ─────────────────────────────────────────────
# FACHADA PRINCIPAL — AegisMinefield
# ─────────────────────────────────────────────

class AegisMinefield:
    """
    Fachada de Capa 2 — Campo de Minas.
    Orquesta los cinco tipos de señuelos y gestiona los tres conectores.

    Uso:
        minefield = AegisMinefield()
        minefield.register_detection_callback(capa3_handler)
        minefield.register_forensic_callback(capa7_handler)
        minefield.register_learning_callback(capa8_handler)

        # Cuando el atacante toca un señuelo:
        contact, response = minefield.touch_file("backup.json", "1.2.3.4", 54321)
        contact, response = minefield.touch_credential("admin", "1.2.3.4", 54321)
        contact, response = minefield.touch_endpoint("/admin", "1.2.3.4", 54321)
        contact, response = minefield.touch_memory("session_keys", "1.2.3.4", 54321)
        contact, response = minefield.touch_identity("admin_master", "1.2.3.4", 54321)
    """

    def __init__(self):
        self.files      = FakeFileSystem()
        self.credentials= FakeCredentials()
        self.endpoints  = FakeEndpoints()
        self.memory     = FakeMemoryData()
        self.identities = FakeIdentities()

        self._contacts: list = []
        self._callbacks_detection: list = []   # → Capa 3
        self._callbacks_forensic:  list = []   # → Capa 7
        self._callbacks_learning:  list = []   # → Capa 8

        logger.info(
            "[AEGIS.Minefield] Capa 2 inicializada — "
            f"{len(self.files.list_paths())} archivos | "
            f"{len(self.credentials.list_usernames())} credenciales | "
            f"{len(self.endpoints.list_paths())} endpoints | "
            f"memoria activa | "
            f"{len(self.identities.list_identities())} identidades"
        )

    # ── Registro de callbacks ─────────────────────────────────────────────────

    def register_detection_callback(self, cb: Callable):
        """Capa 3 — recibe MineContact en tiempo real al primer contacto."""
        self._callbacks_detection.append(cb)

    def register_forensic_callback(self, cb: Callable):
        """Capa 7 — recibe MineContact para análisis forense."""
        self._callbacks_forensic.append(cb)

    def register_learning_callback(self, cb: Callable):
        """Capa 8 — recibe patrón de contacto para aprendizaje colectivo."""
        self._callbacks_learning.append(cb)

    # ── Puntos de contacto — uno por tipo de señuelo ─────────────────────────

    async def touch_file(
        self, path: str, source_ip: str, source_port: int,
        method: str = "READ", payload: bytes = b""
    ) -> tuple:
        """Contacto con archivo señuelo. Retorna (MineContact, contenido_falso)."""
        contact, response = self.files.register_contact(
            path, source_ip, source_port, method, payload
        )
        await self._dispatch(contact)
        return contact, response

    async def touch_credential(
        self, resource: str, source_ip: str, source_port: int,
        method: str = "AUTH", payload: bytes = b""
    ) -> tuple:
        """Contacto con credencial señuelo."""
        contact, response = self.credentials.register_contact(
            resource, source_ip, source_port, method, payload
        )
        await self._dispatch(contact)
        return contact, response

    async def touch_endpoint(
        self, path: str, source_ip: str, source_port: int,
        method: str = "GET", payload: bytes = b""
    ) -> tuple:
        """Contacto con endpoint señuelo."""
        contact, response = self.endpoints.register_contact(
            path, source_ip, source_port, method, payload
        )
        await self._dispatch(contact)
        return contact, response

    async def touch_memory(
        self, resource: str, source_ip: str, source_port: int,
        method: str = "SCAN", payload: bytes = b""
    ) -> tuple:
        """Contacto con dato falso en memoria."""
        contact, response = self.memory.register_contact(
            resource, source_ip, source_port, method, payload
        )
        await self._dispatch(contact)
        return contact, response

    async def touch_identity(
        self, identity_id: str, source_ip: str, source_port: int,
        method: str = "ACCESS", payload: bytes = b""
    ) -> tuple:
        """Contacto con identidad falsa."""
        contact, response = self.identities.register_contact(
            identity_id, source_ip, source_port, method, payload
        )
        await self._dispatch(contact)
        return contact, response

    # ── Dispatcher interno ────────────────────────────────────────────────────

    async def _dispatch(self, contact: MineContact):
        """
        Dispara los tres conectores simultáneamente:
        → Capa 3 (detección), Capa 7 (forense), Capa 8 (aprendizaje).
        """
        self._contacts.append(contact)

        callbacks = (
            self._callbacks_detection +
            self._callbacks_forensic  +
            self._callbacks_learning
        )
        for cb in callbacks:
            try:
                if asyncio.iscoroutinefunction(cb):
                    await cb(contact)
                else:
                    cb(contact)
            except Exception as e:
                logger.warning(f"[MINE] Error en callback: {e}")

    # ── Consultas ─────────────────────────────────────────────────────────────

    def get_contact_log(self) -> list:
        """Historial completo de contactos — para Capa 7."""
        return [c.to_dict() for c in self._contacts]

    def get_contacts_by_ip(self, ip: str) -> list:
        """Todos los contactos de una IP específica."""
        return [c for c in self._contacts if c.source_ip == ip]

    def get_contacts_by_severity(self, severity: ContactSeverity) -> list:
        """Contactos filtrados por severidad."""
        return [c for c in self._contacts if c.severity == severity]

    def total_contacts(self) -> int:
        return len(self._contacts)

    def status(self) -> dict:
        return {
            "files":            len(self.files.list_paths()),
            "credentials":      len(self.credentials.list_usernames()),
            "api_tokens":       len(self.credentials.list_tokens()),
            "endpoints":        len(self.endpoints.list_paths()),
            "identities":       len(self.identities.list_identities()),
            "total_contacts":   self.total_contacts(),
            "critical_contacts":len(self.get_contacts_by_severity(ContactSeverity.CRITICAL)),
        }
