"""
AEGIS — Capa 0: Base Criptográfica Post-Cuántica
=================================================
Librería: pqcrypto 0.4.0
KEM:      ml_kem_1024  (CRYSTALS-Kyber / NIST FIPS 203)
Firma:    ml_dsa_87    (CRYSTALS-Dilithium / NIST FIPS 204)
Respaldo: sphincs_sha2_256s_simple (hash-based, sin retícula)

Arquitectura agnóstica — el resto del sistema NUNCA importa pqcrypto
directamente. Todo pasa por AegisCrypto como fachada única.
Cambiar algoritmos = cambiar imports aquí. Nada más cambia.

REGLAS INVARIABLES:
- Cero hardcoding de claves
- Todas las claves efímeras por defecto
- verify() de pqcrypto lanza excepción si falla — nunca retorna False
  → envolvemos siempre en try/except para comportamiento uniforme
- Firmar siempre sobre SHA3-512 del mensaje — nunca el mensaje en bruto
"""

import hmac
import hashlib
import secrets
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

# ── pqcrypto 0.4.0 ────────────────────────────────────────────────────────────
import pqcrypto.kem.ml_kem_1024               as _kyber      # KEM primario
import pqcrypto.sign.ml_dsa_87                as _dilithium  # Firma primaria
import pqcrypto.sign.sphincs_sha2_256s_simple as _sphincs    # Firma respaldo
# ─────────────────────────────────────────────────────────────────────────────

logger = logging.getLogger("aegis.crypto")


# ─────────────────────────────────────────────
# CONSTANTES DE TAMAÑO — para validación
# ─────────────────────────────────────────────

class _Sizes:
    """Tamaños fijos de pqcrypto 0.4.0 — usados en validaciones internas."""
    KEM_PK     = _kyber.PUBLIC_KEY_SIZE       # 1568 B
    KEM_SK     = _kyber.SECRET_KEY_SIZE       # 3168 B
    KEM_CT     = _kyber.CIPHERTEXT_SIZE       # 1568 B
    KEM_SS     = _kyber.PLAINTEXT_SIZE        # 32 B
    DIL_PK     = _dilithium.PUBLIC_KEY_SIZE   # 2592 B
    DIL_SK     = _dilithium.SECRET_KEY_SIZE   # 4896 B
    DIL_SIG    = _dilithium.SIGNATURE_SIZE    # 4627 B
    SPHINCS_PK = _sphincs.PUBLIC_KEY_SIZE     # 64 B
    SPHINCS_SK = _sphincs.SECRET_KEY_SIZE     # 128 B


# ─────────────────────────────────────────────
# DATACLASSES DE RESULTADO — nunca bytes sueltos
# ─────────────────────────────────────────────

@dataclass(frozen=True)
class KEMKeyPair:
    """Par de claves KEM. public_key se comparte. secret_key nunca sale del proceso."""
    public_key: bytes
    secret_key: bytes
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return (f"KEMKeyPair(pk={len(self.public_key)}B "
                f"sk={len(self.secret_key)}B created_at={self.created_at})")


@dataclass(frozen=True)
class KEMResult:
    """Resultado de encapsulación: ciphertext para enviar, shared_secret para usar."""
    ciphertext: bytes      # enviar al receptor
    shared_secret: bytes   # NUNCA enviar — usar para derivar claves


@dataclass(frozen=True)
class SigKeyPair:
    """Par de claves de firma. verify_key es pública. sign_key nunca sale del proceso."""
    sign_key: bytes
    verify_key: bytes
    algorithm: str         # "dilithium5" | "sphincs_sha2_256s"
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return (f"SigKeyPair(algo={self.algorithm} "
                f"vk={len(self.verify_key)}B created_at={self.created_at})")


@dataclass(frozen=True)
class Signature:
    """Firma digital con metadatos."""
    signature: bytes
    message_hash: bytes    # SHA3-512 del mensaje original
    algorithm: str         # "dilithium5" | "sphincs_sha2_256s"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ─────────────────────────────────────────────
# MOTOR KEM — ML-KEM-1024 (CRYSTALS-Kyber)
# ─────────────────────────────────────────────

class PostQuantumKEM:
    """
    Key Encapsulation Mechanism post-cuántico.
    Basado en ML-KEM-1024 (NIST FIPS 203 — anteriormente Kyber1024).

    Flujo:
        1. Receptor genera keypair → comparte public_key
        2. Emisor llama encapsulate(public_key) → (ciphertext, shared_secret)
        3. Emisor envía ciphertext al receptor
        4. Receptor llama decapsulate(keypair, ciphertext) → shared_secret
        5. Ambos tienen el mismo shared_secret sin haberlo transmitido

    API pqcrypto 0.4.0:
        generate_keypair() → (pk, sk)
        encrypt(pk)        → (ciphertext, shared_secret)   # encapsulate
        decrypt(sk, ct)    → shared_secret                 # decapsulate
    """

    def generate_keypair(self) -> KEMKeyPair:
        """Genera un par de claves KEM efímero."""
        pk, sk = _kyber.generate_keypair()
        logger.debug(f"[KEM] KeyPair generado — pk={len(pk)}B sk={len(sk)}B")
        return KEMKeyPair(public_key=pk, secret_key=sk)

    def encapsulate(self, public_key: bytes) -> KEMResult:
        """
        Encapsula un secreto usando la clave pública del receptor.
        Retorna (ciphertext, shared_secret).
        shared_secret NUNCA se transmite — solo se usa localmente para derivar claves.
        """
        if len(public_key) != _Sizes.KEM_PK:
            raise ValueError(
                f"[KEM] Clave pública inválida: {len(public_key)}B "
                f"(esperado {_Sizes.KEM_PK}B)"
            )
        ct, ss = _kyber.encrypt(public_key)
        logger.debug(f"[KEM] Encapsulado — ct={len(ct)}B ss={len(ss)}B")
        return KEMResult(ciphertext=ct, shared_secret=ss)

    def decapsulate(self, keypair: KEMKeyPair, ciphertext: bytes) -> bytes:
        """
        Decapsula para obtener el secreto compartido.
        Retorna shared_secret — debe coincidir con el del emisor.
        """
        if len(ciphertext) != _Sizes.KEM_CT:
            raise ValueError(
                f"[KEM] Ciphertext inválido: {len(ciphertext)}B "
                f"(esperado {_Sizes.KEM_CT}B)"
            )
        ss = _kyber.decrypt(keypair.secret_key, ciphertext)
        logger.debug(f"[KEM] Decapsulado — ss={len(ss)}B")
        return ss


# ─────────────────────────────────────────────
# MOTOR DE FIRMA — ML-DSA-87 + SPHINCS+
# ─────────────────────────────────────────────

class PostQuantumSigner:
    """
    Firma digital post-cuántica.
    Primario:  ML-DSA-87 (NIST FIPS 204 — anteriormente Dilithium5)
    Respaldo:  SPHINCS+-SHA2-256s (hash-based, sin retícula — máxima longevidad)

    NOTA crítica sobre pqcrypto.verify():
        Retorna True si la firma es válida, False si no lo es.
        En errores de formato lanza excepción — capturamos todo con try/except.

    Firmamos siempre sobre SHA3-512(mensaje) — nunca el mensaje en bruto.
    Protege contra ataques de longitud y normaliza el tamaño de entrada al algoritmo.
    """

    def generate_keypair(self, algorithm: str = "dilithium5") -> SigKeyPair:
        """
        Genera par de claves de firma.
        algorithm: "dilithium5" (default) | "sphincs_sha2_256s"
        """
        if algorithm == "dilithium5":
            pk, sk = _dilithium.generate_keypair()
        elif algorithm == "sphincs_sha2_256s":
            pk, sk = _sphincs.generate_keypair()
        else:
            raise ValueError(f"[SIG] Algoritmo desconocido: {algorithm}")

        logger.debug(f"[SIG] KeyPair generado — algo={algorithm} vk={len(pk)}B sk={len(sk)}B")
        return SigKeyPair(sign_key=sk, verify_key=pk, algorithm=algorithm)

    def sign(self, keypair: SigKeyPair, message: bytes) -> Signature:
        """
        Firma un mensaje.
        Internamente firma SHA3-512(mensaje) — nunca el mensaje en bruto.
        """
        message_hash = hashlib.sha3_512(message).digest()

        if keypair.algorithm == "dilithium5":
            sig_bytes = _dilithium.sign(keypair.sign_key, message_hash)
        elif keypair.algorithm == "sphincs_sha2_256s":
            sig_bytes = _sphincs.sign(keypair.sign_key, message_hash)
        else:
            raise ValueError(f"[SIG] Algoritmo desconocido: {keypair.algorithm}")

        logger.debug(f"[SIG] Firmado — algo={keypair.algorithm} sig={len(sig_bytes)}B")
        return Signature(
            signature=sig_bytes,
            message_hash=message_hash,
            algorithm=keypair.algorithm
        )

    def verify(self, verify_key: bytes, message: bytes, signature: Signature) -> bool:
        """
        Verifica una firma.
        Retorna True si todo es correcto, False en cualquier fallo.
        NUNCA lanza excepción hacia el llamador.
        """
        try:
            # 1. Recomputar hash del mensaje recibido
            expected_hash = hashlib.sha3_512(message).digest()

            # 2. Verificar que el hash embebido coincide (timing-safe)
            if not hmac.compare_digest(expected_hash, signature.message_hash):
                logger.warning("[SIG] Hash del mensaje no coincide — posible manipulación")
                return False

            # 3. Verificar firma criptográfica
            #    pqcrypto.verify() retorna True/False directamente
            if signature.algorithm == "dilithium5":
                valid = _dilithium.verify(verify_key, signature.message_hash, signature.signature)
            elif signature.algorithm == "sphincs_sha2_256s":
                valid = _sphincs.verify(verify_key, signature.message_hash, signature.signature)
            else:
                logger.warning(f"[SIG] Algoritmo desconocido en firma: {signature.algorithm}")
                return False

            if not valid:
                logger.warning(f"[SIG] Verificación criptográfica fallida — algo={signature.algorithm}")
                return False

            logger.debug(f"[SIG] Verificación OK — algo={signature.algorithm}")
            return True

        except Exception as e:
            logger.warning(f"[SIG] Verificación fallida: {type(e).__name__}: {e}")
            return False


# ─────────────────────────────────────────────
# DERIVACIÓN DE CLAVES — de shared_secret a claves simétricas
# ─────────────────────────────────────────────

class KeyDerivation:
    """
    Deriva claves simétricas desde un shared_secret KEM (32 bytes de Kyber).
    Usa HKDF-SHA3-512 — ninguna clave simétrica se usa directamente del KEM.

    Misma shared_secret + distinto contexto = claves completamente distintas.
    """

    @staticmethod
    def derive(
        shared_secret: bytes,
        context: str,
        key_length: int = 32,
        salt: Optional[bytes] = None
    ) -> bytes:
        """
        Deriva una clave simétrica con contexto específico.

        Args:
            shared_secret: 32 bytes del KEM
            context:       Identificador de uso ("aegis.twin", "aegis.lockdown"...)
            key_length:    Longitud en bytes (32 = AES-256, 64 = MAC)
            salt:          Aleatorio — si None se genera uno seguro de 64 bytes

        Returns:
            bytes de longitud key_length
        """
        if salt is None:
            salt = secrets.token_bytes(64)

        context_bytes = context.encode("utf-8")

        # HKDF-SHA3-512
        # Extract: PRK = HMAC-SHA3-512(salt, IKM)
        prk = hmac.new(salt, shared_secret, hashlib.sha3_512).digest()

        # Expand: T(i) = HMAC-SHA3-512(PRK, T(i-1) || context || counter)
        okm = b""
        t = b""
        counter = 1
        while len(okm) < key_length:
            t = hmac.new(prk, t + context_bytes + bytes([counter]), hashlib.sha3_512).digest()
            okm += t
            counter += 1

        derived = okm[:key_length]
        logger.debug(f"[KDF] Clave derivada — contexto='{context}' longitud={key_length}B")
        return derived

    @staticmethod
    def derive_session_keys(shared_secret: bytes) -> dict:
        """
        Deriva el conjunto completo de claves para una sesión AEGIS.
        Una sola shared_secret → 5 claves con propósitos distintos.

        Returns:
            dict con claves:
                encrypt   → 32 B (cifrado simétrico)
                mac       → 64 B (autenticación de mensajes)
                twin      → 32 B (Capa 1 — gemelo en cadena)
                lockdown  → 32 B (Capa 4 — cierre atómico)
                forensics → 32 B (Capa 7 — análisis forense)
        """
        salt = secrets.token_bytes(64)  # mismo salt → coherencia entre claves
        return {
            "encrypt":   KeyDerivation.derive(shared_secret, "aegis.encrypt",   32, salt),
            "mac":       KeyDerivation.derive(shared_secret, "aegis.mac",       64, salt),
            "twin":      KeyDerivation.derive(shared_secret, "aegis.twin",      32, salt),
            "lockdown":  KeyDerivation.derive(shared_secret, "aegis.lockdown",  32, salt),
            "forensics": KeyDerivation.derive(shared_secret, "aegis.forensics", 32, salt),
        }


# ─────────────────────────────────────────────
# GENERADOR SEGURO — entropía y tokens
# ─────────────────────────────────────────────

class SecureRandom:
    """Generador criptográfico seguro — wrapper sobre secrets del sistema operativo."""

    @staticmethod
    def token(n_bytes: int = 32) -> bytes:
        """Token aleatorio de n bytes — para nonces, IDs, etc."""
        return secrets.token_bytes(n_bytes)

    @staticmethod
    def token_hex(n_bytes: int = 32) -> str:
        """Token hexadecimal — para logs y referencias."""
        return secrets.token_hex(n_bytes)

    @staticmethod
    def nonce(n_bytes: int = 16) -> bytes:
        """Nonce para cifrado simétrico — nunca reutilizar."""
        return secrets.token_bytes(n_bytes)

    @staticmethod
    def session_id() -> str:
        """ID de sesión único para trazabilidad interna de AEGIS."""
        ts  = int(datetime.now(timezone.utc).timestamp() * 1000)
        rnd = secrets.token_hex(8)
        return f"aegis-{ts}-{rnd}"


# ─────────────────────────────────────────────
# FACHADA PRINCIPAL — único punto de entrada
# ─────────────────────────────────────────────

class AegisCrypto:
    """
    Fachada única de Capa 0.
    El resto del sistema NUNCA importa pqcrypto directamente.
    Cambiar algoritmos = cambiar los imports al inicio de este archivo. Nada más.

    Uso típico:
        crypto = AegisCrypto()
        crypto.self_test()                              # obligatorio al arranque

        kp  = crypto.kem.generate_keypair()
        res = crypto.kem.encapsulate(remote_pk)
        ss  = crypto.kem.decapsulate(kp, res.ciphertext)
        keys = crypto.kdf.derive_session_keys(ss)

        sig_kp = crypto.signer.generate_keypair()
        sig    = crypto.signer.sign(sig_kp, data)
        ok     = crypto.signer.verify(sig_kp.verify_key, data, sig)
    """

    def __init__(self):
        self.kem    = PostQuantumKEM()
        self.signer = PostQuantumSigner()
        self.kdf    = KeyDerivation()
        self.rand   = SecureRandom()
        logger.info(
            "[AEGIS.Crypto] Capa 0 inicializada — "
            "KEM=ML-KEM-1024  SIG=ML-DSA-87  BACKUP=SPHINCS+-SHA2-256s"
        )

    def self_test(self) -> bool:
        """
        Autoverificación completa al arranque.
        Prueba KEM round-trip + firma Dilithium5 + firma SPHINCS+ + KDF.
        AEGIS no debe arrancar si este test falla.
        Retorna True si todo pasa. Lanza RuntimeError si algo falla.
        """
        logger.info("[AEGIS.Crypto] Ejecutando self-test de Capa 0...")

        # ── Test KEM ──────────────────────────────────────────────────────────
        kp_a = self.kem.generate_keypair()
        kp_b = self.kem.generate_keypair()

        res  = self.kem.encapsulate(kp_b.public_key)
        ss_b = self.kem.decapsulate(kp_b, res.ciphertext)

        if not hmac.compare_digest(res.shared_secret, ss_b):
            raise RuntimeError("[AEGIS.Crypto] FALLO — KEM: secretos no coinciden")

        ss_wrong = self.kem.decapsulate(kp_a, res.ciphertext)
        if hmac.compare_digest(res.shared_secret, ss_wrong):
            raise RuntimeError("[AEGIS.Crypto] FALLO — KEM: clave incorrecta produjo secreto válido")

        # ── Test KDF ──────────────────────────────────────────────────────────
        keys = self.kdf.derive_session_keys(res.shared_secret)
        if set(keys.keys()) != {"encrypt", "mac", "twin", "lockdown", "forensics"}:
            raise RuntimeError("[AEGIS.Crypto] FALLO — KDF: claves incompletas")
        if any(len(v) != 32 for k, v in keys.items() if k != "mac"):
            raise RuntimeError("[AEGIS.Crypto] FALLO — KDF: longitud de clave incorrecta")
        if len(keys["mac"]) != 64:
            raise RuntimeError("[AEGIS.Crypto] FALLO — KDF: clave MAC debe ser 64B")

        # ── Test Dilithium5 ───────────────────────────────────────────────────
        message  = b"AEGIS self-test payload " + self.rand.token(16)
        sig_kp   = self.signer.generate_keypair("dilithium5")
        sig      = self.signer.sign(sig_kp, message)

        if not self.signer.verify(sig_kp.verify_key, message, sig):
            raise RuntimeError("[AEGIS.Crypto] FALLO — Dilithium5: verificación no pasa")
        if self.signer.verify(sig_kp.verify_key, message + b"\x00", sig):
            raise RuntimeError("[AEGIS.Crypto] FALLO — Dilithium5: acepta mensaje alterado")

        wrong_kp = self.signer.generate_keypair("dilithium5")
        if self.signer.verify(wrong_kp.verify_key, message, sig):
            raise RuntimeError("[AEGIS.Crypto] FALLO — Dilithium5: acepta clave incorrecta")

        # ── Test SPHINCS+ ─────────────────────────────────────────────────────
        sph_kp  = self.signer.generate_keypair("sphincs_sha2_256s")
        sph_sig = self.signer.sign(sph_kp, message)

        if not self.signer.verify(sph_kp.verify_key, message, sph_sig):
            raise RuntimeError("[AEGIS.Crypto] FALLO — SPHINCS+: verificación no pasa")
        if self.signer.verify(sph_kp.verify_key, message + b"\x00", sph_sig):
            raise RuntimeError("[AEGIS.Crypto] FALLO — SPHINCS+: acepta mensaje alterado")

        logger.info("[AEGIS.Crypto] Self-test PASADO — Capa 0 operativa ✓")
        return True
