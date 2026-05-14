"""
AEGIS — Test de Capa 0: Criptografía Post-Cuántica (pqcrypto 0.4.0)
=====================================================================
Cero fallos tolerados — un fallo aquí es una brecha en toda la arquitectura.
"""

import hmac
import hashlib
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.crypto import (
    AegisCrypto,
    PostQuantumKEM,
    PostQuantumSigner,
    KeyDerivation,
    SecureRandom,
    Signature,
    KEMKeyPair,
)

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []


def test(name: str, fn):
    try:
        fn()
        print(f"  {PASS}  {name}")
        results.append((name, True))
    except Exception as e:
        print(f"  {FAIL}  {name}")
        print(f"         → {type(e).__name__}: {e}")
        results.append((name, False))


# ─────────────────────────────────────────────
# TESTS KEM — ML-KEM-1024
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 0: KEM (ML-KEM-1024)")
print("═══════════════════════════════════════════════")

kem = PostQuantumKEM()

def t_kem_keypair():
    kp = kem.generate_keypair()
    assert len(kp.public_key) == 1568, f"pk size: {len(kp.public_key)}"
    assert len(kp.secret_key) == 3168, f"sk size: {len(kp.secret_key)}"

def t_kem_roundtrip():
    kp  = kem.generate_keypair()
    res = kem.encapsulate(kp.public_key)
    ss  = kem.decapsulate(kp, res.ciphertext)
    assert hmac.compare_digest(res.shared_secret, ss), "Secretos no coinciden"

def t_kem_ss_longitud():
    kp  = kem.generate_keypair()
    res = kem.encapsulate(kp.public_key)
    assert len(res.shared_secret) == 32, f"ss size: {len(res.shared_secret)}"
    assert len(res.ciphertext)    == 1568

def t_kem_pares_distintos():
    kp1 = kem.generate_keypair()
    kp2 = kem.generate_keypair()
    assert kp1.public_key != kp2.public_key
    assert kp1.secret_key != kp2.secret_key

def t_kem_clave_incorrecta_da_secreto_distinto():
    kp1 = kem.generate_keypair()
    kp2 = kem.generate_keypair()
    res = kem.encapsulate(kp1.public_key)
    # Con kp2 (clave incorrecta) el secreto debe ser diferente
    ss_wrong = kem.decapsulate(kp2, res.ciphertext)
    assert not hmac.compare_digest(res.shared_secret, ss_wrong)

def t_kem_pk_invalida():
    try:
        kem.encapsulate(b"\x00" * 10)
        assert False, "Debería lanzar ValueError"
    except ValueError:
        pass

def t_kem_ct_invalido():
    kp = kem.generate_keypair()
    try:
        kem.decapsulate(kp, b"\x00" * 10)
        assert False, "Debería lanzar ValueError"
    except ValueError:
        pass

def t_kem_secreto_no_cero():
    kp  = kem.generate_keypair()
    res = kem.encapsulate(kp.public_key)
    assert res.shared_secret != bytes(32)

test("KEM — Tamaños de KeyPair correctos (pk=1568B sk=3168B)", t_kem_keypair)
test("KEM — Round-trip encapsular/decapsular", t_kem_roundtrip)
test("KEM — Shared secret 32B, ciphertext 1568B", t_kem_ss_longitud)
test("KEM — Pares distintos entre sí", t_kem_pares_distintos)
test("KEM — Clave incorrecta da secreto distinto", t_kem_clave_incorrecta_da_secreto_distinto)
test("KEM — Clave pública inválida → ValueError", t_kem_pk_invalida)
test("KEM — Ciphertext inválido → ValueError", t_kem_ct_invalido)
test("KEM — Secreto compartido no es cero", t_kem_secreto_no_cero)


# ─────────────────────────────────────────────
# TESTS FIRMA — ML-DSA-87 (Dilithium5)
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 0: FIRMA ML-DSA-87 (Dilithium5)")
print("═══════════════════════════════════════════════")

signer = PostQuantumSigner()

def t_dil_keypair():
    kp = signer.generate_keypair("dilithium5")
    assert len(kp.verify_key) == 2592, f"vk: {len(kp.verify_key)}"
    assert len(kp.sign_key)   == 4896, f"sk: {len(kp.sign_key)}"
    assert kp.algorithm == "dilithium5"

def t_dil_roundtrip():
    kp  = signer.generate_keypair("dilithium5")
    msg = b"AEGIS Dilithium5 test message"
    sig = signer.sign(kp, msg)
    assert signer.verify(kp.verify_key, msg, sig)

def t_dil_mensaje_alterado():
    kp  = signer.generate_keypair("dilithium5")
    msg = b"mensaje original"
    sig = signer.sign(kp, msg)
    assert not signer.verify(kp.verify_key, b"mensaje alterado", sig)

def t_dil_clave_incorrecta():
    kp1 = signer.generate_keypair("dilithium5")
    kp2 = signer.generate_keypair("dilithium5")
    msg = b"AEGIS auth check"
    sig = signer.sign(kp1, msg)
    assert not signer.verify(kp2.verify_key, msg, sig)

def t_dil_firma_corrupta():
    kp  = signer.generate_keypair("dilithium5")
    msg = b"test"
    sig = signer.sign(kp, msg)
    bad_sig = Signature(
        signature=bytes(len(sig.signature)),   # firma de ceros
        message_hash=sig.message_hash,
        algorithm="dilithium5"
    )
    assert not signer.verify(kp.verify_key, msg, bad_sig)

def t_dil_byte_extra_rechazado():
    kp  = signer.generate_keypair("dilithium5")
    msg = b"test message"
    sig = signer.sign(kp, msg)
    assert not signer.verify(kp.verify_key, msg + b"\x00", sig)

test("FIRMA Dilithium5 — Tamaños correctos (vk=2592B sk=4896B)", t_dil_keypair)
test("FIRMA Dilithium5 — Round-trip sign/verify", t_dil_roundtrip)
test("FIRMA Dilithium5 — Mensaje alterado rechazado", t_dil_mensaje_alterado)
test("FIRMA Dilithium5 — Clave incorrecta rechazada", t_dil_clave_incorrecta)
test("FIRMA Dilithium5 — Firma de ceros rechazada", t_dil_firma_corrupta)
test("FIRMA Dilithium5 — Byte extra rechazado", t_dil_byte_extra_rechazado)


# ─────────────────────────────────────────────
# TESTS FIRMA — SPHINCS+ SHA2-256s (respaldo)
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 0: FIRMA SPHINCS+-SHA2-256s")
print("═══════════════════════════════════════════════")

def t_sph_keypair():
    kp = signer.generate_keypair("sphincs_sha2_256s")
    assert len(kp.verify_key) == 64,  f"vk: {len(kp.verify_key)}"
    assert len(kp.sign_key)   == 128, f"sk: {len(kp.sign_key)}"
    assert kp.algorithm == "sphincs_sha2_256s"

def t_sph_roundtrip():
    kp  = signer.generate_keypair("sphincs_sha2_256s")
    msg = b"AEGIS SPHINCS+ test message"
    sig = signer.sign(kp, msg)
    assert signer.verify(kp.verify_key, msg, sig)

def t_sph_mensaje_alterado():
    kp  = signer.generate_keypair("sphincs_sha2_256s")
    msg = b"original"
    sig = signer.sign(kp, msg)
    assert not signer.verify(kp.verify_key, b"alterado", sig)

def t_sph_clave_incorrecta():
    kp1 = signer.generate_keypair("sphincs_sha2_256s")
    kp2 = signer.generate_keypair("sphincs_sha2_256s")
    msg = b"AEGIS SPHINCS+ auth"
    sig = signer.sign(kp1, msg)
    assert not signer.verify(kp2.verify_key, msg, sig)

def t_sph_no_intercambiable_con_dilithium():
    """Firma SPHINCS+ no debe verificar con Dilithium y viceversa."""
    kp_dil = signer.generate_keypair("dilithium5")
    kp_sph = signer.generate_keypair("sphincs_sha2_256s")
    msg    = b"cross-algorithm test"
    sig_dil = signer.sign(kp_dil, msg)
    # Intentar verificar firma Dilithium con clave SPHINCS+ → debe fallar
    assert not signer.verify(kp_sph.verify_key, msg, sig_dil)

test("FIRMA SPHINCS+ — Tamaños correctos (vk=64B sk=128B)", t_sph_keypair)
test("FIRMA SPHINCS+ — Round-trip sign/verify", t_sph_roundtrip)
test("FIRMA SPHINCS+ — Mensaje alterado rechazado", t_sph_mensaje_alterado)
test("FIRMA SPHINCS+ — Clave incorrecta rechazada", t_sph_clave_incorrecta)
test("FIRMA SPHINCS+ — No intercambiable con Dilithium", t_sph_no_intercambiable_con_dilithium)


# ─────────────────────────────────────────────
# TESTS KDF — HKDF-SHA3-512
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 0: KDF (HKDF-SHA3-512)")
print("═══════════════════════════════════════════════")

def t_kdf_longitud_32():
    ss  = SecureRandom.token(32)
    key = KeyDerivation.derive(ss, "aegis.test", 32)
    assert len(key) == 32

def t_kdf_longitud_64():
    ss  = SecureRandom.token(32)
    key = KeyDerivation.derive(ss, "aegis.mac", 64)
    assert len(key) == 64

def t_kdf_contexto_distinto_clave_distinta():
    ss = SecureRandom.token(32)
    salt = SecureRandom.token(64)
    k1 = KeyDerivation.derive(ss, "aegis.encrypt",  32, salt)
    k2 = KeyDerivation.derive(ss, "aegis.lockdown", 32, salt)
    assert k1 != k2

def t_kdf_determinista_mismo_salt():
    ss   = SecureRandom.token(32)
    salt = SecureRandom.token(64)
    k1   = KeyDerivation.derive(ss, "aegis.twin", 32, salt)
    k2   = KeyDerivation.derive(ss, "aegis.twin", 32, salt)
    assert k1 == k2

def t_kdf_session_keys_completas():
    ss   = SecureRandom.token(32)
    keys = KeyDerivation.derive_session_keys(ss)
    assert set(keys.keys()) == {"encrypt", "mac", "twin", "lockdown", "forensics"}
    assert len(keys["encrypt"])   == 32
    assert len(keys["mac"])       == 64
    assert len(keys["twin"])      == 32
    assert len(keys["lockdown"])  == 32
    assert len(keys["forensics"]) == 32

def t_kdf_no_cero():
    ss  = SecureRandom.token(32)
    key = KeyDerivation.derive(ss, "aegis.test", 32)
    assert key != bytes(32)

def t_kdf_secreto_distinto_clave_distinta():
    ss1  = SecureRandom.token(32)
    ss2  = SecureRandom.token(32)
    salt = SecureRandom.token(64)
    k1   = KeyDerivation.derive(ss1, "aegis.encrypt", 32, salt)
    k2   = KeyDerivation.derive(ss2, "aegis.encrypt", 32, salt)
    assert k1 != k2

test("KDF — Longitud 32B correcta", t_kdf_longitud_32)
test("KDF — Longitud 64B correcta (MAC)", t_kdf_longitud_64)
test("KDF — Contexto distinto → clave distinta", t_kdf_contexto_distinto_clave_distinta)
test("KDF — Determinista con mismo salt", t_kdf_determinista_mismo_salt)
test("KDF — Session keys completas y correctas", t_kdf_session_keys_completas)
test("KDF — Clave derivada no es cero", t_kdf_no_cero)
test("KDF — Secreto distinto → clave distinta", t_kdf_secreto_distinto_clave_distinta)


# ─────────────────────────────────────────────
# TEST FACHADA — AegisCrypto.self_test()
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 0: FACHADA COMPLETA")
print("═══════════════════════════════════════════════")

def t_self_test_completo():
    crypto = AegisCrypto()
    assert crypto.self_test() is True

def t_algoritmo_invalido():
    try:
        signer.generate_keypair("algoritmo_inventado")
        assert False, "Debería lanzar ValueError"
    except ValueError:
        pass

test("FACHADA — self_test() completo sin errores", t_self_test_completo)
test("FACHADA — Algoritmo inválido → ValueError", t_algoritmo_invalido)


# ─────────────────────────────────────────────
# RESUMEN FINAL
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed

if failed == 0:
    print(f"  RESULTADO: {passed}/{total} tests PASADOS ✓")
    print("  Capa 0 — Base criptográfica OPERATIVA")
    print("  AEGIS puede continuar construcción de Capa 1")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")
    print("  AEGIS NO puede arrancar con fallos en Capa 0")

print("═══════════════════════════════════════════════\n")

sys.exit(0 if failed == 0 else 1)
