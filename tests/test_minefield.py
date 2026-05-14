"""
AEGIS — Test de Capa 2: Campo de Minas
========================================
Cero falsos positivos tolerados.
Cero señuelos sin respuesta al contacto.
"""

import asyncio
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from layers.minefield import (
    AegisMinefield, MineContact, MineType, ContactSeverity,
    FakeFileSystem, FakeCredentials, FakeEndpoints,
    FakeMemoryData, FakeIdentities,
)

PASS = "✓ PASS"
FAIL = "✗ FAIL"
results = []

IP  = "1.2.3.4"
PORT= 54321


def test(name: str, fn):
    try:
        if asyncio.iscoroutinefunction(fn):
            asyncio.run(fn())
        else:
            fn()
        print(f"  {PASS}  {name}")
        results.append((name, True))
    except Exception as e:
        print(f"  {FAIL}  {name}")
        print(f"         → {type(e).__name__}: {e}")
        results.append((name, False))


# ─────────────────────────────────────────────
# TIPO 1 — ARCHIVOS Y RUTAS FALSAS
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 2: Tipo 1 — Archivos")
print("═══════════════════════════════════════════════")

def t_archivo_existe():
    fs = FakeFileSystem()
    assert fs.exists("backup.json")
    assert fs.exists("admin/database/credentials.env")
    assert fs.exists(".env.production")
    assert fs.exists("config/secrets.yaml")

def t_archivo_contenido_coherente():
    fs      = FakeFileSystem()
    content = fs.get("backup.json")
    assert content is not None
    assert "database" in content
    assert "password" in content

def t_archivo_credenciales_env():
    fs = FakeFileSystem()
    c  = fs.get(".env.production")
    assert "API_SECRET" in c
    assert "JWT_SECRET" in c
    assert "AWS_ACCESS_KEY_ID" in c

def t_archivo_contacto_genera_mine_contact():
    fs = FakeFileSystem()
    contact, response = fs.register_contact("backup.json", IP, PORT)
    assert isinstance(contact, MineContact)
    assert contact.mine_type == MineType.FILE
    assert contact.source_ip == IP
    assert len(contact.contact_id) > 0

def t_archivo_contacto_credential_es_critical():
    fs = FakeFileSystem()
    contact, _ = fs.register_contact("admin/database/credentials.env", IP, PORT)
    assert contact.severity == ContactSeverity.CRITICAL

def t_archivo_lista_no_vacia():
    fs = FakeFileSystem()
    assert len(fs.list_paths()) >= 5

test("ARCHIVO — Señuelos clave existen", t_archivo_existe)
test("ARCHIVO — backup.json tiene contenido coherente", t_archivo_contenido_coherente)
test("ARCHIVO — .env.production tiene variables reales", t_archivo_credenciales_env)
test("ARCHIVO — Contacto genera MineContact correcto", t_archivo_contacto_genera_mine_contact)
test("ARCHIVO — credentials.env → severidad CRITICAL", t_archivo_contacto_credential_es_critical)
test("ARCHIVO — Catálogo tiene ≥5 señuelos", t_archivo_lista_no_vacia)


# ─────────────────────────────────────────────
# TIPO 2 — CREDENCIALES FALSAS
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 2: Tipo 2 — Credenciales")
print("═══════════════════════════════════════════════")

def t_credencial_admin_existe():
    fc   = FakeCredentials()
    result = fc.validate_credential("admin", "Adm1n#Secure2026!")
    assert result is not None
    assert result["authenticated"] is True
    assert result["role"] == "superadmin"

def t_credencial_respuesta_incluye_token():
    fc     = FakeCredentials()
    result = fc.validate_credential("admin", "Adm1n#Secure2026!")
    assert "session_token" in result
    assert result["session_token"].startswith("sess_")

def t_credencial_token_api_valido():
    fc    = FakeCredentials()
    token = fc.list_tokens()[0]
    result = fc.validate_token(token)
    assert result is not None
    assert result["valid"] is True

def t_credencial_contacto_es_critical():
    fc = FakeCredentials()
    contact, _ = fc.register_contact("admin", IP, PORT, "AUTH")
    assert contact.severity == ContactSeverity.CRITICAL
    assert contact.mine_type == MineType.CREDENTIAL

def t_credencial_lista_usuarios():
    fc = FakeCredentials()
    users = fc.list_usernames()
    assert "admin" in users
    assert "sysadmin" in users
    assert len(users) >= 3

test("CREDENCIAL — admin se valida como superadmin", t_credencial_admin_existe)
test("CREDENCIAL — Respuesta incluye session_token", t_credencial_respuesta_incluye_token)
test("CREDENCIAL — Token API parece válido", t_credencial_token_api_valido)
test("CREDENCIAL — Contacto siempre es CRITICAL", t_credencial_contacto_es_critical)
test("CREDENCIAL — Catálogo tiene ≥3 usuarios", t_credencial_lista_usuarios)


# ─────────────────────────────────────────────
# TIPO 3 — ENDPOINTS Y APIS FALSAS
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 2: Tipo 3 — Endpoints")
print("═══════════════════════════════════════════════")

def t_endpoint_admin_existe():
    fe = FakeEndpoints()
    assert fe.exists("/admin")
    assert fe.exists("/admin/users")
    assert fe.exists("/.git/config")
    assert fe.exists("/api/v1/keys")

def t_endpoint_respuesta_coherente():
    fe  = FakeEndpoints()
    res = fe.get_response("/admin/users")
    assert "users" in res
    assert "admin" in res

def t_endpoint_git_config():
    fe  = FakeEndpoints()
    res = fe.get_response("/.git/config")
    assert "remote" in res
    assert "origin" in res

def t_endpoint_contacto_genera_mine_contact():
    fe = FakeEndpoints()
    contact, response = fe.register_contact("/admin", IP, PORT, "GET")
    assert isinstance(contact, MineContact)
    assert contact.mine_type == MineType.ENDPOINT
    assert len(response) > 0

def t_endpoint_secrets_es_critical():
    fe = FakeEndpoints()
    contact, _ = fe.register_contact("/api/internal/secrets", IP, PORT, "GET")
    assert contact.severity == ContactSeverity.CRITICAL

def t_endpoint_lista_no_vacia():
    fe = FakeEndpoints()
    assert len(fe.list_paths()) >= 8

test("ENDPOINT — /admin y /.git/config existen", t_endpoint_admin_existe)
test("ENDPOINT — /admin/users responde con usuarios falsos", t_endpoint_respuesta_coherente)
test("ENDPOINT — /.git/config responde con config git", t_endpoint_git_config)
test("ENDPOINT — Contacto genera MineContact correcto", t_endpoint_contacto_genera_mine_contact)
test("ENDPOINT — /api/internal/secrets → CRITICAL", t_endpoint_secrets_es_critical)
test("ENDPOINT — Catálogo tiene ≥8 endpoints", t_endpoint_lista_no_vacia)


# ─────────────────────────────────────────────
# TIPO 4 — DATOS EN MEMORIA
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 2: Tipo 4 — Memoria")
print("═══════════════════════════════════════════════")

def t_memoria_session_keys_existen():
    fm   = FakeMemoryData()
    keys = fm.get_session_keys()
    assert len(keys) >= 1
    for k, v in keys.items():
        assert k.startswith("sess_")
        assert "user" in v
        assert "scopes" in v

def t_memoria_auth_tokens_existen():
    fm     = FakeMemoryData()
    tokens = fm.get_auth_tokens()
    assert len(tokens) >= 1
    for k in tokens.keys():
        assert "Bearer" in k

def t_memoria_crypto_context_existe():
    fm  = FakeMemoryData()
    ctx = fm.get_crypto_contexts()
    assert "master_context" in ctx
    assert "algorithm" in ctx["master_context"]

def t_memoria_contacto_genera_mine_contact():
    fm = FakeMemoryData()
    contact, response = fm.register_contact("session_keys", IP, PORT)
    assert isinstance(contact, MineContact)
    assert contact.mine_type == MineType.MEMORY

def t_memoria_instancias_distintas():
    """Dos instancias deben generar tokens distintos — parecen datos vivos."""
    fm1 = FakeMemoryData()
    fm2 = FakeMemoryData()
    keys1 = list(fm1.get_session_keys().keys())
    keys2 = list(fm2.get_session_keys().keys())
    assert keys1 != keys2

test("MEMORIA — Session keys tienen formato sess_*", t_memoria_session_keys_existen)
test("MEMORIA — Auth tokens tienen formato Bearer *", t_memoria_auth_tokens_existen)
test("MEMORIA — Contexto cripto existe", t_memoria_crypto_context_existe)
test("MEMORIA — Contacto genera MineContact correcto", t_memoria_contacto_genera_mine_contact)
test("MEMORIA — Instancias distintas generan tokens distintos", t_memoria_instancias_distintas)


# ─────────────────────────────────────────────
# TIPO 5 — IDENTIDADES FALSAS
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 2: Tipo 5 — Identidades")
print("═══════════════════════════════════════════════")

def t_identidad_admin_master_existe():
    fi      = FakeIdentities()
    profile = fi.get_profile("admin_master")
    assert profile is not None
    assert profile["role"] == "superadmin"

def t_identidad_admin_tiene_permiso_total():
    fi      = FakeIdentities()
    profile = fi.get_profile("admin_master")
    perms   = profile["permissions"]
    assert "database.export" in perms
    assert "keys.manage" in perms
    assert "system.restart" in perms

def t_identidad_admin_tiene_recursos_valiosos():
    fi      = FakeIdentities()
    profile = fi.get_profile("admin_master")
    res     = profile["resources"]
    assert "production_db" in res["databases"]
    assert len(res["servers"]) >= 2
    assert len(res["secrets"]) >= 2

def t_identidad_admin_tiene_historial():
    fi      = FakeIdentities()
    profile = fi.get_profile("admin_master")
    history = profile["login_history"]
    assert len(history) >= 3
    assert all("ts" in h and "ip" in h for h in history)

def t_identidad_mas_atractiva_es_admin():
    fi      = FakeIdentities()
    profile = fi.get_most_attractive()
    assert profile["role"] == "superadmin"
    assert profile["profile_score"] == "MAXIMUM_VALUE"

def t_identidad_contacto_es_critical():
    fi = FakeIdentities()
    contact, response = fi.register_contact("admin_master", IP, PORT)
    assert contact.severity == ContactSeverity.CRITICAL
    assert contact.mine_type == MineType.IDENTITY

def t_identidad_respuesta_incluye_token():
    fi = FakeIdentities()
    _, response = fi.register_contact("admin_master", IP, PORT)
    assert "token" in response
    assert "role" in response

test("IDENTIDAD — admin_master existe", t_identidad_admin_master_existe)
test("IDENTIDAD — admin tiene permisos totales", t_identidad_admin_tiene_permiso_total)
test("IDENTIDAD — admin tiene recursos valiosos", t_identidad_admin_tiene_recursos_valiosos)
test("IDENTIDAD — admin tiene historial de login convincente", t_identidad_admin_tiene_historial)
test("IDENTIDAD — Perfil más atractivo es admin_master", t_identidad_mas_atractiva_es_admin)
test("IDENTIDAD — Contacto siempre es CRITICAL", t_identidad_contacto_es_critical)
test("IDENTIDAD — Respuesta incluye token y rol", t_identidad_respuesta_incluye_token)


# ─────────────────────────────────────────────
# FACHADA — AegisMinefield
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
print("  AEGIS — TEST CAPA 2: Fachada Completa")
print("═══════════════════════════════════════════════")

def t_minefield_inicializa():
    mf = AegisMinefield()
    st = mf.status()
    assert st["files"]       >= 5
    assert st["credentials"] >= 3
    assert st["endpoints"]   >= 8
    assert st["identities"]  >= 1
    assert st["total_contacts"] == 0

async def t_touch_file_registra_contacto():
    mf = AegisMinefield()
    contact, response = await mf.touch_file("backup.json", IP, PORT)
    assert mf.total_contacts() == 1
    assert contact.mine_type == MineType.FILE
    assert len(response) > 0

async def t_touch_credential_registra_contacto():
    mf = AegisMinefield()
    contact, _ = await mf.touch_credential("admin", IP, PORT)
    assert mf.total_contacts() == 1
    assert contact.severity == ContactSeverity.CRITICAL

async def t_touch_endpoint_registra_contacto():
    mf = AegisMinefield()
    contact, response = await mf.touch_endpoint("/admin", IP, PORT)
    assert mf.total_contacts() == 1
    assert len(response) > 0

async def t_touch_memory_registra_contacto():
    mf = AegisMinefield()
    contact, _ = await mf.touch_memory("session_keys", IP, PORT)
    assert mf.total_contacts() == 1
    assert contact.mine_type == MineType.MEMORY

async def t_touch_identity_registra_contacto():
    mf = AegisMinefield()
    contact, _ = await mf.touch_identity("admin_master", IP, PORT)
    assert mf.total_contacts() == 1
    assert contact.severity == ContactSeverity.CRITICAL

async def t_callbacks_tres_conectores():
    """Los tres callbacks (detección, forense, aprendizaje) reciben el evento."""
    mf = AegisMinefield()
    detection = []
    forensic  = []
    learning  = []

    async def on_detect(c): detection.append(c)
    async def on_forensic(c): forensic.append(c)
    async def on_learn(c): learning.append(c)

    mf.register_detection_callback(on_detect)
    mf.register_forensic_callback(on_forensic)
    mf.register_learning_callback(on_learn)

    await mf.touch_file("backup.json", IP, PORT)

    assert len(detection) == 1
    assert len(forensic)  == 1
    assert len(learning)  == 1

async def t_multiples_contactos_mismo_ip():
    mf = AegisMinefield()
    await mf.touch_file("backup.json",        IP, PORT)
    await mf.touch_credential("admin",         IP, PORT)
    await mf.touch_endpoint("/admin",          IP, PORT)
    await mf.touch_identity("admin_master",    IP, PORT)

    assert mf.total_contacts() == 4
    by_ip = mf.get_contacts_by_ip(IP)
    assert len(by_ip) == 4

async def t_filtro_por_severidad_critical():
    mf = AegisMinefield()
    await mf.touch_file("backup.json",     IP, PORT)   # HIGH
    await mf.touch_credential("admin",     IP, PORT)   # CRITICAL
    await mf.touch_identity("admin_master",IP, PORT)   # CRITICAL

    criticals = mf.get_contacts_by_severity(ContactSeverity.CRITICAL)
    assert len(criticals) == 2

async def t_export_log_estructura():
    mf = AegisMinefield()
    await mf.touch_file("backup.json", IP, PORT)
    log = mf.get_contact_log()
    assert len(log) == 1
    entry = log[0]
    assert "contact_id"  in entry
    assert "timestamp"   in entry
    assert "mine_type"   in entry
    assert "severity"    in entry
    assert "source_ip"   in entry
    assert "fingerprint" in entry

test("FACHADA — Inicialización con todos los señuelos", t_minefield_inicializa)
test("FACHADA — touch_file registra contacto", t_touch_file_registra_contacto)
test("FACHADA — touch_credential registra CRITICAL", t_touch_credential_registra_contacto)
test("FACHADA — touch_endpoint registra con respuesta", t_touch_endpoint_registra_contacto)
test("FACHADA — touch_memory registra contacto", t_touch_memory_registra_contacto)
test("FACHADA — touch_identity registra CRITICAL", t_touch_identity_registra_contacto)
test("FACHADA — Tres conectores reciben el evento", t_callbacks_tres_conectores)
test("FACHADA — Múltiples contactos mismo IP", t_multiples_contactos_mismo_ip)
test("FACHADA — Filtro por severidad CRITICAL", t_filtro_por_severidad_critical)
test("FACHADA — Export log tiene estructura completa", t_export_log_estructura)


# ─────────────────────────────────────────────
# RESUMEN
# ─────────────────────────────────────────────

print("\n═══════════════════════════════════════════════")
total  = len(results)
passed = sum(1 for _, ok in results if ok)
failed = total - passed

if failed == 0:
    print(f"  RESULTADO: {passed}/{total} tests PASADOS ✓")
    print("  Capa 2 — Campo de Minas OPERATIVO")
    print("  AEGIS puede continuar construcción de Capa 3")
else:
    print(f"  RESULTADO: {failed}/{total} tests FALLADOS ✗")
    for name, ok in results:
        if not ok:
            print(f"    ✗ {name}")
    print("  Revisar fallos antes de continuar")

print("═══════════════════════════════════════════════\n")
sys.exit(0 if failed == 0 else 1)
