"""
AEGIS — MITRE ATT&CK Mapper
=============================
Enriquece cada incidente con técnicas MITRE ATT&CK.
Mapeado estático — cero dependencias externas, cero coste.

Cómo funciona:
    map_incident(detection_type, techniques, actor, intent)
    → dict con lista de técnicas ATT&CK, tácticas y coverage

Nunca lanza excepciones — falla silenciosamente y devuelve vacío.
"""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# BASE DE CONOCIMIENTO — Detection → MITRE ATT&CK
# Fuente: https://attack.mitre.org  (Enterprise ATT&CK v16)
# ─────────────────────────────────────────────────────────────────────────────

_BASE_URL = "https://attack.mitre.org/techniques"

# Cada entrada: (id, nombre, táctica, subtécnica_de)
_TECHNIQUES: dict[str, tuple[str, str, str | None]] = {
    # Reconnaissance
    "T1595":     ("Active Scanning",                        "reconnaissance",      None),
    "T1595.001": ("Scanning IP Blocks",                     "reconnaissance",      "T1595"),
    "T1595.002": ("Vulnerability Scanning",                 "reconnaissance",      "T1595"),
    "T1592":     ("Gather Victim Host Information",         "reconnaissance",      None),
    "T1589":     ("Gather Victim Identity Information",     "reconnaissance",      None),
    # Initial Access
    "T1190":     ("Exploit Public-Facing Application",      "initial-access",      None),
    "T1133":     ("External Remote Services",               "initial-access",      None),
    # Discovery
    "T1046":     ("Network Service Discovery",              "discovery",           None),
    "T1018":     ("Remote System Discovery",                "discovery",           None),
    "T1083":     ("File and Directory Discovery",           "discovery",           None),
    # Credential Access
    "T1110":     ("Brute Force",                            "credential-access",   None),
    "T1110.001": ("Password Guessing",                      "credential-access",   "T1110"),
    "T1110.003": ("Password Spraying",                      "credential-access",   "T1110"),
    "T1110.004": ("Credential Stuffing",                    "credential-access",   "T1110"),
    # Lateral Movement
    "T1021":     ("Remote Services",                        "lateral-movement",    None),
    "T1210":     ("Exploitation of Remote Services",        "lateral-movement",    None),
    # Exfiltration
    "T1041":     ("Exfiltration Over C2 Channel",          "exfiltration",        None),
    "T1048":     ("Exfiltration Over Alt Protocol",        "exfiltration",        None),
    # Persistence
    "T1098":     ("Account Manipulation",                   "persistence",         None),
    "T1078":     ("Valid Accounts",                         "persistence",         None),
    # Execution
    "T1059":     ("Command and Scripting Interpreter",      "execution",           None),
    # Resource Development
    "T1583":     ("Acquire Infrastructure",                 "resource-development", None),
    "T1584":     ("Compromise Infrastructure",              "resource-development", None),
}

# ─────────────────────────────────────────────────────────────────────────────
# REGLAS DE MAPEADO
# ─────────────────────────────────────────────────────────────────────────────

# DetectionType → lista de IDs ATT&CK
_DETECTION_TYPE_MAP: dict[str, list[str]] = {
    "MINE_CONTACT":  ["T1190", "T1595.002"],
    "RECON_PATTERN": ["T1595", "T1595.001"],
    "EXPLORATION":   ["T1046", "T1018"],
    "COORDINATED":   ["T1583", "T1046", "T1018"],
    "AUTOMATED":     ["T1595.002", "T1110"],
}

# AttackTechnique (forense Capa 7) → IDs ATT&CK
_FORENSIC_TECHNIQUE_MAP: dict[str, list[str]] = {
    "RECONNAISSANCE":      ["T1595", "T1592"],
    "CREDENTIAL_STUFFING": ["T1110.004", "T1589"],
    "ENUMERATION":         ["T1592", "T1083"],
    "EXFILTRATION":        ["T1041", "T1048"],
    "LATERAL_MOVEMENT":    ["T1021", "T1210"],
    "PERSISTENCE":         ["T1098", "T1078"],
}

# ActorType → IDs ATT&CK adicionales
_ACTOR_MAP: dict[str, list[str]] = {
    "BOT_SIMPLE":   ["T1595.002"],
    "BOT_ADVANCED": ["T1595", "T1110"],
    "AI_AGENT":     ["T1595", "T1059"],
}

# IntentCategory → IDs ATT&CK adicionales
_INTENT_MAP: dict[str, list[str]] = {
    "CREDENTIAL_THEFT":  ["T1110", "T1110.001"],
    "DATA_EXFILTRATION": ["T1041"],
    "SYSTEM_ACCESS":     ["T1190", "T1078"],
    "RECONNAISSANCE":    ["T1595"],
}


# ─────────────────────────────────────────────────────────────────────────────
# FUNCIÓN PÚBLICA
# ─────────────────────────────────────────────────────────────────────────────

def map_incident(
    detection_type: str,
    forensic_techniques: list[str],
    actor: str,
    intent: str,
) -> dict:
    """
    Genera la sección mitre_attack para un incidente AEGIS.

    Args:
        detection_type:      valor de DetectionType (str)
        forensic_techniques: lista de AttackTechnique.value (str)
        actor:               ActorType.value (str)
        intent:              IntentCategory.value (str)

    Returns:
        dict con claves: techniques, tactics, coverage
        En caso de error, devuelve dict vacío — nunca lanza.
    """
    try:
        ids: set[str] = set()

        # 1. Técnicas por tipo de detección
        ids.update(_DETECTION_TYPE_MAP.get(detection_type, []))

        # 2. Técnicas forenses de Capa 7
        for tech in forensic_techniques:
            ids.update(_FORENSIC_TECHNIQUE_MAP.get(tech, []))

        # 3. Actor
        ids.update(_ACTOR_MAP.get(actor, []))

        # 4. Intención
        ids.update(_INTENT_MAP.get(intent, []))

        if not ids:
            return {"techniques": [], "tactics": [], "coverage": "none"}

        # Construir lista de técnicas ordenadas (primarias primero)
        techniques = []
        seen_tactics: set[str] = set()
        for tid in sorted(ids, key=lambda x: ("." in x, x)):
            if tid in _TECHNIQUES:
                name, tactic, parent = _TECHNIQUES[tid]
                techniques.append({
                    "id":     tid,
                    "name":   name,
                    "tactic": tactic,
                    "url":    f"{_BASE_URL}/{tid.replace('.', '/')}",
                    **({"parent": parent} if parent else {}),
                })
                seen_tactics.add(tactic)

        coverage = (
            "high"    if len(techniques) >= 4 else
            "medium"  if len(techniques) >= 2 else
            "partial"
        )

        return {
            "techniques": techniques,
            "tactics":    sorted(seen_tactics),
            "coverage":   coverage,
        }

    except Exception:
        return {"techniques": [], "tactics": [], "coverage": "none"}


def technique_badge(tid: str) -> str:
    """Devuelve HTML badge para un ID de técnica ATT&CK (para el PIR HTML)."""
    if tid not in _TECHNIQUES:
        return ""
    name, tactic, _ = _TECHNIQUES[tid]
    color = _TACTIC_COLORS.get(tactic, "#2a3a4a")
    return (
        f'<a href="{_BASE_URL}/{tid.replace(".", "/")}" target="_blank" '
        f'style="background:{color};color:#fff;border-radius:3px;'
        f'padding:2px 7px;margin:2px;display:inline-block;font-size:11px;'
        f'text-decoration:none">'
        f'<b>{tid}</b> {name}</a>'
    )


_TACTIC_COLORS = {
    "reconnaissance":       "#7b2d8b",
    "initial-access":       "#c0392b",
    "discovery":            "#1a6b8a",
    "credential-access":    "#c0592b",
    "lateral-movement":     "#8b6914",
    "exfiltration":         "#1a7a4a",
    "persistence":          "#2c3e7a",
    "execution":            "#5a3070",
    "resource-development": "#4a4a4a",
}
