#!/usr/bin/env python3
"""Test de estrés 48h para AEGIS — monitoriza uptime, salud y recursos."""

import time
import subprocess
import requests
import datetime
import os

TG_TOKEN = os.environ.get("AEGIS_TG_TOKEN", "")
TG_CHAT  = os.environ.get("AEGIS_TG_CHAT",  "")
DURACION_H = 36
LOG_FILE   = "/root/aegis/logs/stress_48h.log"

ENDPOINTS = [
    ("AEGIS-health",  "http://localhost:8080/health"),
    ("MACE-health",   "http://localhost:8000/health"),
    ("MACE-web",      "http://localhost:8000/"),
]

SERVICIOS = ["aegis.service", "mace.service", "nexus.service", "omnivara.service"]

contadores = {ep[0]: {"ok": 0, "fail": 0} for ep in ENDPOINTS}
reinicios  = {s: 0 for s in SERVICIOS}
inicio     = datetime.datetime.now()


def tg(msg):
    try:
        requests.post(
            f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage",
            json={"chat_id": TG_CHAT, "text": msg, "parse_mode": "Markdown"},
            timeout=10
        )
    except Exception:
        pass


def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def recursos():
    cpu = subprocess.getoutput("top -bn1 | grep 'Cpu(s)' | awk '{print $2}'").strip()
    mem = subprocess.getoutput("free -m | awk 'NR==2{printf \"%s/%s MB\", $3,$2}'")
    disk = subprocess.getoutput("df -h / | awk 'NR==2{print $5}'")
    return f"CPU {cpu}% | RAM {mem} | Disco {disk}"


def check_servicios():
    caidos = []
    for s in SERVICIOS:
        out = subprocess.getoutput(f"systemctl is-active {s}")
        if out.strip() != "active":
            caidos.append(s)
            subprocess.run(["systemctl", "restart", s])
            reinicios[s] += 1
            log(f"REINICIO: {s} estaba {out} — reiniciando")
    return caidos


def check_endpoints():
    fallos = []
    for nombre, url in ENDPOINTS:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code < 500:
                contadores[nombre]["ok"] += 1
            else:
                contadores[nombre]["fail"] += 1
                fallos.append(f"{nombre} → HTTP {r.status_code}")
        except Exception as e:
            contadores[nombre]["fail"] += 1
            fallos.append(f"{nombre} → {type(e).__name__}")
    return fallos


def resumen(parcial=False):
    ahora = datetime.datetime.now()
    elapsed = ahora - inicio
    horas = elapsed.total_seconds() / 3600
    tipo = "PARCIAL" if parcial else "FINAL"

    lines = [f"🛡️ *AEGIS — Test Estrés 48h [{tipo}]*",
             f"⏱ Tiempo: {horas:.1f}h / {DURACION_H}h",
             "",
             "*Endpoints:*"]
    for nombre, _ in ENDPOINTS:
        ok   = contadores[nombre]["ok"]
        fail = contadores[nombre]["fail"]
        total = ok + fail
        pct  = (ok / total * 100) if total else 0
        lines.append(f"  {nombre}: {ok}/{total} OK ({pct:.1f}%)")

    lines.append("")
    lines.append("*Servicios — reinicios:*")
    for s, n in reinicios.items():
        icon = "✅" if n == 0 else "⚠️"
        lines.append(f"  {icon} {s}: {n} reinicios")

    lines.append("")
    lines.append(f"*Recursos:* {recursos()}")
    return "\n".join(lines)


# ── INICIO ───────────────────────────────────────────────────────────────
os.makedirs("/root/aegis/logs", exist_ok=True)
log("=== Test estrés 48h iniciado ===")
tg(f"🚀 *AEGIS Test Estrés 48h INICIADO*\n{datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}\nResultado final: {(inicio + datetime.timedelta(hours=48)).strftime('%d/%m %H:%M')}")

fin         = inicio + datetime.timedelta(hours=DURACION_H)
ultimo_tg   = inicio   # último resumen por Telegram
intervalo_tg = 6 * 3600  # cada 6 horas

while datetime.datetime.now() < fin:
    # Check cada 30 segundos
    fallos_ep  = check_endpoints()
    caidos_srv = check_servicios()

    if fallos_ep or caidos_srv:
        msg = f"⚠️ *AEGIS ALERTA*\n"
        if fallos_ep:  msg += "Endpoints: " + ", ".join(fallos_ep) + "\n"
        if caidos_srv: msg += "Servicios caídos: " + ", ".join(caidos_srv)
        tg(msg)
        log(f"ALERTA: {fallos_ep} | {caidos_srv}")

    # Resumen cada 6h
    ahora = datetime.datetime.now()
    if (ahora - ultimo_tg).total_seconds() >= intervalo_tg:
        tg(resumen(parcial=True))
        log("Resumen parcial enviado por Telegram")
        ultimo_tg = ahora

    time.sleep(30)

# Resumen final
log("=== Test estrés 48h COMPLETADO ===")
tg(resumen(parcial=False))
