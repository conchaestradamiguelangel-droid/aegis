"""
AEGIS — Punto de Entrada Principal
====================================
Uso:
    python main.py                          — modo interactivo (consola)
    python main.py --daemon                 — modo daemon (systemd, sin terminal)
    python main.py --no-interactive         — igual que --daemon

    # Proteger MACE (aplicación en localhost:8000):
    python main.py --daemon --mace
    python main.py --daemon --mace --mace-port 8080 --mace-target localhost:8000

Comandos disponibles en modo interactivo:
    status  — estado completo del sistema
    rotate  — forzar rotación AMTD inmediata
    lock    — activar cierre atómico manual
    quit    — detener sistema y salir
"""

import asyncio
import logging
import sys
import os

# Añadir raíz del proyecto al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.aegis import AegisSystem, SystemStatus
from status_server import AegisStatusServer

# ─────────────────────────────────────────────
# CONFIGURACIÓN DE DESPLIEGUE
# ─────────────────────────────────────────────

# SHIELD_ENABLED = False  → arranca sin puertos señuelo de Capa 0.5
SHIELD_ENABLED = False

# Detectar modos por argumentos de línea de comandos
DAEMON_MODE = any(a in sys.argv for a in ("--daemon", "--no-interactive"))

# ── Integración MACE ──────────────────────────────────────────────────────────
# --mace              → activa el proxy delante de MACE
# --mace-port N       → puerto donde escucha el proxy (por defecto 8080)
# --mace-target HOST  → destino MACE (por defecto localhost:8000)
# --mace-webhook URL  → URL webhook de MACE para notificaciones (opcional)

def _arg(flag: str, default=None):
    """Extrae el valor de --flag valor de sys.argv."""
    try:
        idx = sys.argv.index(flag)
        return sys.argv[idx + 1]
    except (ValueError, IndexError):
        return default

MACE_ENABLED  = "--mace" in sys.argv
MACE_PORT     = int(_arg("--mace-port",    "8080"))
MACE_TARGET   = _arg("--mace-target", "http://localhost:8000")
MACE_WEBHOOK  = _arg("--mace-webhook", None)
STATE_DIR     = _arg("--state-dir",   "state")
STATUS_PORT   = int(_arg("--status-port", "8081"))

# ── Alertas Telegram ──────────────────────────────────────────────────────────
# Leer de variables de entorno o pasar como argumentos
# Ejemplo systemd: Environment="AEGIS_TG_TOKEN=xxx" "AEGIS_TG_CHAT=yyy"
TELEGRAM_TOKEN   = os.environ.get("AEGIS_TG_TOKEN",   _arg("--tg-token"))
TELEGRAM_CHAT_ID = os.environ.get("AEGIS_TG_CHAT",    _arg("--tg-chat"))

# ── Conector ENLIL ────────────────────────────────────────────────────────────────────────────
ENLIL_URL   = os.environ.get("AEGIS_ENLIL_URL",   "http://127.0.0.1:8002")
ENLIL_TOKEN = os.environ.get("AEGIS_ENLIL_TOKEN")

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────

logging.basicConfig(
    level   = logging.WARNING,   # solo alertas en consola
    format  = "%(asctime)s [%(name)s] %(message)s",
    datefmt = "%H:%M:%S",
)
# Silenciar capas ruidosas en operación normal
for modulo in ["aegis.amtd", "aegis.twin", "aegis.crypto"]:
    logging.getLogger(modulo).setLevel(logging.ERROR)


# ─────────────────────────────────────────────
# CONSOLA DE ESTADO
# ─────────────────────────────────────────────

def print_banner():
    print()
    print("  ╔══════════════════════════════════════════════════╗")
    print("  ║           AEGIS — Sistema Defensivo             ║")
    print("  ║   100% defensivo · Post-cuántico · 10 capas     ║")
    print("  ╚══════════════════════════════════════════════════╝")
    print()


def print_status(aegis: AegisSystem):
    snap = aegis.snapshot()
    st   = snap.to_dict()
    ls   = aegis.learning.status()

    status_sym = {
        "ONLINE":   "🟢",
        "ALERT":    "🟡",
        "LOCKDOWN": "🔴",
        "OFFLINE":  "⚫",
        "STARTING": "🔵",
        "STOPPING": "🔵",
    }.get(st["status"], "⚪")

    print()
    print(f"  ┌─────────────────────────────────────────────┐")
    print(f"  │  AEGIS STATUS — {aegis.installation_id:<28} │")
    print(f"  ├─────────────────────────────────────────────┤")
    print(f"  │  Estado:       {status_sym}  {st['status']:<27}│")
    print(f"  │  Amenaza:      {st['threat_level']:<29} │")
    print(f"  │  Uptime:       {st['uptime_s']:<6.1f}s                       │")
    print(f"  ├─────────────────────────────────────────────┤")
    print(f"  │  Detecciones:  {st['total_detections']:<29} │")
    print(f"  │  Saltos twin:  {st['jump_count']:<29} │")
    print(f"  │  Ciclo AMTD:   {st['amtd_cycle']:<29} │")
    print(f"  │  Sesiones:     {st['active_sessions']:<29} │")
    print(f"  ├─────────────────────────────────────────────┤")
    print(f"  │  Incidentes aprendidos: {ls['incidents_learned']:<20} │")
    print(f"  │  Señales:               {ls['signals_recorded']:<20} │")
    print(f"  │  Paquetes importados:   {ls['packets_imported']:<20} │")
    print(f"  └─────────────────────────────────────────────┘")
    print()


def print_help():
    print()
    print("  Comandos disponibles:")
    print("    status  — estado del sistema")
    print("    rotate  — rotar superficie AMTD ahora")
    print("    lock    — cierre atómico manual")
    print("    quit    — detener y salir")
    print()


# ─────────────────────────────────────────────
# BUCLE DE COMANDOS
# ─────────────────────────────────────────────

async def command_loop(aegis: AegisSystem):
    """Lee comandos de stdin de forma no bloqueante."""
    loop = asyncio.get_event_loop()

    print("  Sistema activo. Escribe un comando (help para ayuda):")
    print()

    while aegis.status != SystemStatus.OFFLINE:
        try:
            # Leer input sin bloquear el event loop
            cmd = await loop.run_in_executor(None, input, "  aegis> ")
            cmd = cmd.strip().lower()

            if cmd in ("status", "st", "s"):
                print_status(aegis)

            elif cmd in ("rotate", "rot", "r"):
                print("  Rotando superficie AMTD...")
                await aegis.rotate_now()
                ciclo = aegis.amtd.status()["cycle"]
                print(f"  Rotación completada — ciclo {ciclo}")
                print()

            elif cmd in ("lock", "lockdown", "l"):
                print("  Activando cierre atómico manual...")
                result = await aegis.trigger_lockdown("manual desde consola")
                print(f"  Cierre {'completado' if result else 'fallido'}")
                print()

            elif cmd in ("help", "h", "?"):
                print_help()

            elif cmd in ("quit", "exit", "q", "stop"):
                print()
                print("  Deteniendo AEGIS...")
                break

            elif cmd == "":
                pass

            else:
                print(f"  Comando desconocido: '{cmd}' — escribe 'help'")
                print()

        except (EOFError, KeyboardInterrupt):
            print()
            print("  Interrupción recibida — deteniendo AEGIS...")
            break
        except Exception as e:
            print(f"  Error en comando: {e}")


# ─────────────────────────────────────────────
# MONITOR DE ESTADO PERIÓDICO
# ─────────────────────────────────────────────

async def status_monitor(aegis: AegisSystem, interval_s: int = 60):
    """Imprime estado automáticamente cada intervalo."""
    while aegis.status not in (SystemStatus.OFFLINE, SystemStatus.STOPPING):
        await asyncio.sleep(interval_s)
        if aegis.status == SystemStatus.ONLINE:
            print()
            print(f"  [AUTO-STATUS — cada {interval_s}s]")
            print_status(aegis)


# ─────────────────────────────────────────────
# BUCLE DAEMON — sin terminal, para systemd
# ─────────────────────────────────────────────

async def daemon_loop(aegis: AegisSystem, interval_s: int = 60):
    """
    Bucle de operación en background — sin input().
    Imprime estado cada interval_s y espera señal de parada.
    systemd gestiona el ciclo de vida vía SIGTERM.
    """
    import signal

    stop_event = asyncio.Event()

    def on_signal():
        print("\n  [DAEMON] Señal de parada recibida — deteniendo AEGIS...")
        stop_event.set()

    loop = asyncio.get_event_loop()
    loop.add_signal_handler(signal.SIGTERM, on_signal)
    loop.add_signal_handler(signal.SIGINT,  on_signal)

    print("  Modo daemon activo. Logs via journalctl -u aegis -f")
    print()

    while not stop_event.is_set():
        try:
            await asyncio.wait_for(
                asyncio.shield(stop_event.wait()),
                timeout=interval_s
            )
        except asyncio.TimeoutError:
            # Intervalo cumplido — imprimir estado
            if aegis.status == SystemStatus.ONLINE:
                print_status(aegis)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────

async def main():
    print_banner()

    # Instanciar sistema
    aegis = AegisSystem(
        installation_id  = "AEGIS-VPS-001",
        state_dir        = STATE_DIR,
        amtd_interval_s  = 30,
        decoy_ports      = [],
        shield_enabled   = SHIELD_ENABLED,
        telegram_token   = TELEGRAM_TOKEN,
        telegram_chat_id = TELEGRAM_CHAT_ID,
        enlil_url        = ENLIL_URL,
        enlil_token      = ENLIL_TOKEN,
    )

    modo_shield = "CON escudo (Capa 0.5 activa)" if SHIELD_ENABLED else \
                  "SIN escudo (SHIELD_ENABLED=False)"
    modo_run    = "DAEMON (systemd)" if DAEMON_MODE else "INTERACTIVO"
    print(f"  Modo arranque: {modo_run}")
    print(f"  Modo escudo:   {modo_shield}")

    if MACE_ENABLED:
        print(f"  Integración MACE: proxy en :{MACE_PORT} → {MACE_TARGET}")

    print("  Iniciando capas...")

    try:
        await aegis.start()
    except Exception as e:
        print(f"  ERROR en arranque: {e}")
        sys.exit(1)

    # ── Arrancar integración MACE si está habilitada ──────────────────────────
    mace_connector = None
    if MACE_ENABLED:
        try:
            mace_connector = await aegis.start_mace_integration(
                target_url  = MACE_TARGET,
                listen_port = MACE_PORT,
                webhook_url = MACE_WEBHOOK,
            )
            print(f"  ✓ MACE protegido — proxy activo en :{MACE_PORT}")
        except Exception as e:
            print(f"  ✗ Error arrancando MACE proxy: {e}")

    # ── Servidor de estado HTTP (puerto 8081) ────────────────────────────────
    status_srv = AegisStatusServer(aegis, port=STATUS_PORT)
    await status_srv.start()
    print("  ✓ Servidor de estado activo en 127.0.0.1:8081")

    print_status(aegis)

    if DAEMON_MODE:
        await daemon_loop(aegis, interval_s=60)
    else:
        monitor_task = asyncio.create_task(
            status_monitor(aegis, interval_s=60)
        )
        await command_loop(aegis)
        monitor_task.cancel()
        try:
            await monitor_task
        except asyncio.CancelledError:
            pass

    # ── Detener MACE proxy antes que AEGIS ───────────────────────────────────
    await status_srv.stop()

    if mace_connector:
        await aegis.stop_mace_integration()

    await aegis.stop()

    print()
    print("  ╔══════════════════════════════════════╗")
    print("  ║        AEGIS — Sistema detenido      ║")
    print("  ╚══════════════════════════════════════╝")
    print()


if __name__ == "__main__":
    asyncio.run(main())
