#!/bin/bash
# Monitorización local cada 5 min — alerta Telegram si cae un servicio
TG_TOKEN="$(grep AEGIS_TG_TOKEN /etc/systemd/system/aegis.service 2>/dev/null | grep -oP '(?<==)[^ ]+' || echo "")"
TG_CHAT="1025881720"
ALERT_FILE="/tmp/aegis_uptime_alerted"

send_tg() {
  [ -z "$TG_TOKEN" ] && return
  curl -s -X POST "https://api.telegram.org/bot${TG_TOKEN}/sendMessage"     -d chat_id="$TG_CHAT"     -d text="$1"     -d parse_mode="Markdown" > /dev/null
}

DOWN=()

check() {
  local name="$1" url="$2"
  local code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$url")
  if [ "$code" != "200" ]; then
    DOWN+=("$name (HTTP $code)")
  fi
}

check "AEGIS" "https://aegis-pq.com"
check "ENLIL" "https://enlil-council.com/dashboard"

if [ ${#DOWN[@]} -gt 0 ]; then
  MSG="🚨 *ALERTA UPTIME*\n\nServicios caídos:\n"
  for s in "${DOWN[@]}"; do MSG+="• $s\n"; done
  MSG+="\n$(date '+%Y-%m-%d %H:%M CET')"
  if [ ! -f "$ALERT_FILE" ]; then
    send_tg "$MSG"
    touch "$ALERT_FILE"
  fi
else
  rm -f "$ALERT_FILE"
fi
