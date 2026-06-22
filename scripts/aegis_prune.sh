#!/bin/bash
# Archiva incidentes AEGIS con más de 30 días en un .tar.gz mensual
INCIDENTS_DIR="/root/aegis/incidents"
ARCHIVE_DIR="/root/aegis/incidents_archive"
mkdir -p "$ARCHIVE_DIR"

CUTOFF=$(date -d "30 days ago" +%Y%m%d)
MONTH_TAG=$(date -d "30 days ago" +%Y-%m)
ARCHIVE_FILE="$ARCHIVE_DIR/incidents_${MONTH_TAG}.tar.gz"

# Buscar ficheros INC- más viejos de 30 días
OLD_FILES=$(find "$INCIDENTS_DIR" -name "INC-*.json" -o -name "INC-*.html" | \
  awk -F'[-]' '{d=$2; if(d != "" && d < "'$CUTOFF'") print}' | sort)

if [ -z "$OLD_FILES" ]; then
  echo "$(date): Nada que archivar." >> /var/log/aegis_prune.log
  exit 0
fi

COUNT=$(echo "$OLD_FILES" | wc -l)
echo "$OLD_FILES" | tar -czf "$ARCHIVE_FILE" -T -
echo "$OLD_FILES" | xargs rm -f
echo "$(date): Archivados $COUNT ficheros → $ARCHIVE_FILE" >> /var/log/aegis_prune.log
