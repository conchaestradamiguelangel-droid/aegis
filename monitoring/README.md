# AEGIS Monitoring - Grafana Dashboard

Import `grafana-dashboard.json` into any Grafana 9+ instance connected to a Prometheus datasource that scrapes AEGIS `/metrics`.

## Quick import

1. In Grafana: **Dashboards > Import**
2. Upload `grafana-dashboard.json` or paste its contents
3. Select your Prometheus datasource when prompted
4. Click **Import**

## Prometheus scrape config

Add to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: aegis
    static_configs:
      - targets: ['<AEGIS_HOST>:8081']
```

Replace `<AEGIS_HOST>` with the IP or hostname where AEGIS runs (default port 8081).

## Panels

| Panel | Metric | Type |
|-------|--------|------|
| System Status | `aegis_up` | Stat |
| Threat Level | `aegis_threat_level` | Stat |
| Active IPs | `aegis_active_ips` | Stat |
| Uptime | `aegis_uptime_seconds` | Stat |
| Open Incidents | `aegis_incidents_open` | Stat |
| Total Incidents | `aegis_incidents_total` | Stat |
| Total Lockdowns | `aegis_lockdowns_total` | Stat |
| Blocked IPs (MACE) | `aegis_blocked_ips` | Stat |
| Detection Rate | `rate(aegis_detections_total[5m])` | Time series |
| AMTD Cycle & Checkpoints | `aegis_amtd_cycle`, `aegis_checkpoints_total` | Time series |

## Color thresholds

- **System Status**: green = ONLINE, orange = ALERT, red = OFFLINE/LOCKDOWN
- **Threat Level**: green = NONE, yellow = LOW, orange = MEDIUM, red = HIGH, dark-red = CRITICAL
- **Open Incidents**: green = 0, orange >= 1, red >= 5
- **Blocked IPs**: green = 0, orange >= 5, red >= 20
