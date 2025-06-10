# JACS Observability Demo

## Quick Start

1. **Start the observability stack:**
```bash
docker compose -f docker-compose.observability.yml up -d
```

2. **Run the JACS demo:**
```bash
cargo run
```

3. **View the results:**
- **Grafana**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090  
- **Jaeger**: http://localhost:16686

## What it does

The demo runs locally and sends:
- Metrics → Prometheus (via localhost:9090)
- Logs → OpenTelemetry Collector (via localhost:4318) → Loki
- Traces → Jaeger (via OTLP collector)

The demo will run for 50 iterations (~2 minutes) then exit.

## Cleanup

```bash
docker compose -f docker-compose.observability.yml down
```
```

Now you can:
1. `docker compose -f docker-compose.observability.yml up -d`
2. `cargo run` 
3. Check Grafana at http://localhost:3000 to see your data!