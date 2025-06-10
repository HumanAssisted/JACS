# JACS Observability Demo

Run the observability stack:

```bash
docker compose -f docker-compose.observability.yml up -d
```

## Access the Services

- **Grafana Dashboard**: http://localhost:3000 (admin/admin)
- **Prometheus**: http://localhost:9090
- **Jaeger Tracing**: http://localhost:16686
- **Loki Logs**: http://localhost:3100
- **OpenTelemetry Collector**: http://localhost:8888 (metrics)

## Local Testing

Run locally without Docker:
```bash
cargo run
```

This will create `./logs/` and `./metrics/metrics.txt` files locally.

## Configuration

The observability configuration uses:
- Docker mode: sends to OTLP collector and Prometheus
- Local mode: writes to local files

Set `DOCKER_MODE=1` environment variable to use Docker endpoints.

Observability section

    "observability": {
        "logs": {
        "enabled": true,
        "level": "debug",
        "destination": {
            "type": "otlp",
            "endpoint": "http://otel-collector:4318",
            "headers": {
            "Content-Type": "application/json"
            }
        }
        },
        "metrics": {
        "enabled": true,
        "destination": {
            "type": "prometheus",
            "endpoint": "http://prometheus:9090",
            "headers": {}
        },
        "export_interval_seconds": 15
        },
        "tracing": {
        "enabled": true,
        "sampling": {
            "ratio": 1.0,
            "parent_based": true
        },
        "resource": {
            "service_name": "jacs-agent",
            "service_version": "1.0.0",
            "environment": "development"
        }
        }
    }