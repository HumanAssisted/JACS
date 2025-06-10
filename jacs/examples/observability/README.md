


    docker compose -f docker-compose.observability.yml up -d
    cargo run


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