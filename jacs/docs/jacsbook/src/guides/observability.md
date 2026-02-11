# Observability Guide

JACS emits structured events at every signing, verification, and agreement lifecycle step. This guide shows you how to capture those events and route them to your monitoring stack.

For Rust-specific API details (ObservabilityConfig, LogDestination, MetricsConfig, etc.), see the [Rust Observability Reference](../rust/observability.md).

## Structured Event Reference

Every event includes an `event` field for filtering. The table below is derived directly from the source code.

### Signing Events

| Event | Level | Fields | Source |
|-------|-------|--------|--------|
| `document_signed` | `info` | `algorithm`, `duration_ms` | `crypt/mod.rs` |
| `batch_signed` | `info` | `algorithm`, `batch_size`, `duration_ms` | `crypt/mod.rs` |
| `signing_procedure_complete` | `info` | `agent_id`, `algorithm`, `timestamp`, `placement_key` | `agent/mod.rs` |

### Verification Events

| Event | Level | Fields | Source |
|-------|-------|--------|--------|
| `signature_verified` | `info` | `algorithm`, `valid`, `duration_ms` | `crypt/mod.rs` |
| `verification_complete` | `info` / `error` | `document_id`, `signer_id`, `algorithm`, `timestamp`, `valid`, `duration_ms` | `agent/mod.rs` |

`verification_complete` emits at `info` when `valid=true` and at `error` when `valid=false`.

### Agreement Events

| Event | Level | Fields | Source |
|-------|-------|--------|--------|
| `agreement_created` | `info` | `document_id`, `agent_count`, `quorum`, `has_timeout` | `agent/agreement.rs` |
| `signature_added` | `info` | `document_id`, `signer_id`, `current`, `total`, `required` | `agent/agreement.rs` |
| `quorum_reached` | `info` | `document_id`, `signatures`, `required`, `total` | `agent/agreement.rs` |
| `agreement_expired` | `warn` | `document_id`, `deadline` | `agent/agreement.rs` |

## Enabling OTEL Export

JACS ships with three optional feature flags for OpenTelemetry backends. By default, only stderr and file logging are available.

```bash
# Enable all three OTEL pipelines
cargo build --features otlp-logs,otlp-metrics,otlp-tracing

# Or enable just tracing
cargo build --features otlp-tracing
```

| Feature | What it adds |
|---------|-------------|
| `otlp-logs` | OTLP log export (opentelemetry, opentelemetry-otlp, opentelemetry-appender-tracing, tokio) |
| `otlp-metrics` | OTLP metrics export (opentelemetry, opentelemetry-otlp, opentelemetry_sdk, tokio) |
| `otlp-tracing` | Distributed tracing (opentelemetry, opentelemetry-otlp, tracing-opentelemetry, tokio) |

The `observability-convenience` feature adds automatic counter/gauge recording for sign and verify operations without pulling in any OTLP dependencies.

## OTEL Collector Configuration

Route JACS events through an OpenTelemetry Collector. This configuration receives OTLP over HTTP, batches events, and exports to common backends.

```yaml
# otel-collector-config.yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

processors:
  batch:
    timeout: 5s
    send_batch_size: 512
  filter/jacs:
    logs:
      include:
        match_type: regexp
        record_attributes:
          - key: event
            value: "document_signed|signature_verified|verification_complete|agreement_.*|batch_signed|signing_procedure_complete|quorum_reached|signature_added"

exporters:
  # Debug: print to collector stdout
  debug:
    verbosity: detailed

  # Datadog
  datadog:
    api:
      key: "${DD_API_KEY}"
      site: datadoghq.com

  # Splunk HEC
  splunkhec:
    token: "${SPLUNK_HEC_TOKEN}"
    endpoint: "https://splunk-hec:8088/services/collector"
    source: "jacs"
    sourcetype: "jacs:events"

  # Generic OTLP (Grafana Cloud, Honeycomb, etc.)
  otlphttp:
    endpoint: "${OTLP_ENDPOINT}"
    headers:
      Authorization: "Bearer ${OTLP_API_KEY}"

service:
  pipelines:
    logs:
      receivers: [otlp]
      processors: [batch, filter/jacs]
      exporters: [debug]          # Replace with your exporter
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [debug]
```

### Pointing JACS at the Collector

In `jacs.config.json`:

```json
{
  "observability": {
    "logs": {
      "enabled": true,
      "level": "info",
      "destination": {
        "otlp": { "endpoint": "http://localhost:4318" }
      }
    },
    "metrics": {
      "enabled": true,
      "destination": {
        "otlp": { "endpoint": "http://localhost:4318" }
      },
      "export_interval_seconds": 30
    },
    "tracing": {
      "enabled": true,
      "sampling": { "ratio": 1.0, "parent_based": true },
      "resource": {
        "service_name": "my-jacs-service",
        "environment": "production"
      },
      "destination": {
        "otlp": { "endpoint": "http://localhost:4318" }
      }
    }
  }
}
```

Or via environment variables (useful in containers):

```bash
export OTEL_EXPORTER_OTLP_ENDPOINT="http://collector:4318"
export OTEL_SERVICE_NAME="jacs-production"
export OTEL_RESOURCE_ATTRIBUTES="deployment.environment=production"
```

## Feeding Events to Datadog

1. Deploy the OTEL Collector with the `datadog` exporter (see config above).
2. Set `DD_API_KEY` in the collector's environment.
3. In Datadog, JACS events appear under **Logs > Search** with `source:opentelemetry`.
4. Create a monitor on `event:verification_complete AND valid:false` to alert on verification failures.

Alternatively, use the Datadog Agent's built-in OTLP receiver:

```yaml
# datadog.yaml
otlp_config:
  receiver:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
```

## Feeding Events to Splunk

1. Deploy the OTEL Collector with the `splunkhec` exporter.
2. Set `SPLUNK_HEC_TOKEN` in the collector's environment.
3. Events arrive in Splunk with `sourcetype=jacs:events`.
4. Search: `sourcetype="jacs:events" event="verification_complete" valid=false`

## Agreement Monitoring

Agreement events give you a complete lifecycle view: creation, each signature, quorum, and expiry. Here are practical queries.

### Agreements Approaching Timeout

Filter for `agreement_created` events where `has_timeout=true`, then correlate with `quorum_reached`. Any `agreement_created` without a matching `quorum_reached` within the timeout window is at risk.

### Failed Quorum Detection

```
event="signature_added" | stats max(current) as sigs, max(required) as needed by document_id
| where sigs < needed
```

### Signature Velocity

Track `signature_added` events over time to see how quickly agents sign after agreement creation:

```
event="signature_added" | timechart count by document_id
```

### Expiry Alerts

The `agreement_expired` event (level `warn`) fires when an agent attempts to sign or verify an expired agreement. Alert on this directly:

```
event="agreement_expired" | alert
```

## Latency Tracking

Both `document_signed` and `signature_verified` include `duration_ms`. Use these to track signing and verification performance:

```
event="document_signed" | stats avg(duration_ms) as avg_sign_ms, p99(duration_ms) as p99_sign_ms by algorithm
event="signature_verified" | stats avg(duration_ms) as avg_verify_ms, p99(duration_ms) as p99_verify_ms by algorithm
```

Post-quantum algorithms (`pq2025`, `pq-dilithium`) will show higher latency than `ring-Ed25519`. Use these metrics to decide whether the security/performance tradeoff is acceptable for your workload.

## Next Steps

- [Rust Observability Reference](../rust/observability.md) -- Full API: ObservabilityConfig, LogDestination, MetricsConfig, TracingConfig
- [Algorithm Selection Guide](../advanced/algorithm-guide.md) -- Latency implications of algorithm choice
- [Failure Modes](../advanced/failure-modes.md) -- What events to expect when things go wrong
