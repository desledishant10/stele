# Stele deployment assets

Operations-side artifacts that pair with the observability surface in
`pkg/obs`.

- `prometheus/alerts.yml` — Prometheus alert rules covering availability,
  the append path, checkpoint signing, witness mesh health, and security
  signals (honeypots, watchdog rotations). Load via `rule_files:` in
  your Prometheus config.

- `grafana/stele-overview.json` — Grafana dashboard for the operator and
  on-call view. Imports cleanly into Grafana 10+; uses a Prometheus
  datasource and an instance template variable.

## Scrape config snippet

```yaml
scrape_configs:
  - job_name: stele
    static_configs:
      - targets:
          - "steled.internal:8080"
          - "witness-a.internal:9090"
          - "witness-b.internal:9090"
          - "cosigner-alice.internal:9101"
          - "cosigner-bob.internal:9101"
          - "mirror-1.internal:8444"
    metrics_path: /metrics
```

If you have TLS or mTLS terminating at the steled HTTP server, scrape
with `scheme: https` and supply the relevant `tls_config`.

## OpenTelemetry collector

Set `--otlp-endpoint http://otelcol:4318` on steled (or any of the
`OTEL_EXPORTER_OTLP_*_ENDPOINT` env vars). The collector should be
configured with an OTLP receiver on `:4318` and an exporter to your
backend (Tempo, Jaeger, Honeycomb, Datadog).

```yaml
# otel-collector.yaml — minimal
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

exporters:
  otlphttp/tempo:
    endpoint: http://tempo:4318

service:
  pipelines:
    traces:
      receivers: [otlp]
      exporters: [otlphttp/tempo]
```
