package obs

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

// Tracer is the package-level tracer. Until InitTracing is called it's a
// no-op, so every Tracer().Start(...) site is safe to call from
// processes that don't have an OTLP collector configured.
var tracer trace.Tracer = noop.NewTracerProvider().Tracer("stele")

// Tracer returns the configured stele tracer. Spans started via this
// tracer are exported to the collector configured by InitTracing.
func Tracer() trace.Tracer { return tracer }

// InitTracing wires up an OTLP/HTTP exporter against the supplied
// endpoint (e.g. "otelcol:4318") and registers it as the global
// TracerProvider. Returns a shutdown function the caller must defer.
//
// If endpoint is empty, this is a no-op and the package-level Tracer
// remains the noop tracer — spans are free.
//
// The environment variables OTEL_EXPORTER_OTLP_ENDPOINT and
// OTEL_EXPORTER_OTLP_TRACES_ENDPOINT are honored by the upstream
// otlptracehttp library if no explicit endpoint is passed here.
func InitTracing(ctx context.Context, endpoint, version, commit string) (func(context.Context) error, error) {
	if endpoint == "" {
		// Honor OTEL_EXPORTER_OTLP_(TRACES_)?ENDPOINT if set in env.
		endpoint = os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
		if endpoint == "" {
			endpoint = os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		}
	}
	if endpoint == "" {
		return func(context.Context) error { return nil }, nil
	}

	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpointURL(endpoint),
	}
	exp, err := otlptrace.New(ctx, otlptracehttp.NewClient(opts...))
	if err != nil {
		return nil, fmt.Errorf("obs: init OTLP exporter: %w", err)
	}

	// Use plain attributes without a semconv schema URL so we don't
	// conflict with whatever schema resource.Default() ships on.
	res, err := resource.Merge(resource.Default(), resource.NewSchemaless(
		attribute.String("service.name", component),
		attribute.String("service.version", version),
		attribute.String("service.commit", commit),
	))
	if err != nil {
		return nil, fmt.Errorf("obs: build OTel resource: %w", err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exp, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
	)
	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))
	tracer = tp.Tracer("stele")

	return tp.Shutdown, nil
}

// StartSpan is a convenience wrapper around Tracer().Start so callers
// don't have to import otel/trace just for kvs.
func StartSpan(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, trace.Span) {
	return tracer.Start(ctx, name, trace.WithAttributes(attrs...))
}

// AttrString lets non-otel-aware packages add a string attribute to a
// span without importing the otel/attribute package directly. Pair with
// trace.Span.SetAttributes via obs.SetAttrs below.
func AttrString(key, value string) attribute.KeyValue {
	return attribute.String(key, value)
}

// AttrInt64 is the int64 counterpart of AttrString.
func AttrInt64(key string, value int64) attribute.KeyValue {
	return attribute.Int64(key, value)
}

// SetAttrs sets attributes on the current span carried by ctx. No-op if
// the context carries no span.
func SetAttrs(ctx context.Context, attrs ...attribute.KeyValue) {
	trace.SpanFromContext(ctx).SetAttributes(attrs...)
}

// InjectHTTPHeaders serialises the current span context from ctx into
// the given HTTP header carrier (W3C traceparent / tracestate /
// baggage). Use on outbound HTTP requests so downstream services can
// continue the trace.
func InjectHTTPHeaders(ctx context.Context, h http.Header) {
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(h))
}
