package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

// TracerName is the instrumentation scope of every Sigillum span.
const TracerName = "github.com/se-wo/sigillum"

// Tracer returns the Sigillum tracer from the global provider. Until
// InitTracing installs an SDK provider this is a no-op tracer, so callers can
// create spans unconditionally.
func Tracer() trace.Tracer {
	return otel.Tracer(TracerName)
}

// InitTracing configures OTLP/HTTP trace export from the standard
// OpenTelemetry environment variables (US-4.4):
//
//	OTEL_EXPORTER_OTLP_ENDPOINT / OTEL_EXPORTER_OTLP_TRACES_ENDPOINT
//	OTEL_EXPORTER_OTLP_HEADERS, OTEL_EXPORTER_OTLP_INSECURE, ...
//	OTEL_SERVICE_NAME, OTEL_RESOURCE_ATTRIBUTES
//	OTEL_TRACES_SAMPLER, OTEL_TRACES_SAMPLER_ARG
//	OTEL_SDK_DISABLED
//
// Tracing stays disabled (no-op, zero overhead) unless an endpoint is set.
// W3C trace-context propagation is installed either way, so an incoming
// traceparent is still honored by downstream log correlation.
// The returned shutdown func flushes pending spans.
func InitTracing(ctx context.Context, defaultServiceName string) (shutdown func(context.Context) error, enabled bool, err error) {
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{}))
	noop := func(context.Context) error { return nil }

	if strings.EqualFold(os.Getenv("OTEL_SDK_DISABLED"), "true") {
		return noop, false, nil
	}
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" {
		return noop, false, nil
	}
	proto := os.Getenv("OTEL_EXPORTER_OTLP_TRACES_PROTOCOL")
	if proto == "" {
		proto = os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	}
	if proto != "" && proto != "http/protobuf" {
		return noop, false, fmt.Errorf("OTLP protocol %q is not supported; use http/protobuf (port 4318)", proto)
	}

	exp, err := otlptracehttp.New(ctx)
	if err != nil {
		return noop, false, fmt.Errorf("otlp exporter: %w", err)
	}
	res, err := resource.New(ctx,
		resource.WithAttributes(attribute.String("service.name", defaultServiceName)),
		resource.WithFromEnv(), // OTEL_SERVICE_NAME / OTEL_RESOURCE_ATTRIBUTES override the default
		resource.WithTelemetrySDK(),
		resource.WithHost(),
	)
	if err != nil {
		return noop, false, fmt.Errorf("otel resource: %w", err)
	}
	// The SDK reads OTEL_TRACES_SAMPLER itself; default is parentbased_always_on.
	tp := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exp), sdktrace.WithResource(res))
	otel.SetTracerProvider(tp)
	return tp.Shutdown, true, nil
}

// statusRecorder captures the response status for the span.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// HTTPMiddleware starts the root "http.request" span, continuing any W3C
// traceparent sent by the caller.
func HTTPMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))
		ctx, span := Tracer().Start(ctx, "http.request",
			trace.WithSpanKind(trace.SpanKindServer),
			trace.WithAttributes(
				attribute.String("http.request.method", r.Method),
				attribute.String("url.path", r.URL.Path),
			))
		defer span.End()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r.WithContext(ctx))
		span.SetAttributes(attribute.Int("http.response.status_code", rec.status))
		if rec.status >= 500 {
			span.SetStatus(codes.Error, http.StatusText(rec.status))
		}
	})
}

// TraceID returns the hex trace ID of the span in ctx, or "" if none.
func TraceID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.IsValid() {
		return ""
	}
	return sc.TraceID().String()
}
