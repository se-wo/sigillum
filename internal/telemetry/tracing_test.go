package telemetry

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/otel"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestInitTracing_DisabledWithoutEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
	_, enabled, err := InitTracing(context.Background(), "test")
	if err != nil || enabled {
		t.Fatalf("want disabled without error, got enabled=%v err=%v", enabled, err)
	}
}

func TestInitTracing_RejectsGRPC(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector:4317")
	t.Setenv("OTEL_EXPORTER_OTLP_PROTOCOL", "grpc")
	if _, _, err := InitTracing(context.Background(), "test"); err == nil {
		t.Fatal("want error for unsupported grpc protocol")
	}
}

func TestInitTracing_EnabledWithEndpoint(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:1")
	shutdown, enabled, err := InitTracing(context.Background(), "test")
	if err != nil || !enabled {
		t.Fatalf("want enabled, got enabled=%v err=%v", enabled, err)
	}
	t.Cleanup(func() { otel.SetTracerProvider(sdktrace.NewTracerProvider()) })
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // do not wait on the unreachable collector
	_ = shutdown(ctx)
}

func TestHTTPMiddleware_ContinuesIncomingTraceparent(t *testing.T) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exp))
	prev := otel.GetTracerProvider()
	otel.SetTracerProvider(tp)
	t.Cleanup(func() { otel.SetTracerProvider(prev) })
	_, _, _ = InitTracing(context.Background(), "test") // installs the W3C propagator only

	const traceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	var seen string
	h := HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = TraceID(r.Context())
		w.WriteHeader(http.StatusBadGateway)
	}))
	r := httptest.NewRequest(http.MethodPost, "/v1/messages", nil)
	r.Header.Set("traceparent", "00-"+traceID+"-00f067aa0ba902b7-01")
	h.ServeHTTP(httptest.NewRecorder(), r)

	if seen != traceID {
		t.Fatalf("handler saw trace %q, want %q", seen, traceID)
	}
	spans := exp.GetSpans()
	if len(spans) != 1 || spans[0].Name != "http.request" || spans[0].Parent.SpanID().String() != "00f067aa0ba902b7" {
		t.Fatalf("unexpected spans %+v", spans)
	}
	if spans[0].Status.Code.String() != "Error" {
		t.Fatalf("5xx must mark the span as error, got %v", spans[0].Status)
	}
}
