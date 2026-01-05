// Package tracing provides OpenTelemetry distributed tracing support.
package tracing

import (
	"context"
	"net/http"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Config holds OpenTelemetry configuration.
type Config struct {
	Enabled      bool
	Endpoint     string
	ServiceName  string
	SampleRate   float64
	BatchTimeout time.Duration
}

// DefaultConfig returns default tracing configuration.
func DefaultConfig() Config {
	return Config{
		Enabled:      false,
		Endpoint:     "localhost:4317",
		ServiceName:  "gateway",
		SampleRate:   1.0,
		BatchTimeout: 5 * time.Second,
	}
}

// Provider manages the OpenTelemetry tracer provider.
type Provider struct {
	provider *sdktrace.TracerProvider
	tracer   trace.Tracer
}

// NewProvider creates a new tracing provider.
func NewProvider(ctx context.Context, cfg Config) (*Provider, error) {
	if !cfg.Enabled {
		return &Provider{
			tracer: otel.Tracer(cfg.ServiceName),
		}, nil
	}

	// Create OTLP exporter
	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(cfg.Endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	// Create resource
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			semconv.ServiceVersion("1.0.0"),
		),
	)
	if err != nil {
		return nil, err
	}

	// Create sampler
	var sampler sdktrace.Sampler
	if cfg.SampleRate >= 1.0 {
		sampler = sdktrace.AlwaysSample()
	} else if cfg.SampleRate <= 0 {
		sampler = sdktrace.NeverSample()
	} else {
		sampler = sdktrace.TraceIDRatioBased(cfg.SampleRate)
	}

	// Create tracer provider
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter, sdktrace.WithBatchTimeout(cfg.BatchTimeout)),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)

	// Set global provider and propagator
	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return &Provider{
		provider: provider,
		tracer:   provider.Tracer(cfg.ServiceName),
	}, nil
}

// Shutdown shuts down the tracer provider.
func (p *Provider) Shutdown(ctx context.Context) error {
	if p.provider != nil {
		return p.provider.Shutdown(ctx)
	}
	return nil
}

// Tracer returns the tracer.
func (p *Provider) Tracer() trace.Tracer {
	return p.tracer
}

// Middleware returns HTTP middleware for tracing.
func (p *Provider) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract trace context from incoming request
			ctx := otel.GetTextMapPropagator().Extract(r.Context(), propagation.HeaderCarrier(r.Header))

			// Start span
			spanName := r.Method + " " + r.URL.Path
			ctx, span := p.tracer.Start(ctx, spanName,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(
					semconv.HTTPRequestMethodKey.String(r.Method),
					semconv.URLPath(r.URL.Path),
					semconv.URLScheme(r.URL.Scheme),
					semconv.ServerAddress(r.Host),
					semconv.UserAgentOriginal(r.UserAgent()),
					semconv.ClientAddress(r.RemoteAddr),
				),
			)
			defer span.End()

			// Wrap response writer to capture status
			rw := &tracingResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			// Continue with traced context
			next.ServeHTTP(rw, r.WithContext(ctx))

			// Record response status
			span.SetAttributes(semconv.HTTPResponseStatusCode(rw.statusCode))

			if rw.statusCode >= 400 {
				span.SetStatus(codes.Error, http.StatusText(rw.statusCode))
			} else {
				span.SetStatus(codes.Ok, "")
			}
		})
	}
}

// tracingResponseWriter wraps http.ResponseWriter to capture status code.
type tracingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (w *tracingResponseWriter) WriteHeader(statusCode int) {
	w.statusCode = statusCode
	w.ResponseWriter.WriteHeader(statusCode)
}

// StartSpan starts a new span from context.
func (p *Provider) StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return p.tracer.Start(ctx, name, opts...)
}

// SpanFromContext returns the span from context.
func SpanFromContext(ctx context.Context) trace.Span {
	return trace.SpanFromContext(ctx)
}

// AddEvent adds an event to the current span.
func AddEvent(ctx context.Context, name string, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.AddEvent(name, trace.WithAttributes(attrs...))
}

// RecordError records an error on the current span.
func RecordError(ctx context.Context, err error) {
	span := trace.SpanFromContext(ctx)
	span.RecordError(err)
	span.SetStatus(codes.Error, err.Error())
}

// SetAttributes sets attributes on the current span.
func SetAttributes(ctx context.Context, attrs ...attribute.KeyValue) {
	span := trace.SpanFromContext(ctx)
	span.SetAttributes(attrs...)
}

// InjectContext injects trace context into HTTP headers.
func InjectContext(ctx context.Context, headers http.Header) {
	otel.GetTextMapPropagator().Inject(ctx, propagation.HeaderCarrier(headers))
}
