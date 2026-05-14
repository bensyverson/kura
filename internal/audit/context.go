package audit

import "context"

// clientIPKey is the context key under which the real client IP of a
// request is carried.
type clientIPKey struct{}

// WithClientIP returns a context carrying the real client IP of the
// request being served. An adapter (the HTTP API, say) sets it once at
// the request boundary; every Record* call made while serving that
// request then stamps the IP onto its event without the adapter having
// to thread it through every call.
func WithClientIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, clientIPKey{}, ip)
}

// ClientIP returns the real client IP carried on ctx by WithClientIP, or
// the empty string if none was set — the case for a call made outside a
// request, such as a CLI-local access.
func ClientIP(ctx context.Context) string {
	ip, _ := ctx.Value(clientIPKey{}).(string)
	return ip
}
