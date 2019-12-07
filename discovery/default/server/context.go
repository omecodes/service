package server

import "context"

type ctxType string

const (
	contextBroadcastEnabled = ctxType("broadcastEnabled")
)

func broadcastEnabled(ctx context.Context) bool {
	val := ctx.Value(contextBroadcastEnabled)
	if val == nil {
		return false
	}

	boolVal, castOK := val.(bool)
	return castOK && boolVal
}

func withBroadcastEnabled(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, contextBroadcastEnabled, enabled)
}
