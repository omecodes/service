package registry

import "context"

type ctxType string

const (
	contextBroadcastDisabled = ctxType("broadcastDisabled")
)

func broadcastDisabled(ctx context.Context) bool {
	val := ctx.Value(contextBroadcastDisabled)
	if val == nil {
		return false
	}

	boolVal, castOK := val.(bool)
	return castOK && boolVal
}

func withBroadcastEnabled(ctx context.Context, disabled bool) context.Context {
	return context.WithValue(ctx, contextBroadcastDisabled, disabled)
}
