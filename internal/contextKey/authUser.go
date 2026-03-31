package contextkey

import "context"

type contextKey string

const authUserKey contextKey = "authUser"

func WithAuthUser(ctx context.Context, user string) context.Context {
	return context.WithValue(ctx, authUserKey, user)
}

func AuthUserFromContext(ctx context.Context) (string, bool) {
	user, ok := ctx.Value(authUserKey).(string)
	if !ok || user == "" {
		return "", false
	}
	return user, true
}
