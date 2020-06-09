package service

import (
	"context"
	authpb "github.com/omecodes/common/proto/auth"
	"github.com/omecodes/service/jwt"
)

func (box *Box) TokenVerifier() authpb.TokenVerifier {
	return jwt.NewVerifier(box.CACertificate(), box.ServiceCert(), box.ServiceKey(), box.Registry(), box.params.Dir)
}

func (box *Box) BearerTokenVerifyFunc(ctx context.Context, jwt string) (context.Context, error) {
	t, err := authpb.ParseJWT(jwt)
	if err != nil {
		return ctx, err
	}
	state, err := box.TokenVerifier().Verify(ctx, t)
	if err != nil {
		return ctx, err
	}

	if state == authpb.JWTState_VALID {
		ctx = authpb.ContextWithToken(ctx, t)
	}

	return ctx, nil
}
