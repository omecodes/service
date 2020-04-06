package service

import (
	"context"
	authpb "github.com/zoenion/common/proto/auth"
	"github.com/zoenion/service/interceptors/authentication"
	"github.com/zoenion/service/jwt"
)

func (box *Box) TokenVerifier() authpb.TokenVerifier {
	return jwt.NewVerifier(box.CACertificate(), box.ServiceCert(), box.ServiceKey(), box.Registry(), box.params.Dir)
}

func (box *Box) JwtVerifyFunc(ctx context.Context, jwt string) (context.Context, error) {
	t, err := authpb.TokenFromJWT(jwt)
	if err != nil {
		return nil, err
	}
	state, err := box.TokenVerifier().Verify(ctx, t)
	if err != nil {
		return ctx, err
	}

	if state == authpb.JWTState_VALID {
		ctx = authentication.ContextWithToken(ctx, t)
	}

	return ctx, nil
}
