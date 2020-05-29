package service

import (
	"context"
	"github.com/zoenion/common/errors"
	authpb "github.com/zoenion/common/proto/auth"
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
		ctx = authpb.ContextWithToken(ctx, t)
	}

	return ctx, nil
}

func VerifyJWT(ctx context.Context, jwt string) (*authpb.JWT, error) {
	box := BoxFromContext(ctx)
	if box == nil {
		return nil, errors.Internal
	}

	t, err := authpb.TokenFromJWT(jwt)
	if err != nil {
		return nil, errors.BadInput
	}

	state, err := box.TokenVerifier().Verify(ctx, t)
	if err != nil {
		return nil, err
	}

	if state != authpb.JWTState_VALID {
		return nil, errors.Unauthorized
	}

	return t, nil
}