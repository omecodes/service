package service

import (
	"context"
	"github.com/omecodes/common/errors"
	authpb "github.com/omecodes/common/ome/proto/auth"
	pb2 "github.com/omecodes/common/ome/proto/service"
	"github.com/omecodes/common/utils/log"
	"github.com/omecodes/service/jwt"
)

func (box *Box) TokenVerifier() authpb.TokenVerifier {
	return jwt.NewVerifier(box.CACertificate(), box.ServiceCert(), box.ServiceKey(), box.Registry(), box.params.Dir)
}

func (box *Box) JwtVerifyFunc(ctx context.Context, jwt string) (context.Context, error) {
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

func VerifyJwt(ctx context.Context, jwt string) error {
	box := BoxFromContext(ctx)
	_, err := box.JwtVerifyFunc(ctx, jwt)
	return err
}

func RevokeJwt(ctx context.Context, jwt string) error {
	conn, err := Connect(ctx, pb2.Type_TokenStore)
	if err != nil {
		return err
	}

	t, err := authpb.ParseJWT(jwt)
	if err != nil {
		log.Error("could not parse JWT", log.Err(err))
		return errors.BadInput
	}

	client := authpb.NewTokenStoreServiceClient(conn)
	_, err = client.RevokeToken(ctx, &authpb.RevokeTokenRequest{Jwt: t})
	return err
}
