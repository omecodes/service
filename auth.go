package service

import (
	"context"

	"github.com/omecodes/common/errors"
	"github.com/omecodes/common/utils/log"
	"github.com/omecodes/libome"
)

func (box *Box) TokenVerifier(store JwtInfoStore) ome.TokenVerifier {
	return NewJwtVerifier(box.ClientMutualTLS(), box.Registry(), store)
}

func (box *Box) JwtVerifyFunc(ctx context.Context, jwt string) (context.Context, error) {
	t, err := ome.ParseJWT(jwt)
	if err != nil {
		return ctx, err
	}
	state, err := box.TokenVerifier(nil).Verify(ctx, t)
	if err != nil {
		return ctx, err
	}

	if state == ome.JWTState_Valid {
		ctx = ome.ContextWithToken(ctx, t)
	}

	return ctx, nil
}

func VerifyJwt(ctx context.Context, jwt string) error {
	box := BoxFromContext(ctx)
	_, err := box.JwtVerifyFunc(ctx, jwt)
	return err
}

func RevokeJwt(ctx context.Context, jwt string) error {
	conn, err := Connect(ctx, ome.TokenStoreServiceType)
	if err != nil {
		return err
	}

	t, err := ome.ParseJWT(jwt)
	if err != nil {
		log.Error("could not parse JWT", log.Err(err))
		return errors.BadInput
	}

	client := ome.NewTokenStoreServiceClient(conn)
	_, err = client.DeleteJwt(ctx, &ome.DeleteJwtRequest{Jti: t.Claims.Jti})
	return err
}

type CredentialsValidatorFunc func(credentials *ome.ProxyCredentials) (bool, error)
