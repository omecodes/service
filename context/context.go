package context

import (
	"context"
	"github.com/zoenion/common/errors"
	authpb "github.com/zoenion/common/proto/auth"
)

type Key string

const (
	//Jwt            = Key("jwt")
	//Token          = Key("token")
	User = Key("user")
	//UserAgent      = Key("user-agent")
	//PeerAddress    = Key("peer-address")
	ServiceContext = Key("service-context")

	AuthorizationToken    = Key("Authorization-Token")
	StrAuthorizationToken = Key("St-Authorization-Token")
	Credentials           = Key("Credentials")
)

func TokenFromContext(ctx context.Context) (*authpb.JWT, error) {
	authorizationTokenValue := ctx.Value(AuthorizationToken)
	if authorizationTokenValue == nil {
		// w.WriteHeader(http.StatusUnauthorized)
		return nil, nil
	}

	token, ok := authorizationTokenValue.(*authpb.JWT)
	if !ok {
		return nil, errors.Errorf("Unsupported object token from request context: %s", authorizationTokenValue)
	}

	return token, nil
}

func CredentialsFromContext(ctx context.Context) (*authpb.Credentials, error) {
	credentialsValue := ctx.Value(Credentials)
	if credentialsValue == nil {
		// w.WriteHeader(http.StatusUnauthorized)
		return nil, nil
	}

	credentials, ok := credentialsValue.(*authpb.Credentials)
	if !ok {
		return nil, errors.Errorf("Unsupported object token from request context: %s", credentialsValue)
	}

	return credentials, nil
}
