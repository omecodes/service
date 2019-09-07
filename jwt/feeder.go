package jwt

import (
	"context"
	"crypto/tls"
	authpb "github.com/zoenion/common/proto/auth"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
)

type Feeder struct {
	serverAddress string
	tlsConfig     *tls.Config
	conn          *grpc.ClientConn
	stream        authpb.JWTStore_FeedClient
}

func (f *Feeder) connect() (err error) {
	if f.conn != nil && f.conn.GetState() == connectivity.Ready {
		return nil
	}

	if f.tlsConfig != nil {
		f.conn, err = grpc.Dial(f.serverAddress, grpc.WithTransportCredentials(credentials.NewTLS(f.tlsConfig)))
	} else {
		f.conn, err = grpc.Dial(f.serverAddress, grpc.WithInsecure())
	}
	return err
}

func (f *Feeder) Register(info *authpb.JwtInfo) (err error) {
	if err = f.connect(); err != nil {
		return
	}

	if f.stream == nil {
		client := authpb.NewJWTStoreClient(f.conn)
		f.stream, err = client.Feed(context.Background())
		if err != nil {
			return
		}
	}

	return f.stream.Send(&authpb.JwtEvent{
		Info:   info,
		Action: authpb.EventAction_Save,
	})
}

func (f *Feeder) Revoke(jti string) (err error) {
	if err = f.connect(); err != nil {
		return
	}

	if f.stream == nil {
		client := authpb.NewJWTStoreClient(f.conn)
		f.stream, err = client.Feed(context.Background())
		if err != nil {
			return
		}
	}

	return f.stream.Send(&authpb.JwtEvent{
		Action: authpb.EventAction_Delete,
		Info:   &authpb.JwtInfo{Jti: jti},
	})
}

func NewJwtFeeder(serverAddress string, tlsConfig *tls.Config) *Feeder {
	return &Feeder{
		serverAddress: serverAddress,
		tlsConfig:     tlsConfig,
	}
}
