package service

import (
	authpb "github.com/zoenion/common/proto/auth"
	"github.com/zoenion/service/jwt"
)

func (box *Box) TokenVerifier() authpb.TokenVerifier {
	return jwt.NewVerifier(box.CACertificate(), box.ServiceCert(), box.ServiceKey(), box.Registry(), box.params.Dir)
}
