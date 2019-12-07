package server

import (
	"fmt"
	pb "github.com/zoenion/service/proto"
)

type idGenerator int

func (ig idGenerator) GenerateID(info *pb.Info) string {
	return fmt.Sprintf("%s.%s", info.Namespace, info.Name)
}
