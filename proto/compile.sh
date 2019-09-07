#!/bin/bash

protoc -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
	-I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway \
	-I$GOPATH/src/github.com/google/protobuf \
	-I$GOPATH/src/github.com/golang/protobuf \
	-I$GOPATH/src \
	-I. \
	--swagger_out=. *.proto

protoc -I. \
  -I$GOPATH/src \
  -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
  --go_out=plugins=grpc:. *.proto

protoc -I. \
  -I$GOPATH/src \
  -I$GOPATH/src/github.com/grpc-ecosystem/grpc-gateway/third_party/googleapis \
  --grpc-gateway_out=logtostderr=true:. *.proto