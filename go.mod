module github.com/cilium/proxy

go 1.26.4

toolchain go1.27.1

require (
	github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	github.com/envoyproxy/go-control-plane/envoy v1.37.0
	github.com/envoyproxy/protoc-gen-validate v1.3.3
	github.com/sirupsen/logrus v1.10.2
	github.com/stretchr/testify v1.12.1
	golang.org/x/sys v0.48.0
	google.golang.org/genproto/googleapis/api v0.0.0-20260921155816-b14227669459
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260921155816-b14227669459
	google.golang.org/grpc v1.84.0
	google.golang.org/protobuf v1.36.12
)

require (
	cel.dev/expr v0.25.2 // indirect
	github.com/cncf/xds/go v0.0.0-20260202195803-dba9d589def2 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/lyft/protoc-gen-star/v2 v2.0.4 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20260702190614-8ae5a48058df // indirect
	github.com/spf13/afero v1.15.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/mod v0.38.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/tools v0.48.0 // indirect
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.6.2 // indirect
)

tool (
	github.com/envoyproxy/protoc-gen-validate
	github.com/planetscale/vtprotobuf/cmd/protoc-gen-go-vtproto
	google.golang.org/grpc/cmd/protoc-gen-go-grpc
	google.golang.org/protobuf/cmd/protoc-gen-go
)
