module github.com/cilium/proxy

go 1.25.0

toolchain go1.26.3

require (
	github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	github.com/envoyproxy/go-control-plane/envoy v1.37.0
	github.com/envoyproxy/protoc-gen-validate v1.3.3
	github.com/sirupsen/logrus v1.9.4
	github.com/stretchr/testify v1.11.1
	golang.org/x/sys v0.44.0
	google.golang.org/genproto/googleapis/api v0.0.0-20260519071638-aa98bba5eb94
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260519071638-aa98bba5eb94
	google.golang.org/grpc v1.81.1
	google.golang.org/protobuf v1.36.11
)

require (
	cel.dev/expr v0.25.1 // indirect
	github.com/cncf/xds/go v0.0.0-20260202195803-dba9d589def2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/lyft/protoc-gen-star/v2 v2.0.4 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	golang.org/x/mod v0.32.0 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	golang.org/x/tools v0.41.0 // indirect
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.6.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

tool (
	github.com/envoyproxy/protoc-gen-validate
	google.golang.org/grpc/cmd/protoc-gen-go-grpc
	google.golang.org/protobuf/cmd/protoc-gen-go
)
