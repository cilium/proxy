module github.com/cilium/proxy

go 1.24.0

toolchain go1.24.7

require (
	github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	github.com/envoyproxy/go-control-plane/envoy v1.32.4
	github.com/envoyproxy/protoc-gen-validate v1.2.1
	github.com/golang/protobuf v1.5.4
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.11.1
	golang.org/x/sys v0.36.0
	google.golang.org/genproto/googleapis/api v0.0.0-20250908214217-97024824d090
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250908214217-97024824d090
	google.golang.org/grpc v1.75.1
	google.golang.org/protobuf v1.36.9
)

require (
	cel.dev/expr v0.24.0 // indirect
	github.com/cncf/xds/go v0.0.0-20250501225837-2ac532fd4443 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/lyft/protoc-gen-star/v2 v2.0.4-0.20230330145011-496ad1ac90a4 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/afero v1.10.0 // indirect
	golang.org/x/mod v0.25.0 // indirect
	golang.org/x/net v0.41.0 // indirect
	golang.org/x/sync v0.15.0 // indirect
	golang.org/x/text v0.26.0 // indirect
	golang.org/x/tools v0.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

tool (
	github.com/envoyproxy/protoc-gen-validate
	github.com/golang/protobuf/protoc-gen-go
	google.golang.org/protobuf
)
