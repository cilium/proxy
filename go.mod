module github.com/cilium/proxy

go 1.23.0

toolchain go1.24.3

require (
	github.com/cilium/checkmate v1.0.3
	github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	github.com/envoyproxy/go-control-plane/envoy v1.32.4
	github.com/envoyproxy/protoc-gen-validate v1.2.1
	github.com/golang/protobuf v1.5.4
	github.com/sirupsen/logrus v1.9.3
	golang.org/x/sys v0.33.0
	google.golang.org/genproto/googleapis/api v0.0.0-20250519155744-55703ea1f237
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250519155744-55703ea1f237
	google.golang.org/grpc v1.72.1
	google.golang.org/protobuf v1.36.6
)

require (
	cel.dev/expr v0.20.0 // indirect
	github.com/cncf/xds/go v0.0.0-20250501225837-2ac532fd4443 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	github.com/stretchr/testify v1.10.0 // indirect
	golang.org/x/net v0.39.0 // indirect
	golang.org/x/text v0.24.0 // indirect
)

tool (
	github.com/golang/protobuf/protoc-gen-go
	google.golang.org/protobuf
)
