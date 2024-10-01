module github.com/cilium/proxy

go 1.22

require (
	github.com/census-instrumentation/opencensus-proto v0.4.1
	github.com/cilium/checkmate v1.0.3
	github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	github.com/cncf/xds/go v0.0.0-20240905190251-b4127c9b8d78
	github.com/envoyproxy/protoc-gen-validate v1.1.0
	github.com/golang/protobuf v1.5.4
	github.com/google/uuid v1.6.0
	github.com/prometheus/client_model v0.6.1
	github.com/sasha-s/go-deadlock v0.3.5
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.9.0
	go.opentelemetry.io/proto/otlp v1.3.1
	golang.org/x/sync v0.8.0
	golang.org/x/sys v0.25.0
	google.golang.org/genproto/googleapis/api v0.0.0-20240930140551-af27646dc61f
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240930140551-af27646dc61f
	google.golang.org/grpc v1.67.1
	google.golang.org/protobuf v1.34.2
	k8s.io/klog/v2 v2.130.1
)

require (
	cel.dev/expr v0.16.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/petermattis/goid v0.0.0-20240813172612-4fcff4a6cae7 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
