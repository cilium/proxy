module github.com/cilium/proxy

go 1.21

require (
	github.com/census-instrumentation/opencensus-proto v0.4.1
	github.com/cilium/checkmate v1.0.3
	github.com/cilium/kafka v0.0.0-20180809090225-01ce283b732b
	github.com/cncf/xds/go v0.0.0-20240329184929-0c46c01016dc
	github.com/envoyproxy/protoc-gen-validate v1.0.4
	github.com/golang/protobuf v1.5.4
	github.com/google/uuid v1.6.0
	github.com/prometheus/client_model v0.6.1
	github.com/sasha-s/go-deadlock v0.3.1
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.9.0
	go.opentelemetry.io/proto/otlp v1.1.0
	golang.org/x/sync v0.7.0
	golang.org/x/sys v0.19.0
	google.golang.org/genproto/googleapis/api v0.0.0-20240401170217-c3f982113cda
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240401170217-c3f982113cda
	google.golang.org/grpc v1.63.0
	google.golang.org/protobuf v1.33.0
	k8s.io/klog/v2 v2.120.1
)

require (
	cel.dev/expr v0.15.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/petermattis/goid v0.0.0-20180202154549-b0b1615b78e5 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	golang.org/x/net v0.21.0 // indirect
	golang.org/x/text v0.14.0 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
