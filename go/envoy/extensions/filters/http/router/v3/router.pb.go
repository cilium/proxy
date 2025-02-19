// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v5.29.2
// source: envoy/extensions/filters/http/router/v3/router.proto

package routerv3

import (
	_ "github.com/cilium/proxy/go/envoy/annotations"
	v3 "github.com/cilium/proxy/go/envoy/config/accesslog/v3"
	v31 "github.com/cilium/proxy/go/envoy/extensions/filters/network/http_connection_manager/v3"
	_ "github.com/cncf/xds/go/udpa/annotations"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
	wrapperspb "google.golang.org/protobuf/types/known/wrapperspb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

// This is a compile-time assertion that a sufficiently up-to-date version
// of the legacy proto package is being used.
const _ = proto.ProtoPackageIsVersion4

// [#next-free-field: 10]
type Router struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Whether the router generates dynamic cluster statistics. Defaults to
	// true. Can be disabled in high performance scenarios.
	DynamicStats *wrapperspb.BoolValue `protobuf:"bytes,1,opt,name=dynamic_stats,json=dynamicStats,proto3" json:"dynamic_stats,omitempty"`
	// Whether to start a child span for egress routed calls. This can be
	// useful in scenarios where other filters (auth, ratelimit, etc.) make
	// outbound calls and have child spans rooted at the same ingress
	// parent. Defaults to false.
	//
	// .. attention::
	//
	//	This field is deprecated by the
	//	:ref:`spawn_upstream_span <envoy_v3_api_field_extensions.filters.network.http_connection_manager.v3.HttpConnectionManager.Tracing.spawn_upstream_span>`.
	//	Please use that ``spawn_upstream_span`` field to control the span creation.
	//
	// Deprecated: Do not use.
	StartChildSpan bool `protobuf:"varint,2,opt,name=start_child_span,json=startChildSpan,proto3" json:"start_child_span,omitempty"`
	// Configuration for HTTP upstream logs emitted by the router. Upstream logs
	// are configured in the same way as access logs, but each log entry represents
	// an upstream request. Presuming retries are configured, multiple upstream
	// requests may be made for each downstream (inbound) request.
	UpstreamLog []*v3.AccessLog `protobuf:"bytes,3,rep,name=upstream_log,json=upstreamLog,proto3" json:"upstream_log,omitempty"`
	// Additional upstream access log options.
	UpstreamLogOptions *Router_UpstreamAccessLogOptions `protobuf:"bytes,9,opt,name=upstream_log_options,json=upstreamLogOptions,proto3" json:"upstream_log_options,omitempty"`
	// Do not add any additional “x-envoy-“ headers to requests or responses. This
	// only affects the :ref:`router filter generated x-envoy- headers
	// <config_http_filters_router_headers_set>`, other Envoy filters and the HTTP
	// connection manager may continue to set “x-envoy-“ headers.
	SuppressEnvoyHeaders bool `protobuf:"varint,4,opt,name=suppress_envoy_headers,json=suppressEnvoyHeaders,proto3" json:"suppress_envoy_headers,omitempty"`
	// Specifies a list of HTTP headers to strictly validate. Envoy will reject a
	// request and respond with HTTP status 400 if the request contains an invalid
	// value for any of the headers listed in this field. Strict header checking
	// is only supported for the following headers:
	//
	// Value must be a ','-delimited list (i.e. no spaces) of supported retry
	// policy values:
	//
	// * :ref:`config_http_filters_router_x-envoy-retry-grpc-on`
	// * :ref:`config_http_filters_router_x-envoy-retry-on`
	//
	// Value must be an integer:
	//
	// * :ref:`config_http_filters_router_x-envoy-max-retries`
	// * :ref:`config_http_filters_router_x-envoy-upstream-rq-timeout-ms`
	// * :ref:`config_http_filters_router_x-envoy-upstream-rq-per-try-timeout-ms`
	StrictCheckHeaders []string `protobuf:"bytes,5,rep,name=strict_check_headers,json=strictCheckHeaders,proto3" json:"strict_check_headers,omitempty"`
	// If not set, ingress Envoy will ignore
	// :ref:`config_http_filters_router_x-envoy-expected-rq-timeout-ms` header, populated by egress
	// Envoy, when deriving timeout for upstream cluster.
	RespectExpectedRqTimeout bool `protobuf:"varint,6,opt,name=respect_expected_rq_timeout,json=respectExpectedRqTimeout,proto3" json:"respect_expected_rq_timeout,omitempty"`
	// If set, Envoy will avoid incrementing HTTP failure code stats
	// on gRPC requests. This includes the individual status code value
	// (e.g. upstream_rq_504) and group stats (e.g. upstream_rq_5xx).
	// This field is useful if interested in relying only on the gRPC
	// stats filter to define success and failure metrics for gRPC requests
	// as not all failed gRPC requests charge HTTP status code metrics. See
	// :ref:`gRPC stats filter<config_http_filters_grpc_stats>` documentation
	// for more details.
	SuppressGrpcRequestFailureCodeStats bool `protobuf:"varint,7,opt,name=suppress_grpc_request_failure_code_stats,json=suppressGrpcRequestFailureCodeStats,proto3" json:"suppress_grpc_request_failure_code_stats,omitempty"`
	// .. note::
	//
	//	Upstream HTTP filters are currently in alpha.
	//
	// Optional HTTP filters for the upstream HTTP filter chain.
	//
	// These filters will be applied for all requests that pass through the router.
	// They will also be applied to shadowed requests.
	// Upstream HTTP filters cannot change route or cluster.
	// Upstream HTTP filters specified on the cluster will override these filters.
	//
	// If using upstream HTTP filters, please be aware that local errors sent by
	// upstream HTTP filters will not trigger retries, and local errors sent by
	// upstream HTTP filters will count as a final response if hedging is configured.
	// [#extension-category: envoy.filters.http.upstream]
	UpstreamHttpFilters []*v31.HttpFilter `protobuf:"bytes,8,rep,name=upstream_http_filters,json=upstreamHttpFilters,proto3" json:"upstream_http_filters,omitempty"`
}

func (x *Router) Reset() {
	*x = Router{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_http_router_v3_router_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Router) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Router) ProtoMessage() {}

func (x *Router) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_http_router_v3_router_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Router.ProtoReflect.Descriptor instead.
func (*Router) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_http_router_v3_router_proto_rawDescGZIP(), []int{0}
}

func (x *Router) GetDynamicStats() *wrapperspb.BoolValue {
	if x != nil {
		return x.DynamicStats
	}
	return nil
}

// Deprecated: Do not use.
func (x *Router) GetStartChildSpan() bool {
	if x != nil {
		return x.StartChildSpan
	}
	return false
}

func (x *Router) GetUpstreamLog() []*v3.AccessLog {
	if x != nil {
		return x.UpstreamLog
	}
	return nil
}

func (x *Router) GetUpstreamLogOptions() *Router_UpstreamAccessLogOptions {
	if x != nil {
		return x.UpstreamLogOptions
	}
	return nil
}

func (x *Router) GetSuppressEnvoyHeaders() bool {
	if x != nil {
		return x.SuppressEnvoyHeaders
	}
	return false
}

func (x *Router) GetStrictCheckHeaders() []string {
	if x != nil {
		return x.StrictCheckHeaders
	}
	return nil
}

func (x *Router) GetRespectExpectedRqTimeout() bool {
	if x != nil {
		return x.RespectExpectedRqTimeout
	}
	return false
}

func (x *Router) GetSuppressGrpcRequestFailureCodeStats() bool {
	if x != nil {
		return x.SuppressGrpcRequestFailureCodeStats
	}
	return false
}

func (x *Router) GetUpstreamHttpFilters() []*v31.HttpFilter {
	if x != nil {
		return x.UpstreamHttpFilters
	}
	return nil
}

type Router_UpstreamAccessLogOptions struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// If set to true, an upstream access log will be recorded when an upstream stream is
	// associated to an http request. Note: Each HTTP request received for an already established
	// connection will result in an upstream access log record. This includes, for example,
	// consecutive HTTP requests over the same connection or a request that is retried.
	// In case a retry is applied, an upstream access log will be recorded for each retry.
	FlushUpstreamLogOnUpstreamStream bool `protobuf:"varint,1,opt,name=flush_upstream_log_on_upstream_stream,json=flushUpstreamLogOnUpstreamStream,proto3" json:"flush_upstream_log_on_upstream_stream,omitempty"`
	// The interval to flush the upstream access logs. By default, the router will flush an upstream
	// access log on stream close, when the HTTP request is complete. If this field is set, the router
	// will flush access logs periodically at the specified interval. This is especially useful in the
	// case of long-lived requests, such as CONNECT and Websockets.
	// The interval must be at least 1 millisecond.
	UpstreamLogFlushInterval *durationpb.Duration `protobuf:"bytes,2,opt,name=upstream_log_flush_interval,json=upstreamLogFlushInterval,proto3" json:"upstream_log_flush_interval,omitempty"`
}

func (x *Router_UpstreamAccessLogOptions) Reset() {
	*x = Router_UpstreamAccessLogOptions{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_http_router_v3_router_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Router_UpstreamAccessLogOptions) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Router_UpstreamAccessLogOptions) ProtoMessage() {}

func (x *Router_UpstreamAccessLogOptions) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_http_router_v3_router_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Router_UpstreamAccessLogOptions.ProtoReflect.Descriptor instead.
func (*Router_UpstreamAccessLogOptions) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_http_router_v3_router_proto_rawDescGZIP(), []int{0, 0}
}

func (x *Router_UpstreamAccessLogOptions) GetFlushUpstreamLogOnUpstreamStream() bool {
	if x != nil {
		return x.FlushUpstreamLogOnUpstreamStream
	}
	return false
}

func (x *Router_UpstreamAccessLogOptions) GetUpstreamLogFlushInterval() *durationpb.Duration {
	if x != nil {
		return x.UpstreamLogFlushInterval
	}
	return nil
}

var File_envoy_extensions_filters_http_router_v3_router_proto protoreflect.FileDescriptor

var file_envoy_extensions_filters_http_router_v3_router_proto_rawDesc = []byte{
	0x0a, 0x34, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f,
	0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2f, 0x76, 0x33, 0x2f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x27, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78,
	0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73,
	0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x1a,
	0x29, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x61, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x6c, 0x6f, 0x67, 0x2f, 0x76, 0x33, 0x2f, 0x61, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x6c, 0x6f, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x59, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c,
	0x74, 0x65, 0x72, 0x73, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x68, 0x74, 0x74,
	0x70, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x61, 0x6e,
	0x61, 0x67, 0x65, 0x72, 0x2f, 0x76, 0x33, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x5f, 0x63, 0x6f, 0x6e,
	0x6e, 0x65, 0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x23, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x61, 0x6e, 0x6e,
	0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x64, 0x65, 0x70, 0x72, 0x65, 0x63, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61,
	0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61,
	0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x75, 0x64, 0x70, 0x61, 0x2f,
	0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x65, 0x72, 0x73,
	0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61,
	0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xe0, 0x08, 0x0a, 0x06, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x72,
	0x12, 0x3f, 0x0a, 0x0d, 0x64, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x5f, 0x73, 0x74, 0x61, 0x74,
	0x73, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x42, 0x6f, 0x6f, 0x6c, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x52, 0x0c, 0x64, 0x79, 0x6e, 0x61, 0x6d, 0x69, 0x63, 0x53, 0x74, 0x61, 0x74,
	0x73, 0x12, 0x35, 0x0a, 0x10, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x63, 0x68, 0x69, 0x6c, 0x64,
	0x5f, 0x73, 0x70, 0x61, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x08, 0x42, 0x0b, 0x18, 0x01, 0x92,
	0xc7, 0x86, 0xd8, 0x04, 0x03, 0x33, 0x2e, 0x30, 0x52, 0x0e, 0x73, 0x74, 0x61, 0x72, 0x74, 0x43,
	0x68, 0x69, 0x6c, 0x64, 0x53, 0x70, 0x61, 0x6e, 0x12, 0x47, 0x0a, 0x0c, 0x75, 0x70, 0x73, 0x74,
	0x72, 0x65, 0x61, 0x6d, 0x5f, 0x6c, 0x6f, 0x67, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x24,
	0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x61, 0x63,
	0x63, 0x65, 0x73, 0x73, 0x6c, 0x6f, 0x67, 0x2e, 0x76, 0x33, 0x2e, 0x41, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x4c, 0x6f, 0x67, 0x52, 0x0b, 0x75, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x4c, 0x6f,
	0x67, 0x12, 0x7a, 0x0a, 0x14, 0x75, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x5f, 0x6c, 0x6f,
	0x67, 0x5f, 0x6f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18, 0x09, 0x20, 0x01, 0x28, 0x0b, 0x32,
	0x48, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e,
	0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x2e, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x72,
	0x2e, 0x55, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x41, 0x63, 0x63, 0x65, 0x73, 0x73, 0x4c,
	0x6f, 0x67, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x52, 0x12, 0x75, 0x70, 0x73, 0x74, 0x72,
	0x65, 0x61, 0x6d, 0x4c, 0x6f, 0x67, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x34, 0x0a,
	0x16, 0x73, 0x75, 0x70, 0x70, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x5f,
	0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x14, 0x73,
	0x75, 0x70, 0x70, 0x72, 0x65, 0x73, 0x73, 0x45, 0x6e, 0x76, 0x6f, 0x79, 0x48, 0x65, 0x61, 0x64,
	0x65, 0x72, 0x73, 0x12, 0xc7, 0x01, 0x0a, 0x14, 0x73, 0x74, 0x72, 0x69, 0x63, 0x74, 0x5f, 0x63,
	0x68, 0x65, 0x63, 0x6b, 0x5f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x18, 0x05, 0x20, 0x03,
	0x28, 0x09, 0x42, 0x94, 0x01, 0xfa, 0x42, 0x90, 0x01, 0x92, 0x01, 0x8c, 0x01, 0x22, 0x89, 0x01,
	0x72, 0x86, 0x01, 0x52, 0x1e, 0x78, 0x2d, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2d, 0x75, 0x70, 0x73,
	0x74, 0x72, 0x65, 0x61, 0x6d, 0x2d, 0x72, 0x71, 0x2d, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74,
	0x2d, 0x6d, 0x73, 0x52, 0x26, 0x78, 0x2d, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2d, 0x75, 0x70, 0x73,
	0x74, 0x72, 0x65, 0x61, 0x6d, 0x2d, 0x72, 0x71, 0x2d, 0x70, 0x65, 0x72, 0x2d, 0x74, 0x72, 0x79,
	0x2d, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x2d, 0x6d, 0x73, 0x52, 0x13, 0x78, 0x2d, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x2d, 0x6d, 0x61, 0x78, 0x2d, 0x72, 0x65, 0x74, 0x72, 0x69, 0x65, 0x73,
	0x52, 0x15, 0x78, 0x2d, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2d, 0x72, 0x65, 0x74, 0x72, 0x79, 0x2d,
	0x67, 0x72, 0x70, 0x63, 0x2d, 0x6f, 0x6e, 0x52, 0x10, 0x78, 0x2d, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2d, 0x72, 0x65, 0x74, 0x72, 0x79, 0x2d, 0x6f, 0x6e, 0x52, 0x12, 0x73, 0x74, 0x72, 0x69, 0x63,
	0x74, 0x43, 0x68, 0x65, 0x63, 0x6b, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x73, 0x12, 0x3d, 0x0a,
	0x1b, 0x72, 0x65, 0x73, 0x70, 0x65, 0x63, 0x74, 0x5f, 0x65, 0x78, 0x70, 0x65, 0x63, 0x74, 0x65,
	0x64, 0x5f, 0x72, 0x71, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x18, 0x06, 0x20, 0x01,
	0x28, 0x08, 0x52, 0x18, 0x72, 0x65, 0x73, 0x70, 0x65, 0x63, 0x74, 0x45, 0x78, 0x70, 0x65, 0x63,
	0x74, 0x65, 0x64, 0x52, 0x71, 0x54, 0x69, 0x6d, 0x65, 0x6f, 0x75, 0x74, 0x12, 0x55, 0x0a, 0x28,
	0x73, 0x75, 0x70, 0x70, 0x72, 0x65, 0x73, 0x73, 0x5f, 0x67, 0x72, 0x70, 0x63, 0x5f, 0x72, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x66, 0x61, 0x69, 0x6c, 0x75, 0x72, 0x65, 0x5f, 0x63, 0x6f,
	0x64, 0x65, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x08, 0x52, 0x23,
	0x73, 0x75, 0x70, 0x70, 0x72, 0x65, 0x73, 0x73, 0x47, 0x72, 0x70, 0x63, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x46, 0x61, 0x69, 0x6c, 0x75, 0x72, 0x65, 0x43, 0x6f, 0x64, 0x65, 0x53, 0x74,
	0x61, 0x74, 0x73, 0x12, 0x7b, 0x0a, 0x15, 0x75, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x5f,
	0x68, 0x74, 0x74, 0x70, 0x5f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x18, 0x08, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x47, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e,
	0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65,
	0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x5f, 0x63, 0x6f, 0x6e, 0x6e, 0x65,
	0x63, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x6d, 0x61, 0x6e, 0x61, 0x67, 0x65, 0x72, 0x2e, 0x76, 0x33,
	0x2e, 0x48, 0x74, 0x74, 0x70, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x52, 0x13, 0x75, 0x70, 0x73,
	0x74, 0x72, 0x65, 0x61, 0x6d, 0x48, 0x74, 0x74, 0x70, 0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73,
	0x1a, 0xd3, 0x01, 0x0a, 0x18, 0x55, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x41, 0x63, 0x63,
	0x65, 0x73, 0x73, 0x4c, 0x6f, 0x67, 0x4f, 0x70, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x4f, 0x0a,
	0x25, 0x66, 0x6c, 0x75, 0x73, 0x68, 0x5f, 0x75, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x5f,
	0x6c, 0x6f, 0x67, 0x5f, 0x6f, 0x6e, 0x5f, 0x75, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x5f,
	0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x20, 0x66, 0x6c,
	0x75, 0x73, 0x68, 0x55, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x4c, 0x6f, 0x67, 0x4f, 0x6e,
	0x55, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x12, 0x66,
	0x0a, 0x1b, 0x75, 0x70, 0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x5f, 0x6c, 0x6f, 0x67, 0x5f, 0x66,
	0x6c, 0x75, 0x73, 0x68, 0x5f, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x42, 0x0c,
	0xfa, 0x42, 0x09, 0xaa, 0x01, 0x06, 0x32, 0x04, 0x10, 0xc0, 0x84, 0x3d, 0x52, 0x18, 0x75, 0x70,
	0x73, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x4c, 0x6f, 0x67, 0x46, 0x6c, 0x75, 0x73, 0x68, 0x49, 0x6e,
	0x74, 0x65, 0x72, 0x76, 0x61, 0x6c, 0x3a, 0x30, 0x9a, 0xc5, 0x88, 0x1e, 0x2b, 0x0a, 0x29, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x66, 0x69, 0x6c, 0x74,
	0x65, 0x72, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e, 0x76,
	0x32, 0x2e, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x42, 0xa7, 0x01, 0x0a, 0x35, 0x69, 0x6f, 0x2e,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74,
	0x65, 0x72, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2e,
	0x76, 0x33, 0x42, 0x0b, 0x52, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50,
	0x01, 0x5a, 0x57, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74,
	0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f,
	0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65,
	0x72, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x2f, 0x76,
	0x33, 0x3b, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x72, 0x76, 0x33, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02,
	0x10, 0x02, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_extensions_filters_http_router_v3_router_proto_rawDescOnce sync.Once
	file_envoy_extensions_filters_http_router_v3_router_proto_rawDescData = file_envoy_extensions_filters_http_router_v3_router_proto_rawDesc
)

func file_envoy_extensions_filters_http_router_v3_router_proto_rawDescGZIP() []byte {
	file_envoy_extensions_filters_http_router_v3_router_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_filters_http_router_v3_router_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_filters_http_router_v3_router_proto_rawDescData)
	})
	return file_envoy_extensions_filters_http_router_v3_router_proto_rawDescData
}

var file_envoy_extensions_filters_http_router_v3_router_proto_msgTypes = make([]protoimpl.MessageInfo, 2)
var file_envoy_extensions_filters_http_router_v3_router_proto_goTypes = []interface{}{
	(*Router)(nil),                          // 0: envoy.extensions.filters.http.router.v3.Router
	(*Router_UpstreamAccessLogOptions)(nil), // 1: envoy.extensions.filters.http.router.v3.Router.UpstreamAccessLogOptions
	(*wrapperspb.BoolValue)(nil),            // 2: google.protobuf.BoolValue
	(*v3.AccessLog)(nil),                    // 3: envoy.config.accesslog.v3.AccessLog
	(*v31.HttpFilter)(nil),                  // 4: envoy.extensions.filters.network.http_connection_manager.v3.HttpFilter
	(*durationpb.Duration)(nil),             // 5: google.protobuf.Duration
}
var file_envoy_extensions_filters_http_router_v3_router_proto_depIdxs = []int32{
	2, // 0: envoy.extensions.filters.http.router.v3.Router.dynamic_stats:type_name -> google.protobuf.BoolValue
	3, // 1: envoy.extensions.filters.http.router.v3.Router.upstream_log:type_name -> envoy.config.accesslog.v3.AccessLog
	1, // 2: envoy.extensions.filters.http.router.v3.Router.upstream_log_options:type_name -> envoy.extensions.filters.http.router.v3.Router.UpstreamAccessLogOptions
	4, // 3: envoy.extensions.filters.http.router.v3.Router.upstream_http_filters:type_name -> envoy.extensions.filters.network.http_connection_manager.v3.HttpFilter
	5, // 4: envoy.extensions.filters.http.router.v3.Router.UpstreamAccessLogOptions.upstream_log_flush_interval:type_name -> google.protobuf.Duration
	5, // [5:5] is the sub-list for method output_type
	5, // [5:5] is the sub-list for method input_type
	5, // [5:5] is the sub-list for extension type_name
	5, // [5:5] is the sub-list for extension extendee
	0, // [0:5] is the sub-list for field type_name
}

func init() { file_envoy_extensions_filters_http_router_v3_router_proto_init() }
func file_envoy_extensions_filters_http_router_v3_router_proto_init() {
	if File_envoy_extensions_filters_http_router_v3_router_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_filters_http_router_v3_router_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Router); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_envoy_extensions_filters_http_router_v3_router_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Router_UpstreamAccessLogOptions); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_envoy_extensions_filters_http_router_v3_router_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   2,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_filters_http_router_v3_router_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_filters_http_router_v3_router_proto_depIdxs,
		MessageInfos:      file_envoy_extensions_filters_http_router_v3_router_proto_msgTypes,
	}.Build()
	File_envoy_extensions_filters_http_router_v3_router_proto = out.File
	file_envoy_extensions_filters_http_router_v3_router_proto_rawDesc = nil
	file_envoy_extensions_filters_http_router_v3_router_proto_goTypes = nil
	file_envoy_extensions_filters_http_router_v3_router_proto_depIdxs = nil
}
