// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/config/filter/http/router/v2/router.proto

package v2

import (
	fmt "fmt"
	v2 "github.com/cilium/cilium/pkg/envoy/envoy/config/filter/accesslog/v2"
	proto "github.com/golang/protobuf/proto"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Router struct {
	// Whether the router generates dynamic cluster statistics. Defaults to
	// true. Can be disabled in high performance scenarios.
	DynamicStats *wrappers.BoolValue `protobuf:"bytes,1,opt,name=dynamic_stats,json=dynamicStats,proto3" json:"dynamic_stats,omitempty"`
	// Whether to start a child span for egress routed calls. This can be
	// useful in scenarios where other filters (auth, ratelimit, etc.) make
	// outbound calls and have child spans rooted at the same ingress
	// parent. Defaults to false.
	StartChildSpan bool `protobuf:"varint,2,opt,name=start_child_span,json=startChildSpan,proto3" json:"start_child_span,omitempty"`
	// Configuration for HTTP upstream logs emitted by the router. Upstream logs
	// are configured in the same way as access logs, but each log entry represents
	// an upstream request. Presuming retries are configured, multiple upstream
	// requests may be made for each downstream (inbound) request.
	UpstreamLog []*v2.AccessLog `protobuf:"bytes,3,rep,name=upstream_log,json=upstreamLog,proto3" json:"upstream_log,omitempty"`
	// Do not add any additional *x-envoy-* headers to requests or responses. This
	// only affects the :ref:`router filter generated *x-envoy-* headers
	// <config_http_filters_router_headers_set>`, other Envoy filters and the HTTP
	// connection manager may continue to set *x-envoy-* headers.
	SuppressEnvoyHeaders bool     `protobuf:"varint,4,opt,name=suppress_envoy_headers,json=suppressEnvoyHeaders,proto3" json:"suppress_envoy_headers,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Router) Reset()         { *m = Router{} }
func (m *Router) String() string { return proto.CompactTextString(m) }
func (*Router) ProtoMessage()    {}
func (*Router) Descriptor() ([]byte, []int) {
	return fileDescriptor_cc1f525510d06eb8, []int{0}
}

func (m *Router) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Router.Unmarshal(m, b)
}
func (m *Router) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Router.Marshal(b, m, deterministic)
}
func (m *Router) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Router.Merge(m, src)
}
func (m *Router) XXX_Size() int {
	return xxx_messageInfo_Router.Size(m)
}
func (m *Router) XXX_DiscardUnknown() {
	xxx_messageInfo_Router.DiscardUnknown(m)
}

var xxx_messageInfo_Router proto.InternalMessageInfo

func (m *Router) GetDynamicStats() *wrappers.BoolValue {
	if m != nil {
		return m.DynamicStats
	}
	return nil
}

func (m *Router) GetStartChildSpan() bool {
	if m != nil {
		return m.StartChildSpan
	}
	return false
}

func (m *Router) GetUpstreamLog() []*v2.AccessLog {
	if m != nil {
		return m.UpstreamLog
	}
	return nil
}

func (m *Router) GetSuppressEnvoyHeaders() bool {
	if m != nil {
		return m.SuppressEnvoyHeaders
	}
	return false
}

func init() {
	proto.RegisterType((*Router)(nil), "envoy.config.filter.http.router.v2.Router")
}

func init() {
	proto.RegisterFile("envoy/config/filter/http/router/v2/router.proto", fileDescriptor_cc1f525510d06eb8)
}

var fileDescriptor_cc1f525510d06eb8 = []byte{
	// 294 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x6c, 0x90, 0xc1, 0x4b, 0xc3, 0x30,
	0x14, 0x87, 0xe9, 0x36, 0x86, 0x74, 0x53, 0xa4, 0x88, 0x94, 0x1d, 0x64, 0xec, 0x54, 0x10, 0x12,
	0x89, 0xde, 0xc5, 0x89, 0xe0, 0x61, 0x78, 0xe8, 0xc0, 0x83, 0x97, 0x90, 0x75, 0x59, 0x56, 0xc8,
	0xfa, 0x42, 0x5e, 0x5a, 0xd9, 0x9f, 0xee, 0x4d, 0x92, 0xac, 0x7a, 0xd9, 0xed, 0xbd, 0xf7, 0x7b,
	0xdf, 0x17, 0x5e, 0x52, 0x2a, 0x9b, 0x0e, 0x8e, 0xb4, 0x82, 0x66, 0x57, 0x2b, 0xba, 0xab, 0xb5,
	0x93, 0x96, 0xee, 0x9d, 0x33, 0xd4, 0x42, 0xeb, 0xeb, 0x8e, 0x9d, 0x2a, 0x62, 0x2c, 0x38, 0xc8,
	0x16, 0x01, 0x20, 0x11, 0x20, 0x11, 0x20, 0x1e, 0x20, 0xa7, 0xb5, 0x8e, 0xcd, 0x1e, 0xce, 0x49,
	0x45, 0x55, 0x49, 0x44, 0x0d, 0xca, 0x2b, 0xff, 0x9a, 0x68, 0x9d, 0xdd, 0x29, 0x00, 0xa5, 0x25,
	0x0d, 0xdd, 0xa6, 0xdd, 0xd1, 0x6f, 0x2b, 0x8c, 0x91, 0x16, 0x63, 0xbe, 0xf8, 0x49, 0xd2, 0x71,
	0x19, 0xfc, 0xd9, 0x73, 0x7a, 0xb9, 0x3d, 0x36, 0xe2, 0x50, 0x57, 0x1c, 0x9d, 0x70, 0x98, 0x27,
	0xf3, 0xa4, 0x98, 0xb0, 0x19, 0x89, 0x0a, 0xd2, 0x2b, 0xc8, 0x12, 0x40, 0x7f, 0x0a, 0xdd, 0xca,
	0x72, 0x7a, 0x02, 0xd6, 0x7e, 0x3f, 0x2b, 0xd2, 0x6b, 0x74, 0xc2, 0x3a, 0x5e, 0xed, 0x6b, 0xbd,
	0xe5, 0x68, 0x44, 0x93, 0x0f, 0xe6, 0x49, 0x71, 0x51, 0x5e, 0x85, 0xf9, 0xab, 0x1f, 0xaf, 0x8d,
	0x68, 0xb2, 0x8f, 0x74, 0xda, 0x1a, 0x74, 0x56, 0x8a, 0x03, 0xd7, 0xa0, 0xf2, 0xe1, 0x7c, 0x58,
	0x4c, 0xd8, 0x3d, 0x39, 0xf7, 0x05, 0xff, 0x17, 0x75, 0x8c, 0xbc, 0x84, 0x66, 0x05, 0xaa, 0x9c,
	0xf4, 0x82, 0x15, 0xa8, 0xec, 0x29, 0xbd, 0xc5, 0xd6, 0x18, 0x2b, 0x11, 0x79, 0x70, 0xf0, 0xbd,
	0x14, 0x5b, 0x69, 0x31, 0x1f, 0x85, 0xf7, 0x6f, 0xfa, 0xf4, 0xcd, 0x87, 0xef, 0x31, 0x5b, 0x8e,
	0xbe, 0x06, 0x1d, 0xdb, 0x8c, 0xc3, 0x5d, 0x8f, 0xbf, 0x01, 0x00, 0x00, 0xff, 0xff, 0x8f, 0xf0,
	0x1e, 0x7c, 0xb1, 0x01, 0x00, 0x00,
}
