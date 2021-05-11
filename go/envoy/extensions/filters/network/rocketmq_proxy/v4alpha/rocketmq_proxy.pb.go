// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.14.0
// source: envoy/extensions/filters/network/rocketmq_proxy/v4alpha/rocketmq_proxy.proto

package envoy_extensions_filters_network_rocketmq_proxy_v4alpha

import (
	_ "github.com/cncf/udpa/go/udpa/annotations"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	_ "google.golang.org/protobuf/types/known/anypb"
	durationpb "google.golang.org/protobuf/types/known/durationpb"
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

type RocketmqProxy struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The human readable prefix to use when emitting statistics.
	StatPrefix string `protobuf:"bytes,1,opt,name=stat_prefix,json=statPrefix,proto3" json:"stat_prefix,omitempty"`
	// The route table for the connection manager is specified in this property.
	RouteConfig *RouteConfiguration `protobuf:"bytes,2,opt,name=route_config,json=routeConfig,proto3" json:"route_config,omitempty"`
	// The largest duration transient object expected to live, more than 10s is recommended.
	TransientObjectLifeSpan *durationpb.Duration `protobuf:"bytes,3,opt,name=transient_object_life_span,json=transientObjectLifeSpan,proto3" json:"transient_object_life_span,omitempty"`
	// If develop_mode is enabled, this proxy plugin may work without dedicated traffic intercepting
	// facility without considering backward compatibility of exiting RocketMQ client SDK.
	DevelopMode bool `protobuf:"varint,4,opt,name=develop_mode,json=developMode,proto3" json:"develop_mode,omitempty"`
}

func (x *RocketmqProxy) Reset() {
	*x = RocketmqProxy{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *RocketmqProxy) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*RocketmqProxy) ProtoMessage() {}

func (x *RocketmqProxy) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use RocketmqProxy.ProtoReflect.Descriptor instead.
func (*RocketmqProxy) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_rawDescGZIP(), []int{0}
}

func (x *RocketmqProxy) GetStatPrefix() string {
	if x != nil {
		return x.StatPrefix
	}
	return ""
}

func (x *RocketmqProxy) GetRouteConfig() *RouteConfiguration {
	if x != nil {
		return x.RouteConfig
	}
	return nil
}

func (x *RocketmqProxy) GetTransientObjectLifeSpan() *durationpb.Duration {
	if x != nil {
		return x.TransientObjectLifeSpan
	}
	return nil
}

func (x *RocketmqProxy) GetDevelopMode() bool {
	if x != nil {
		return x.DevelopMode
	}
	return false
}

var File_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto protoreflect.FileDescriptor

var file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_rawDesc = []byte{
	0x0a, 0x4c, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f,
	0x72, 0x6b, 0x2f, 0x72, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x6d, 0x71, 0x5f, 0x70, 0x72, 0x6f, 0x78,
	0x79, 0x2f, 0x76, 0x34, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x72, 0x6f, 0x63, 0x6b, 0x65, 0x74,
	0x6d, 0x71, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x37,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73,
	0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b,
	0x2e, 0x72, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x6d, 0x71, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e,
	0x76, 0x34, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x1a, 0x43, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65,
	0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72,
	0x73, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x72, 0x6f, 0x63, 0x6b, 0x65, 0x74,
	0x6d, 0x71, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x76, 0x34, 0x61, 0x6c, 0x70, 0x68, 0x61,
	0x2f, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x19, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x61, 0x6e,
	0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e,
	0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e,
	0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64,
	0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x22, 0xed, 0x02, 0x0a, 0x0d, 0x52, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x6d, 0x71, 0x50,
	0x72, 0x6f, 0x78, 0x79, 0x12, 0x28, 0x0a, 0x0b, 0x73, 0x74, 0x61, 0x74, 0x5f, 0x70, 0x72, 0x65,
	0x66, 0x69, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02,
	0x10, 0x01, 0x52, 0x0a, 0x73, 0x74, 0x61, 0x74, 0x50, 0x72, 0x65, 0x66, 0x69, 0x78, 0x12, 0x6e,
	0x0a, 0x0c, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x5f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0b, 0x32, 0x4b, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74,
	0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e,
	0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x72, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x6d, 0x71,
	0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x76, 0x34, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x52,
	0x6f, 0x75, 0x74, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x52, 0x0b, 0x72, 0x6f, 0x75, 0x74, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x56,
	0x0a, 0x1a, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x6f, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x5f, 0x6c, 0x69, 0x66, 0x65, 0x5f, 0x73, 0x70, 0x61, 0x6e, 0x18, 0x03, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x17, 0x74,
	0x72, 0x61, 0x6e, 0x73, 0x69, 0x65, 0x6e, 0x74, 0x4f, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x4c, 0x69,
	0x66, 0x65, 0x53, 0x70, 0x61, 0x6e, 0x12, 0x21, 0x0a, 0x0c, 0x64, 0x65, 0x76, 0x65, 0x6c, 0x6f,
	0x70, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08, 0x52, 0x0b, 0x64, 0x65,
	0x76, 0x65, 0x6c, 0x6f, 0x70, 0x4d, 0x6f, 0x64, 0x65, 0x3a, 0x47, 0x9a, 0xc5, 0x88, 0x1e, 0x42,
	0x0a, 0x40, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f,
	0x72, 0x6b, 0x2e, 0x72, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x6d, 0x71, 0x5f, 0x70, 0x72, 0x6f, 0x78,
	0x79, 0x2e, 0x76, 0x33, 0x2e, 0x52, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x6d, 0x71, 0x50, 0x72, 0x6f,
	0x78, 0x79, 0x42, 0x65, 0x0a, 0x45, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73,
	0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65, 0x74,
	0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x72, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x6d, 0x71, 0x5f, 0x70, 0x72,
	0x6f, 0x78, 0x79, 0x2e, 0x76, 0x34, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x42, 0x12, 0x52, 0x6f, 0x63,
	0x6b, 0x65, 0x74, 0x6d, 0x71, 0x50, 0x72, 0x6f, 0x78, 0x79, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50,
	0x01, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x03, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_rawDescOnce sync.Once
	file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_rawDescData = file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_rawDesc
)

func file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_rawDescGZIP() []byte {
	file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_rawDescData)
	})
	return file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_rawDescData
}

var file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_goTypes = []interface{}{
	(*RocketmqProxy)(nil),       // 0: envoy.extensions.filters.network.rocketmq_proxy.v4alpha.RocketmqProxy
	(*RouteConfiguration)(nil),  // 1: envoy.extensions.filters.network.rocketmq_proxy.v4alpha.RouteConfiguration
	(*durationpb.Duration)(nil), // 2: google.protobuf.Duration
}
var file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_depIdxs = []int32{
	1, // 0: envoy.extensions.filters.network.rocketmq_proxy.v4alpha.RocketmqProxy.route_config:type_name -> envoy.extensions.filters.network.rocketmq_proxy.v4alpha.RouteConfiguration
	2, // 1: envoy.extensions.filters.network.rocketmq_proxy.v4alpha.RocketmqProxy.transient_object_life_span:type_name -> google.protobuf.Duration
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_init() }
func file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_init() {
	if File_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto != nil {
		return
	}
	file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_route_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*RocketmqProxy); i {
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
			RawDescriptor: file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_depIdxs,
		MessageInfos:      file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_msgTypes,
	}.Build()
	File_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto = out.File
	file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_rawDesc = nil
	file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_goTypes = nil
	file_envoy_extensions_filters_network_rocketmq_proxy_v4alpha_rocketmq_proxy_proto_depIdxs = nil
}
