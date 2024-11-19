// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v5.26.1
// source: envoy/extensions/filters/network/generic_proxy/codecs/http1/v3/http1.proto

package http1v3

import (
	_ "github.com/cncf/xds/go/udpa/annotations"
	_ "github.com/cncf/xds/go/xds/annotations/v3"
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
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

// Configuration for HTTP codec. This HTTP1 codec is used to parse and serialize HTTP1 messages
// for the generic proxy filter.
// Any decoding error will result in the generic proxy closing the connection.
//
// .. note::
//
//	This codec only supports HTTP1.1 messages and does not support HTTP1.0 messages. And it limits
//	part of the HTTP1.1 features, such as upgrade, connect, etc.
//	This codec is mainly designed for the features evaluation of the generic proxy filter. Please
//	be cautious when using it in production.
type Http1CodecConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// If true, the codec will parse and serialize HTTP1 messages in a single frame per message.
	//
	// A frame is a minimal unit of data that can be processed by the generic proxy. If false, the
	// codec will parse and serialize HTTP1 messages in a streaming way. In this case, the codec
	// will output multiple frames for a single HTTP1 message to the generic proxy.
	// If true, the codec will buffer the entire HTTP1 message body before sending it to the generic
	// proxy. This may have better performance in small message scenarios and is more friendly to
	// handle the HTTP1 message body. This also may result in higher memory usage and latency if
	// the message body is large.
	//
	// Default is true.
	SingleFrameMode *wrapperspb.BoolValue `protobuf:"bytes,1,opt,name=single_frame_mode,json=singleFrameMode,proto3" json:"single_frame_mode,omitempty"`
	// The maximum size of the HTTP1 message body in bytes. If not set, 8*1024*1024 (8MB) is used.
	// This only makes sense when single_frame_mode is true.
	// If the HTTP1 message body size exceeds this value, this will result in a decoding error
	// and the generic proxy will close the connection.
	MaxBufferSize *wrapperspb.UInt32Value `protobuf:"bytes,2,opt,name=max_buffer_size,json=maxBufferSize,proto3" json:"max_buffer_size,omitempty"`
}

func (x *Http1CodecConfig) Reset() {
	*x = Http1CodecConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Http1CodecConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Http1CodecConfig) ProtoMessage() {}

func (x *Http1CodecConfig) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Http1CodecConfig.ProtoReflect.Descriptor instead.
func (*Http1CodecConfig) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_rawDescGZIP(), []int{0}
}

func (x *Http1CodecConfig) GetSingleFrameMode() *wrapperspb.BoolValue {
	if x != nil {
		return x.SingleFrameMode
	}
	return nil
}

func (x *Http1CodecConfig) GetMaxBufferSize() *wrapperspb.UInt32Value {
	if x != nil {
		return x.MaxBufferSize
	}
	return nil
}

var File_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto protoreflect.FileDescriptor

var file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_rawDesc = []byte{
	0x0a, 0x4a, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2f, 0x6e, 0x65, 0x74, 0x77, 0x6f,
	0x72, 0x6b, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79,
	0x2f, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x31, 0x2f, 0x76, 0x33,
	0x2f, 0x68, 0x74, 0x74, 0x70, 0x31, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x3e, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66,
	0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2e, 0x67,
	0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x63, 0x6f, 0x64,
	0x65, 0x63, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x31, 0x2e, 0x76, 0x33, 0x1a, 0x1e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77, 0x72,
	0x61, 0x70, 0x70, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x78, 0x64,
	0x73, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x33,
	0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75,
	0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f,
	0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xa0, 0x01, 0x0a,
	0x10, 0x48, 0x74, 0x74, 0x70, 0x31, 0x43, 0x6f, 0x64, 0x65, 0x63, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x12, 0x46, 0x0a, 0x11, 0x73, 0x69, 0x6e, 0x67, 0x6c, 0x65, 0x5f, 0x66, 0x72, 0x61, 0x6d,
	0x65, 0x5f, 0x6d, 0x6f, 0x64, 0x65, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67,
	0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x42,
	0x6f, 0x6f, 0x6c, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x0f, 0x73, 0x69, 0x6e, 0x67, 0x6c, 0x65,
	0x46, 0x72, 0x61, 0x6d, 0x65, 0x4d, 0x6f, 0x64, 0x65, 0x12, 0x44, 0x0a, 0x0f, 0x6d, 0x61, 0x78,
	0x5f, 0x62, 0x75, 0x66, 0x66, 0x65, 0x72, 0x5f, 0x73, 0x69, 0x7a, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x0b, 0x32, 0x1c, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x55, 0x49, 0x6e, 0x74, 0x33, 0x32, 0x56, 0x61, 0x6c, 0x75, 0x65,
	0x52, 0x0d, 0x6d, 0x61, 0x78, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72, 0x53, 0x69, 0x7a, 0x65, 0x42,
	0xdb, 0x01, 0x0a, 0x4c, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78,
	0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x6e, 0x65, 0x74, 0x77, 0x6f,
	0x72, 0x6b, 0x2e, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x5f, 0x70, 0x72, 0x6f, 0x78, 0x79,
	0x2e, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x31, 0x2e, 0x76, 0x33,
	0x42, 0x0a, 0x48, 0x74, 0x74, 0x70, 0x31, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x6d,
	0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c,
	0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74,
	0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2f,
	0x6e, 0x65, 0x74, 0x77, 0x6f, 0x72, 0x6b, 0x2f, 0x67, 0x65, 0x6e, 0x65, 0x72, 0x69, 0x63, 0x5f,
	0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x63, 0x6f, 0x64, 0x65, 0x63, 0x73, 0x2f, 0x68, 0x74, 0x74,
	0x70, 0x31, 0x2f, 0x76, 0x33, 0x3b, 0x68, 0x74, 0x74, 0x70, 0x31, 0x76, 0x33, 0xba, 0x80, 0xc8,
	0xd1, 0x06, 0x02, 0x10, 0x02, 0xd2, 0xc6, 0xa4, 0xe1, 0x06, 0x02, 0x08, 0x01, 0x62, 0x06, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_rawDescOnce sync.Once
	file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_rawDescData = file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_rawDesc
)

func file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_rawDescGZIP() []byte {
	file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_rawDescData)
	})
	return file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_rawDescData
}

var file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_goTypes = []interface{}{
	(*Http1CodecConfig)(nil),       // 0: envoy.extensions.filters.network.generic_proxy.codecs.http1.v3.Http1CodecConfig
	(*wrapperspb.BoolValue)(nil),   // 1: google.protobuf.BoolValue
	(*wrapperspb.UInt32Value)(nil), // 2: google.protobuf.UInt32Value
}
var file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_depIdxs = []int32{
	1, // 0: envoy.extensions.filters.network.generic_proxy.codecs.http1.v3.Http1CodecConfig.single_frame_mode:type_name -> google.protobuf.BoolValue
	2, // 1: envoy.extensions.filters.network.generic_proxy.codecs.http1.v3.Http1CodecConfig.max_buffer_size:type_name -> google.protobuf.UInt32Value
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_init() }
func file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_init() {
	if File_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Http1CodecConfig); i {
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
			RawDescriptor: file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_depIdxs,
		MessageInfos:      file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_msgTypes,
	}.Build()
	File_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto = out.File
	file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_rawDesc = nil
	file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_goTypes = nil
	file_envoy_extensions_filters_network_generic_proxy_codecs_http1_v3_http1_proto_depIdxs = nil
}
