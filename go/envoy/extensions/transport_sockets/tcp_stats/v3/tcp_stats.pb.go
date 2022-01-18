// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.19.1
// source: envoy/extensions/transport_sockets/tcp_stats/v3/tcp_stats.proto

package tcp_statsv3

import (
	v3 "github.com/cilium/proxy/go/envoy/config/core/v3"
	_ "github.com/cncf/xds/go/udpa/annotations"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
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

// Configuration for the TCP Stats transport socket wrapper, which wraps another transport socket for
// all communication, but emits stats about the underlying TCP connection.
//
// The stats are documented :ref:`here <config_listener_stats_tcp>` for listeners and
// :ref:`here <config_cluster_manager_cluster_stats_tcp>` for clusters.
//
// This transport socket is currently only supported on Linux.
type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The underlying transport socket being wrapped.
	TransportSocket *v3.TransportSocket `protobuf:"bytes,1,opt,name=transport_socket,json=transportSocket,proto3" json:"transport_socket,omitempty"`
	// Period to update stats while the connection is open. If unset, updates only happen when the
	// connection is closed. Stats are always updated one final time when the connection is closed.
	UpdatePeriod *durationpb.Duration `protobuf:"bytes,2,opt,name=update_period,json=updatePeriod,proto3" json:"update_period,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config.ProtoReflect.Descriptor instead.
func (*Config) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_rawDescGZIP(), []int{0}
}

func (x *Config) GetTransportSocket() *v3.TransportSocket {
	if x != nil {
		return x.TransportSocket
	}
	return nil
}

func (x *Config) GetUpdatePeriod() *durationpb.Duration {
	if x != nil {
		return x.UpdatePeriod
	}
	return nil
}

var File_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto protoreflect.FileDescriptor

var file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_rawDesc = []byte{
	0x0a, 0x3f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x73, 0x6f, 0x63,
	0x6b, 0x65, 0x74, 0x73, 0x2f, 0x74, 0x63, 0x70, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x73, 0x2f, 0x76,
	0x33, 0x2f, 0x74, 0x63, 0x70, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x12, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69,
	0x6f, 0x6e, 0x73, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x73, 0x6f,
	0x63, 0x6b, 0x65, 0x74, 0x73, 0x2e, 0x74, 0x63, 0x70, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x73, 0x2e,
	0x76, 0x33, 0x1a, 0x1f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x2f, 0x63, 0x6f, 0x72, 0x65, 0x2f, 0x76, 0x33, 0x2f, 0x62, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x64, 0x75, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c,
	0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0xb2, 0x01, 0x0a, 0x06,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x5a, 0x0a, 0x10, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70,
	0x6f, 0x72, 0x74, 0x5f, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x25, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e,
	0x63, 0x6f, 0x72, 0x65, 0x2e, 0x76, 0x33, 0x2e, 0x54, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72,
	0x74, 0x53, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x8a, 0x01, 0x02, 0x10,
	0x01, 0x52, 0x0f, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x53, 0x6f, 0x63, 0x6b,
	0x65, 0x74, 0x12, 0x4c, 0x0a, 0x0d, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x5f, 0x70, 0x65, 0x72,
	0x69, 0x6f, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x19, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x44, 0x75, 0x72, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x42, 0x0c, 0xfa, 0x42, 0x09, 0xaa, 0x01, 0x06, 0x32, 0x04, 0x10, 0xc0,
	0x84, 0x3d, 0x52, 0x0c, 0x75, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x65, 0x72, 0x69, 0x6f, 0x64,
	0x42, 0xbc, 0x01, 0x0a, 0x3d, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f,
	0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69,
	0x6f, 0x6e, 0x73, 0x2e, 0x74, 0x72, 0x61, 0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x73, 0x6f,
	0x63, 0x6b, 0x65, 0x74, 0x73, 0x2e, 0x74, 0x63, 0x70, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x73, 0x2e,
	0x76, 0x33, 0x42, 0x0d, 0x54, 0x63, 0x70, 0x53, 0x74, 0x61, 0x74, 0x73, 0x50, 0x72, 0x6f, 0x74,
	0x6f, 0x50, 0x01, 0x5a, 0x62, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63, 0x6f,
	0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x74, 0x72, 0x61,
	0x6e, 0x73, 0x70, 0x6f, 0x72, 0x74, 0x5f, 0x73, 0x6f, 0x63, 0x6b, 0x65, 0x74, 0x73, 0x2f, 0x74,
	0x63, 0x70, 0x5f, 0x73, 0x74, 0x61, 0x74, 0x73, 0x2f, 0x76, 0x33, 0x3b, 0x74, 0x63, 0x70, 0x5f,
	0x73, 0x74, 0x61, 0x74, 0x73, 0x76, 0x33, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x02, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_rawDescOnce sync.Once
	file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_rawDescData = file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_rawDesc
)

func file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_rawDescGZIP() []byte {
	file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_rawDescData)
	})
	return file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_rawDescData
}

var file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_goTypes = []interface{}{
	(*Config)(nil),              // 0: envoy.extensions.transport_sockets.tcp_stats.v3.Config
	(*v3.TransportSocket)(nil),  // 1: envoy.config.core.v3.TransportSocket
	(*durationpb.Duration)(nil), // 2: google.protobuf.Duration
}
var file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_depIdxs = []int32{
	1, // 0: envoy.extensions.transport_sockets.tcp_stats.v3.Config.transport_socket:type_name -> envoy.config.core.v3.TransportSocket
	2, // 1: envoy.extensions.transport_sockets.tcp_stats.v3.Config.update_period:type_name -> google.protobuf.Duration
	2, // [2:2] is the sub-list for method output_type
	2, // [2:2] is the sub-list for method input_type
	2, // [2:2] is the sub-list for extension type_name
	2, // [2:2] is the sub-list for extension extendee
	0, // [0:2] is the sub-list for field type_name
}

func init() { file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_init() }
func file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_init() {
	if File_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Config); i {
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
			RawDescriptor: file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_depIdxs,
		MessageInfos:      file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_msgTypes,
	}.Build()
	File_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto = out.File
	file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_rawDesc = nil
	file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_goTypes = nil
	file_envoy_extensions_transport_sockets_tcp_stats_v3_tcp_stats_proto_depIdxs = nil
}
