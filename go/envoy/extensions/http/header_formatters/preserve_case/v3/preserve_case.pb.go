// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.19.4
// source: envoy/extensions/http/header_formatters/preserve_case/v3/preserve_case.proto

package preserve_casev3

import (
	_ "github.com/cncf/xds/go/udpa/annotations"
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
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

// Configuration for the preserve case header formatter.
// See the :ref:`header casing <config_http_conn_man_header_casing>` configuration guide for more
// information.
type PreserveCaseFormatterConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Allows forwarding reason phrase text.
	// This is off by default, and a standard reason phrase is used for a corresponding HTTP response code.
	ForwardReasonPhrase bool `protobuf:"varint,1,opt,name=forward_reason_phrase,json=forwardReasonPhrase,proto3" json:"forward_reason_phrase,omitempty"`
}

func (x *PreserveCaseFormatterConfig) Reset() {
	*x = PreserveCaseFormatterConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PreserveCaseFormatterConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PreserveCaseFormatterConfig) ProtoMessage() {}

func (x *PreserveCaseFormatterConfig) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PreserveCaseFormatterConfig.ProtoReflect.Descriptor instead.
func (*PreserveCaseFormatterConfig) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescGZIP(), []int{0}
}

func (x *PreserveCaseFormatterConfig) GetForwardReasonPhrase() bool {
	if x != nil {
		return x.ForwardReasonPhrase
	}
	return false
}

var File_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto protoreflect.FileDescriptor

var file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDesc = []byte{
	0x0a, 0x4c, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x66,
	0x6f, 0x72, 0x6d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x73, 0x2f, 0x70, 0x72, 0x65, 0x73, 0x65, 0x72,
	0x76, 0x65, 0x5f, 0x63, 0x61, 0x73, 0x65, 0x2f, 0x76, 0x33, 0x2f, 0x70, 0x72, 0x65, 0x73, 0x65,
	0x72, 0x76, 0x65, 0x5f, 0x63, 0x61, 0x73, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x38,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73,
	0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x66, 0x6f, 0x72,
	0x6d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65,
	0x5f, 0x63, 0x61, 0x73, 0x65, 0x2e, 0x76, 0x33, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61,
	0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75,
	0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x51, 0x0a, 0x1b, 0x50, 0x72, 0x65, 0x73, 0x65,
	0x72, 0x76, 0x65, 0x43, 0x61, 0x73, 0x65, 0x46, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x74, 0x65, 0x72,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x32, 0x0a, 0x15, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72,
	0x64, 0x5f, 0x72, 0x65, 0x61, 0x73, 0x6f, 0x6e, 0x5f, 0x70, 0x68, 0x72, 0x61, 0x73, 0x65, 0x18,
	0x01, 0x20, 0x01, 0x28, 0x08, 0x52, 0x13, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72, 0x64, 0x52, 0x65,
	0x61, 0x73, 0x6f, 0x6e, 0x50, 0x68, 0x72, 0x61, 0x73, 0x65, 0x42, 0xd6, 0x01, 0x0a, 0x46, 0x69,
	0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76,
	0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x68, 0x74,
	0x74, 0x70, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74,
	0x74, 0x65, 0x72, 0x73, 0x2e, 0x70, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x5f, 0x63, 0x61,
	0x73, 0x65, 0x2e, 0x76, 0x33, 0x42, 0x11, 0x50, 0x72, 0x65, 0x73, 0x65, 0x72, 0x76, 0x65, 0x43,
	0x61, 0x73, 0x65, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0x5a, 0x6f, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78,
	0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61,
	0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69,
	0x6f, 0x6e, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f,
	0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x74, 0x65, 0x72, 0x73, 0x2f, 0x70, 0x72, 0x65, 0x73, 0x65,
	0x72, 0x76, 0x65, 0x5f, 0x63, 0x61, 0x73, 0x65, 0x2f, 0x76, 0x33, 0x3b, 0x70, 0x72, 0x65, 0x73,
	0x65, 0x72, 0x76, 0x65, 0x5f, 0x63, 0x61, 0x73, 0x65, 0x76, 0x33, 0xba, 0x80, 0xc8, 0xd1, 0x06,
	0x02, 0x10, 0x02, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescOnce sync.Once
	file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescData = file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDesc
)

func file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescGZIP() []byte {
	file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescData)
	})
	return file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDescData
}

var file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_goTypes = []interface{}{
	(*PreserveCaseFormatterConfig)(nil), // 0: envoy.extensions.http.header_formatters.preserve_case.v3.PreserveCaseFormatterConfig
}
var file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_init() }
func file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_init() {
	if File_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PreserveCaseFormatterConfig); i {
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
			RawDescriptor: file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_depIdxs,
		MessageInfos:      file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_msgTypes,
	}.Build()
	File_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto = out.File
	file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_rawDesc = nil
	file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_goTypes = nil
	file_envoy_extensions_http_header_formatters_preserve_case_v3_preserve_case_proto_depIdxs = nil
}
