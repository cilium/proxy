// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.19.4
// source: envoy/extensions/matching/input_matchers/consistent_hashing/v3/consistent_hashing.proto

package consistent_hashingv3

import (
	_ "github.com/cncf/xds/go/udpa/annotations"
	_ "github.com/envoyproxy/protoc-gen-validate/validate"
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

// The consistent hashing matchers computes a consistent hash from the input and matches if the resulting hash
// is within the configured threshold.
// More specifically, this matcher evaluates to true if hash(input, seed) % modulo >= threshold.
// Note that the consistency of the match result relies on the internal hash function (xxhash) remaining
// unchanged. While this is unlikely to happen intentionally, this could cause inconsistent match results
// between deployments.
type ConsistentHashing struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The threshold the resulting hash must be over in order for this matcher to evaluate to true.
	// This value must be below the configured modulo value.
	// Setting this to 0 is equivalent to this matcher always matching.
	Threshold uint32 `protobuf:"varint,1,opt,name=threshold,proto3" json:"threshold,omitempty"`
	// The value to use for the modulus in the calculation. This effectively  bounds the hash output,
	// specifying the range of possible values.
	// This value must be above the configured threshold.
	Modulo uint32 `protobuf:"varint,2,opt,name=modulo,proto3" json:"modulo,omitempty"`
	// Optional seed passed through the hash function. This allows using additional information when computing
	// the hash value: by changing the seed value, a different partition of matching and non-matching inputs will
	// be created that remains consistent for that seed value.
	Seed uint64 `protobuf:"varint,3,opt,name=seed,proto3" json:"seed,omitempty"`
}

func (x *ConsistentHashing) Reset() {
	*x = ConsistentHashing{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConsistentHashing) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConsistentHashing) ProtoMessage() {}

func (x *ConsistentHashing) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConsistentHashing.ProtoReflect.Descriptor instead.
func (*ConsistentHashing) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_rawDescGZIP(), []int{0}
}

func (x *ConsistentHashing) GetThreshold() uint32 {
	if x != nil {
		return x.Threshold
	}
	return 0
}

func (x *ConsistentHashing) GetModulo() uint32 {
	if x != nil {
		return x.Modulo
	}
	return 0
}

func (x *ConsistentHashing) GetSeed() uint64 {
	if x != nil {
		return x.Seed
	}
	return 0
}

var File_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto protoreflect.FileDescriptor

var file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_rawDesc = []byte{
	0x0a, 0x57, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x2f, 0x69, 0x6e, 0x70, 0x75,
	0x74, 0x5f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x73, 0x69,
	0x73, 0x74, 0x65, 0x6e, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x2f, 0x76, 0x33,
	0x2f, 0x63, 0x6f, 0x6e, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68,
	0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x3e, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x6d, 0x61, 0x74, 0x63,
	0x68, 0x69, 0x6e, 0x67, 0x2e, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x5f, 0x6d, 0x61, 0x74, 0x63, 0x68,
	0x65, 0x72, 0x73, 0x2e, 0x63, 0x6f, 0x6e, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x5f, 0x68,
	0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x2e, 0x76, 0x33, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f,
	0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74,
	0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61,
	0x74, 0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x22, 0x66, 0x0a, 0x11, 0x43, 0x6f, 0x6e, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x48,
	0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x12, 0x1c, 0x0a, 0x09, 0x74, 0x68, 0x72, 0x65, 0x73, 0x68,
	0x6f, 0x6c, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0d, 0x52, 0x09, 0x74, 0x68, 0x72, 0x65, 0x73,
	0x68, 0x6f, 0x6c, 0x64, 0x12, 0x1f, 0x0a, 0x06, 0x6d, 0x6f, 0x64, 0x75, 0x6c, 0x6f, 0x18, 0x02,
	0x20, 0x01, 0x28, 0x0d, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x2a, 0x02, 0x20, 0x00, 0x52, 0x06, 0x6d,
	0x6f, 0x64, 0x75, 0x6c, 0x6f, 0x12, 0x12, 0x0a, 0x04, 0x73, 0x65, 0x65, 0x64, 0x18, 0x03, 0x20,
	0x01, 0x28, 0x04, 0x52, 0x04, 0x73, 0x65, 0x65, 0x64, 0x42, 0xec, 0x01, 0x0a, 0x4c, 0x69, 0x6f,
	0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x6d, 0x61, 0x74,
	0x63, 0x68, 0x69, 0x6e, 0x67, 0x2e, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x5f, 0x6d, 0x61, 0x74, 0x63,
	0x68, 0x65, 0x72, 0x73, 0x2e, 0x63, 0x6f, 0x6e, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x5f,
	0x68, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x2e, 0x76, 0x33, 0x42, 0x16, 0x43, 0x6f, 0x6e, 0x73,
	0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x48, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x50, 0x72, 0x6f,
	0x74, 0x6f, 0x50, 0x01, 0x5a, 0x7a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d,
	0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63,
	0x6f, 0x6e, 0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76,
	0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x6d, 0x61,
	0x74, 0x63, 0x68, 0x69, 0x6e, 0x67, 0x2f, 0x69, 0x6e, 0x70, 0x75, 0x74, 0x5f, 0x6d, 0x61, 0x74,
	0x63, 0x68, 0x65, 0x72, 0x73, 0x2f, 0x63, 0x6f, 0x6e, 0x73, 0x69, 0x73, 0x74, 0x65, 0x6e, 0x74,
	0x5f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x2f, 0x76, 0x33, 0x3b, 0x63, 0x6f, 0x6e, 0x73,
	0x69, 0x73, 0x74, 0x65, 0x6e, 0x74, 0x5f, 0x68, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x76, 0x33,
	0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x02, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_rawDescOnce sync.Once
	file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_rawDescData = file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_rawDesc
)

func file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_rawDescGZIP() []byte {
	file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_rawDescData)
	})
	return file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_rawDescData
}

var file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_goTypes = []interface{}{
	(*ConsistentHashing)(nil), // 0: envoy.extensions.matching.input_matchers.consistent_hashing.v3.ConsistentHashing
}
var file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() {
	file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_init()
}
func file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_init() {
	if File_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ConsistentHashing); i {
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
			RawDescriptor: file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_depIdxs,
		MessageInfos:      file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_msgTypes,
	}.Build()
	File_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto = out.File
	file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_rawDesc = nil
	file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_goTypes = nil
	file_envoy_extensions_matching_input_matchers_consistent_hashing_v3_consistent_hashing_proto_depIdxs = nil
}
