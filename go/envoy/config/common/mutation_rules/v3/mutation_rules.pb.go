// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.19.4
// source: envoy/config/common/mutation_rules/v3/mutation_rules.proto

package mutation_rulesv3

import (
	v3 "github.com/cilium/proxy/go/envoy/type/matcher/v3"
	_ "github.com/cncf/xds/go/udpa/annotations"
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

// The HeaderMutationRules structure specifies what headers may be
// manipulated by a processing filter. This set of rules makes it
// possible to control which modifications a filter may make.
//
// By default, an external processing server may add, modify, or remove
// any header except for an "Envoy internal" header (which is typically
// denoted by an x-envoy prefix) or specific headers that may affect
// further filter processing:
//
// * “host“
// * “:authority“
// * “:scheme“
// * “:method“
//
// Every attempt to add, change, append, or remove a header will be
// tested against the rules here. Disallowed header mutations will be
// ignored unless “disallow_is_error“ is set to true.
//
// Attempts to remove headers are further constrained -- regardless of the
// settings, system-defined headers (that start with “:“) and the “host“
// header may never be removed.
//
// In addition, a counter will be incremented whenever a mutation is
// rejected. In the ext_proc filter, that counter is named
// “rejected_header_mutations“.
// [#next-free-field: 8]
type HeaderMutationRules struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// By default, certain headers that could affect processing of subsequent
	// filters or request routing cannot be modified. These headers are
	// “host“, “:authority“, “:scheme“, and “:method“. Setting this parameter
	// to true allows these headers to be modified as well.
	AllowAllRouting *wrapperspb.BoolValue `protobuf:"bytes,1,opt,name=allow_all_routing,json=allowAllRouting,proto3" json:"allow_all_routing,omitempty"`
	// If true, allow modification of envoy internal headers. By default, these
	// start with “x-envoy“ but this may be overridden in the “Bootstrap“
	// configuration using the
	// :ref:`header_prefix <envoy_v3_api_field_config.bootstrap.v3.Bootstrap.header_prefix>`
	// field. Default is false.
	AllowEnvoy *wrapperspb.BoolValue `protobuf:"bytes,2,opt,name=allow_envoy,json=allowEnvoy,proto3" json:"allow_envoy,omitempty"`
	// If true, prevent modification of any system header, defined as a header
	// that starts with a “:“ character, regardless of any other settings.
	// A processing server may still override the “:status“ of an HTTP response
	// using an “ImmediateResponse“ message. Default is false.
	DisallowSystem *wrapperspb.BoolValue `protobuf:"bytes,3,opt,name=disallow_system,json=disallowSystem,proto3" json:"disallow_system,omitempty"`
	// If true, prevent modifications of all header values, regardless of any
	// other settings. A processing server may still override the “:status“
	// of an HTTP response using an “ImmediateResponse“ message. Default is false.
	DisallowAll *wrapperspb.BoolValue `protobuf:"bytes,4,opt,name=disallow_all,json=disallowAll,proto3" json:"disallow_all,omitempty"`
	// If set, specifically allow any header that matches this regular
	// expression. This overrides all other settings except for
	// “disallow_expression“.
	AllowExpression *v3.RegexMatcher `protobuf:"bytes,5,opt,name=allow_expression,json=allowExpression,proto3" json:"allow_expression,omitempty"`
	// If set, specifically disallow any header that matches this regular
	// expression regardless of any other settings.
	DisallowExpression *v3.RegexMatcher `protobuf:"bytes,6,opt,name=disallow_expression,json=disallowExpression,proto3" json:"disallow_expression,omitempty"`
	// If true, and if the rules in this list cause a header mutation to be
	// disallowed, then the filter using this configuration will terminate the
	// request with a 500 error. In addition, regardless of the setting of this
	// parameter, any attempt to set, add, or modify a disallowed header will
	// cause the “rejected_header_mutations“ counter to be incremented.
	// Default is false.
	DisallowIsError *wrapperspb.BoolValue `protobuf:"bytes,7,opt,name=disallow_is_error,json=disallowIsError,proto3" json:"disallow_is_error,omitempty"`
}

func (x *HeaderMutationRules) Reset() {
	*x = HeaderMutationRules{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HeaderMutationRules) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HeaderMutationRules) ProtoMessage() {}

func (x *HeaderMutationRules) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HeaderMutationRules.ProtoReflect.Descriptor instead.
func (*HeaderMutationRules) Descriptor() ([]byte, []int) {
	return file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_rawDescGZIP(), []int{0}
}

func (x *HeaderMutationRules) GetAllowAllRouting() *wrapperspb.BoolValue {
	if x != nil {
		return x.AllowAllRouting
	}
	return nil
}

func (x *HeaderMutationRules) GetAllowEnvoy() *wrapperspb.BoolValue {
	if x != nil {
		return x.AllowEnvoy
	}
	return nil
}

func (x *HeaderMutationRules) GetDisallowSystem() *wrapperspb.BoolValue {
	if x != nil {
		return x.DisallowSystem
	}
	return nil
}

func (x *HeaderMutationRules) GetDisallowAll() *wrapperspb.BoolValue {
	if x != nil {
		return x.DisallowAll
	}
	return nil
}

func (x *HeaderMutationRules) GetAllowExpression() *v3.RegexMatcher {
	if x != nil {
		return x.AllowExpression
	}
	return nil
}

func (x *HeaderMutationRules) GetDisallowExpression() *v3.RegexMatcher {
	if x != nil {
		return x.DisallowExpression
	}
	return nil
}

func (x *HeaderMutationRules) GetDisallowIsError() *wrapperspb.BoolValue {
	if x != nil {
		return x.DisallowIsError
	}
	return nil
}

var File_envoy_config_common_mutation_rules_v3_mutation_rules_proto protoreflect.FileDescriptor

var file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_rawDesc = []byte{
	0x0a, 0x3a, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x63,
	0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x6d, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x72,
	0x75, 0x6c, 0x65, 0x73, 0x2f, 0x76, 0x33, 0x2f, 0x6d, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x5f, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x25, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f,
	0x6e, 0x2e, 0x6d, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x72, 0x75, 0x6c, 0x65, 0x73,
	0x2e, 0x76, 0x33, 0x1a, 0x21, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f,
	0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2f, 0x76, 0x33, 0x2f, 0x72, 0x65, 0x67, 0x65, 0x78,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x77, 0x72, 0x61, 0x70, 0x70, 0x65, 0x72, 0x73,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e,
	0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22, 0x8c, 0x04, 0x0a, 0x13, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x4d, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x75, 0x6c, 0x65, 0x73, 0x12, 0x46, 0x0a,
	0x11, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x61, 0x6c, 0x6c, 0x5f, 0x72, 0x6f, 0x75, 0x74, 0x69,
	0x6e, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c,
	0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x42, 0x6f, 0x6f, 0x6c, 0x56,
	0x61, 0x6c, 0x75, 0x65, 0x52, 0x0f, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x41, 0x6c, 0x6c, 0x52, 0x6f,
	0x75, 0x74, 0x69, 0x6e, 0x67, 0x12, 0x3b, 0x0a, 0x0b, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x42, 0x6f, 0x6f,
	0x6c, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x0a, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x45, 0x6e, 0x76,
	0x6f, 0x79, 0x12, 0x43, 0x0a, 0x0f, 0x64, 0x69, 0x73, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x73,
	0x79, 0x73, 0x74, 0x65, 0x6d, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x42, 0x6f,
	0x6f, 0x6c, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x0e, 0x64, 0x69, 0x73, 0x61, 0x6c, 0x6c, 0x6f,
	0x77, 0x53, 0x79, 0x73, 0x74, 0x65, 0x6d, 0x12, 0x3d, 0x0a, 0x0c, 0x64, 0x69, 0x73, 0x61, 0x6c,
	0x6c, 0x6f, 0x77, 0x5f, 0x61, 0x6c, 0x6c, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x42, 0x6f, 0x6f, 0x6c, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x0b, 0x64, 0x69, 0x73, 0x61, 0x6c,
	0x6c, 0x6f, 0x77, 0x41, 0x6c, 0x6c, 0x12, 0x4e, 0x0a, 0x10, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x5f,
	0x65, 0x78, 0x70, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x23, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x74, 0x79, 0x70, 0x65, 0x2e, 0x6d, 0x61,
	0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x2e, 0x52, 0x65, 0x67, 0x65, 0x78, 0x4d, 0x61,
	0x74, 0x63, 0x68, 0x65, 0x72, 0x52, 0x0f, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x45, 0x78, 0x70, 0x72,
	0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x54, 0x0a, 0x13, 0x64, 0x69, 0x73, 0x61, 0x6c, 0x6c,
	0x6f, 0x77, 0x5f, 0x65, 0x78, 0x70, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x18, 0x06, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x23, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x74, 0x79, 0x70, 0x65,
	0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76, 0x33, 0x2e, 0x52, 0x65, 0x67, 0x65,
	0x78, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x52, 0x12, 0x64, 0x69, 0x73, 0x61, 0x6c, 0x6c,
	0x6f, 0x77, 0x45, 0x78, 0x70, 0x72, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x46, 0x0a, 0x11,
	0x64, 0x69, 0x73, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x5f, 0x69, 0x73, 0x5f, 0x65, 0x72, 0x72, 0x6f,
	0x72, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x42, 0x6f, 0x6f, 0x6c, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x52, 0x0f, 0x64, 0x69, 0x73, 0x61, 0x6c, 0x6c, 0x6f, 0x77, 0x49, 0x73, 0x45,
	0x72, 0x72, 0x6f, 0x72, 0x42, 0xb2, 0x01, 0x0a, 0x33, 0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x63, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x2e, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2e, 0x6d, 0x75, 0x74, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x5f, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2e, 0x76, 0x33, 0x42, 0x12, 0x4d, 0x75,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x75, 0x6c, 0x65, 0x73, 0x50, 0x72, 0x6f, 0x74, 0x6f,
	0x50, 0x01, 0x5a, 0x5d, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2f, 0x67, 0x6f, 0x2d, 0x63, 0x6f, 0x6e,
	0x74, 0x72, 0x6f, 0x6c, 0x2d, 0x70, 0x6c, 0x61, 0x6e, 0x65, 0x2f, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2f, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2f, 0x63, 0x6f, 0x6d, 0x6d, 0x6f, 0x6e, 0x2f, 0x6d,
	0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x2f, 0x76, 0x33,
	0x3b, 0x6d, 0x75, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x5f, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x76,
	0x33, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x02, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_rawDescOnce sync.Once
	file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_rawDescData = file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_rawDesc
)

func file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_rawDescGZIP() []byte {
	file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_rawDescOnce.Do(func() {
		file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_rawDescData)
	})
	return file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_rawDescData
}

var file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_goTypes = []interface{}{
	(*HeaderMutationRules)(nil),  // 0: envoy.config.common.mutation_rules.v3.HeaderMutationRules
	(*wrapperspb.BoolValue)(nil), // 1: google.protobuf.BoolValue
	(*v3.RegexMatcher)(nil),      // 2: envoy.type.matcher.v3.RegexMatcher
}
var file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_depIdxs = []int32{
	1, // 0: envoy.config.common.mutation_rules.v3.HeaderMutationRules.allow_all_routing:type_name -> google.protobuf.BoolValue
	1, // 1: envoy.config.common.mutation_rules.v3.HeaderMutationRules.allow_envoy:type_name -> google.protobuf.BoolValue
	1, // 2: envoy.config.common.mutation_rules.v3.HeaderMutationRules.disallow_system:type_name -> google.protobuf.BoolValue
	1, // 3: envoy.config.common.mutation_rules.v3.HeaderMutationRules.disallow_all:type_name -> google.protobuf.BoolValue
	2, // 4: envoy.config.common.mutation_rules.v3.HeaderMutationRules.allow_expression:type_name -> envoy.type.matcher.v3.RegexMatcher
	2, // 5: envoy.config.common.mutation_rules.v3.HeaderMutationRules.disallow_expression:type_name -> envoy.type.matcher.v3.RegexMatcher
	1, // 6: envoy.config.common.mutation_rules.v3.HeaderMutationRules.disallow_is_error:type_name -> google.protobuf.BoolValue
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() { file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_init() }
func file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_init() {
	if File_envoy_config_common_mutation_rules_v3_mutation_rules_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HeaderMutationRules); i {
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
			RawDescriptor: file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_goTypes,
		DependencyIndexes: file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_depIdxs,
		MessageInfos:      file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_msgTypes,
	}.Build()
	File_envoy_config_common_mutation_rules_v3_mutation_rules_proto = out.File
	file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_rawDesc = nil
	file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_goTypes = nil
	file_envoy_config_common_mutation_rules_v3_mutation_rules_proto_depIdxs = nil
}
