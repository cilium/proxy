// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.23.0
// 	protoc        v3.14.0
// source: envoy/extensions/filters/http/header_to_metadata/v4alpha/header_to_metadata.proto

package envoy_extensions_filters_http_header_to_metadata_v4alpha

import (
	v4alpha "github.com/cilium/proxy/go/envoy/type/matcher/v4alpha"
	_ "github.com/cncf/udpa/go/udpa/annotations"
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

type Config_ValueType int32

const (
	Config_STRING Config_ValueType = 0
	Config_NUMBER Config_ValueType = 1
	// The value is a serialized `protobuf.Value
	// <https://github.com/protocolbuffers/protobuf/blob/master/src/google/protobuf/struct.proto#L62>`_.
	Config_PROTOBUF_VALUE Config_ValueType = 2
)

// Enum value maps for Config_ValueType.
var (
	Config_ValueType_name = map[int32]string{
		0: "STRING",
		1: "NUMBER",
		2: "PROTOBUF_VALUE",
	}
	Config_ValueType_value = map[string]int32{
		"STRING":         0,
		"NUMBER":         1,
		"PROTOBUF_VALUE": 2,
	}
)

func (x Config_ValueType) Enum() *Config_ValueType {
	p := new(Config_ValueType)
	*p = x
	return p
}

func (x Config_ValueType) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Config_ValueType) Descriptor() protoreflect.EnumDescriptor {
	return file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_enumTypes[0].Descriptor()
}

func (Config_ValueType) Type() protoreflect.EnumType {
	return &file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_enumTypes[0]
}

func (x Config_ValueType) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Config_ValueType.Descriptor instead.
func (Config_ValueType) EnumDescriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDescGZIP(), []int{0, 0}
}

// ValueEncode defines the encoding algorithm.
type Config_ValueEncode int32

const (
	// The value is not encoded.
	Config_NONE Config_ValueEncode = 0
	// The value is encoded in `Base64 <https://tools.ietf.org/html/rfc4648#section-4>`_.
	// Note: this is mostly used for STRING and PROTOBUF_VALUE to escape the
	// non-ASCII characters in the header.
	Config_BASE64 Config_ValueEncode = 1
)

// Enum value maps for Config_ValueEncode.
var (
	Config_ValueEncode_name = map[int32]string{
		0: "NONE",
		1: "BASE64",
	}
	Config_ValueEncode_value = map[string]int32{
		"NONE":   0,
		"BASE64": 1,
	}
)

func (x Config_ValueEncode) Enum() *Config_ValueEncode {
	p := new(Config_ValueEncode)
	*p = x
	return p
}

func (x Config_ValueEncode) String() string {
	return protoimpl.X.EnumStringOf(x.Descriptor(), protoreflect.EnumNumber(x))
}

func (Config_ValueEncode) Descriptor() protoreflect.EnumDescriptor {
	return file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_enumTypes[1].Descriptor()
}

func (Config_ValueEncode) Type() protoreflect.EnumType {
	return &file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_enumTypes[1]
}

func (x Config_ValueEncode) Number() protoreflect.EnumNumber {
	return protoreflect.EnumNumber(x)
}

// Deprecated: Use Config_ValueEncode.Descriptor instead.
func (Config_ValueEncode) EnumDescriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDescGZIP(), []int{0, 1}
}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The list of rules to apply to requests.
	RequestRules []*Config_Rule `protobuf:"bytes,1,rep,name=request_rules,json=requestRules,proto3" json:"request_rules,omitempty"`
	// The list of rules to apply to responses.
	ResponseRules []*Config_Rule `protobuf:"bytes,2,rep,name=response_rules,json=responseRules,proto3" json:"response_rules,omitempty"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_msgTypes[0]
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
	return file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDescGZIP(), []int{0}
}

func (x *Config) GetRequestRules() []*Config_Rule {
	if x != nil {
		return x.RequestRules
	}
	return nil
}

func (x *Config) GetResponseRules() []*Config_Rule {
	if x != nil {
		return x.ResponseRules
	}
	return nil
}

// [#next-free-field: 7]
type Config_KeyValuePair struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The namespace — if this is empty, the filter's namespace will be used.
	MetadataNamespace string `protobuf:"bytes,1,opt,name=metadata_namespace,json=metadataNamespace,proto3" json:"metadata_namespace,omitempty"`
	// The key to use within the namespace.
	Key string `protobuf:"bytes,2,opt,name=key,proto3" json:"key,omitempty"`
	// Types that are assignable to ValueType:
	//	*Config_KeyValuePair_Value
	//	*Config_KeyValuePair_RegexValueRewrite
	ValueType isConfig_KeyValuePair_ValueType `protobuf_oneof:"value_type"`
	// The value's type — defaults to string.
	Type Config_ValueType `protobuf:"varint,4,opt,name=type,proto3,enum=envoy.extensions.filters.http.header_to_metadata.v4alpha.Config_ValueType" json:"type,omitempty"`
	// How is the value encoded, default is NONE (not encoded).
	// The value will be decoded accordingly before storing to metadata.
	Encode Config_ValueEncode `protobuf:"varint,5,opt,name=encode,proto3,enum=envoy.extensions.filters.http.header_to_metadata.v4alpha.Config_ValueEncode" json:"encode,omitempty"`
}

func (x *Config_KeyValuePair) Reset() {
	*x = Config_KeyValuePair{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config_KeyValuePair) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config_KeyValuePair) ProtoMessage() {}

func (x *Config_KeyValuePair) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config_KeyValuePair.ProtoReflect.Descriptor instead.
func (*Config_KeyValuePair) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDescGZIP(), []int{0, 0}
}

func (x *Config_KeyValuePair) GetMetadataNamespace() string {
	if x != nil {
		return x.MetadataNamespace
	}
	return ""
}

func (x *Config_KeyValuePair) GetKey() string {
	if x != nil {
		return x.Key
	}
	return ""
}

func (m *Config_KeyValuePair) GetValueType() isConfig_KeyValuePair_ValueType {
	if m != nil {
		return m.ValueType
	}
	return nil
}

func (x *Config_KeyValuePair) GetValue() string {
	if x, ok := x.GetValueType().(*Config_KeyValuePair_Value); ok {
		return x.Value
	}
	return ""
}

func (x *Config_KeyValuePair) GetRegexValueRewrite() *v4alpha.RegexMatchAndSubstitute {
	if x, ok := x.GetValueType().(*Config_KeyValuePair_RegexValueRewrite); ok {
		return x.RegexValueRewrite
	}
	return nil
}

func (x *Config_KeyValuePair) GetType() Config_ValueType {
	if x != nil {
		return x.Type
	}
	return Config_STRING
}

func (x *Config_KeyValuePair) GetEncode() Config_ValueEncode {
	if x != nil {
		return x.Encode
	}
	return Config_NONE
}

type isConfig_KeyValuePair_ValueType interface {
	isConfig_KeyValuePair_ValueType()
}

type Config_KeyValuePair_Value struct {
	// The value to pair with the given key.
	//
	// When used for a
	// :ref:`on_header_present <envoy_v3_api_field_extensions.filters.http.header_to_metadata.v3.Config.Rule.on_header_present>`
	// case, if value is non-empty it'll be used instead of the header value. If both are empty, no metadata is added.
	//
	// When used for a :ref:`on_header_missing <envoy_v3_api_field_extensions.filters.http.header_to_metadata.v3.Config.Rule.on_header_missing>`
	// case, a non-empty value must be provided otherwise no metadata is added.
	Value string `protobuf:"bytes,3,opt,name=value,proto3,oneof"`
}

type Config_KeyValuePair_RegexValueRewrite struct {
	// If present, the header's value will be matched and substituted with this. If there is no match or substitution, the header value
	// is used as-is.
	//
	// This is only used for :ref:`on_header_present <envoy_v3_api_field_extensions.filters.http.header_to_metadata.v3.Config.Rule.on_header_present>`.
	//
	// Note: if the `value` field is non-empty this field should be empty.
	RegexValueRewrite *v4alpha.RegexMatchAndSubstitute `protobuf:"bytes,6,opt,name=regex_value_rewrite,json=regexValueRewrite,proto3,oneof"`
}

func (*Config_KeyValuePair_Value) isConfig_KeyValuePair_ValueType() {}

func (*Config_KeyValuePair_RegexValueRewrite) isConfig_KeyValuePair_ValueType() {}

// A Rule defines what metadata to apply when a header is present or missing.
// [#next-free-field: 6]
type Config_Rule struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Types that are assignable to HeaderCookieSpecifier:
	//	*Config_Rule_Header
	//	*Config_Rule_Cookie
	HeaderCookieSpecifier isConfig_Rule_HeaderCookieSpecifier `protobuf_oneof:"header_cookie_specifier"`
	// If the header or cookie is present, apply this metadata KeyValuePair.
	//
	// If the value in the KeyValuePair is non-empty, it'll be used instead
	// of the header or cookie value.
	OnPresent *Config_KeyValuePair `protobuf:"bytes,2,opt,name=on_present,json=onPresent,proto3" json:"on_present,omitempty"`
	// If the header or cookie is not present, apply this metadata KeyValuePair.
	//
	// The value in the KeyValuePair must be set, since it'll be used in lieu
	// of the missing header or cookie value.
	OnMissing *Config_KeyValuePair `protobuf:"bytes,3,opt,name=on_missing,json=onMissing,proto3" json:"on_missing,omitempty"`
	// Whether or not to remove the header after a rule is applied.
	//
	// This prevents headers from leaking.
	// This field is not supported in case of a cookie.
	Remove bool `protobuf:"varint,4,opt,name=remove,proto3" json:"remove,omitempty"`
}

func (x *Config_Rule) Reset() {
	*x = Config_Rule{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config_Rule) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config_Rule) ProtoMessage() {}

func (x *Config_Rule) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config_Rule.ProtoReflect.Descriptor instead.
func (*Config_Rule) Descriptor() ([]byte, []int) {
	return file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDescGZIP(), []int{0, 1}
}

func (m *Config_Rule) GetHeaderCookieSpecifier() isConfig_Rule_HeaderCookieSpecifier {
	if m != nil {
		return m.HeaderCookieSpecifier
	}
	return nil
}

func (x *Config_Rule) GetHeader() string {
	if x, ok := x.GetHeaderCookieSpecifier().(*Config_Rule_Header); ok {
		return x.Header
	}
	return ""
}

func (x *Config_Rule) GetCookie() string {
	if x, ok := x.GetHeaderCookieSpecifier().(*Config_Rule_Cookie); ok {
		return x.Cookie
	}
	return ""
}

func (x *Config_Rule) GetOnPresent() *Config_KeyValuePair {
	if x != nil {
		return x.OnPresent
	}
	return nil
}

func (x *Config_Rule) GetOnMissing() *Config_KeyValuePair {
	if x != nil {
		return x.OnMissing
	}
	return nil
}

func (x *Config_Rule) GetRemove() bool {
	if x != nil {
		return x.Remove
	}
	return false
}

type isConfig_Rule_HeaderCookieSpecifier interface {
	isConfig_Rule_HeaderCookieSpecifier()
}

type Config_Rule_Header struct {
	// Specifies that a match will be performed on the value of a header or a cookie.
	//
	// The header to be extracted.
	Header string `protobuf:"bytes,1,opt,name=header,proto3,oneof"`
}

type Config_Rule_Cookie struct {
	// The cookie to be extracted.
	Cookie string `protobuf:"bytes,5,opt,name=cookie,proto3,oneof"`
}

func (*Config_Rule_Header) isConfig_Rule_HeaderCookieSpecifier() {}

func (*Config_Rule_Cookie) isConfig_Rule_HeaderCookieSpecifier() {}

var File_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto protoreflect.FileDescriptor

var file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDesc = []byte{
	0x0a, 0x51, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2f, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2f, 0x68, 0x74, 0x74, 0x70, 0x2f,
	0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x74, 0x6f, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x2f, 0x76, 0x34, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x65,
	0x72, 0x5f, 0x74, 0x6f, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x12, 0x38, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e,
	0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68, 0x74,
	0x74, 0x70, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x74, 0x6f, 0x5f, 0x6d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x76, 0x34, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x1a, 0x26, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x74, 0x79, 0x70, 0x65, 0x2f, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65,
	0x72, 0x2f, 0x76, 0x34, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2f, 0x72, 0x65, 0x67, 0x65, 0x78, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x75, 0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e,
	0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x17, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x65, 0x2f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x22, 0xb9, 0x0a, 0x0a, 0x06, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x6a, 0x0a, 0x0d, 0x72,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x5f, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03,
	0x28, 0x0b, 0x32, 0x45, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e,
	0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68, 0x74,
	0x74, 0x70, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x74, 0x6f, 0x5f, 0x6d, 0x65, 0x74,
	0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x76, 0x34, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x2e, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x0c, 0x72, 0x65, 0x71, 0x75, 0x65,
	0x73, 0x74, 0x52, 0x75, 0x6c, 0x65, 0x73, 0x12, 0x6c, 0x0a, 0x0e, 0x72, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x5f, 0x72, 0x75, 0x6c, 0x65, 0x73, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32,
	0x45, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e,
	0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x74, 0x6f, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x2e, 0x76, 0x34, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x2e, 0x52, 0x75, 0x6c, 0x65, 0x52, 0x0d, 0x72, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x52, 0x75, 0x6c, 0x65, 0x73, 0x1a, 0x85, 0x04, 0x0a, 0x0c, 0x4b, 0x65, 0x79, 0x56, 0x61, 0x6c,
	0x75, 0x65, 0x50, 0x61, 0x69, 0x72, 0x12, 0x2d, 0x0a, 0x12, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x70, 0x61, 0x63, 0x65, 0x18, 0x01, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x11, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x4e, 0x61, 0x6d, 0x65,
	0x73, 0x70, 0x61, 0x63, 0x65, 0x12, 0x19, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x42, 0x07, 0xfa, 0x42, 0x04, 0x72, 0x02, 0x10, 0x01, 0x52, 0x03, 0x6b, 0x65, 0x79,
	0x12, 0x16, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09, 0x48,
	0x00, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x12, 0x65, 0x0a, 0x13, 0x72, 0x65, 0x67, 0x65,
	0x78, 0x5f, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x5f, 0x72, 0x65, 0x77, 0x72, 0x69, 0x74, 0x65, 0x18,
	0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x33, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x74, 0x79,
	0x70, 0x65, 0x2e, 0x6d, 0x61, 0x74, 0x63, 0x68, 0x65, 0x72, 0x2e, 0x76, 0x34, 0x61, 0x6c, 0x70,
	0x68, 0x61, 0x2e, 0x52, 0x65, 0x67, 0x65, 0x78, 0x4d, 0x61, 0x74, 0x63, 0x68, 0x41, 0x6e, 0x64,
	0x53, 0x75, 0x62, 0x73, 0x74, 0x69, 0x74, 0x75, 0x74, 0x65, 0x48, 0x00, 0x52, 0x11, 0x72, 0x65,
	0x67, 0x65, 0x78, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x52, 0x65, 0x77, 0x72, 0x69, 0x74, 0x65, 0x12,
	0x68, 0x0a, 0x04, 0x74, 0x79, 0x70, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x4a, 0x2e,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73,
	0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x68, 0x65,
	0x61, 0x64, 0x65, 0x72, 0x5f, 0x74, 0x6f, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61,
	0x2e, 0x76, 0x34, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e,
	0x56, 0x61, 0x6c, 0x75, 0x65, 0x54, 0x79, 0x70, 0x65, 0x42, 0x08, 0xfa, 0x42, 0x05, 0x82, 0x01,
	0x02, 0x10, 0x01, 0x52, 0x04, 0x74, 0x79, 0x70, 0x65, 0x12, 0x64, 0x0a, 0x06, 0x65, 0x6e, 0x63,
	0x6f, 0x64, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0e, 0x32, 0x4c, 0x2e, 0x65, 0x6e, 0x76, 0x6f,
	0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c,
	0x74, 0x65, 0x72, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x5f, 0x74, 0x6f, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x76, 0x34, 0x61,
	0x6c, 0x70, 0x68, 0x61, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x56, 0x61, 0x6c, 0x75,
	0x65, 0x45, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x52, 0x06, 0x65, 0x6e, 0x63, 0x6f, 0x64, 0x65, 0x3a,
	0x4e, 0x9a, 0xc5, 0x88, 0x1e, 0x49, 0x0a, 0x47, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78,
	0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73,
	0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x74, 0x6f, 0x5f,
	0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x76, 0x33, 0x2e, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x2e, 0x4b, 0x65, 0x79, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x50, 0x61, 0x69, 0x72, 0x42,
	0x0c, 0x0a, 0x0a, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x1a, 0xab, 0x03,
	0x0a, 0x04, 0x52, 0x75, 0x6c, 0x65, 0x12, 0x25, 0x0a, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0b, 0xfa, 0x42, 0x08, 0x72, 0x06, 0xc0, 0x01, 0x01,
	0xc8, 0x01, 0x00, 0x48, 0x00, 0x52, 0x06, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x12, 0x25, 0x0a,
	0x06, 0x63, 0x6f, 0x6f, 0x6b, 0x69, 0x65, 0x18, 0x05, 0x20, 0x01, 0x28, 0x09, 0x42, 0x0b, 0xfa,
	0x42, 0x08, 0x72, 0x06, 0xc0, 0x01, 0x01, 0xc8, 0x01, 0x00, 0x48, 0x00, 0x52, 0x06, 0x63, 0x6f,
	0x6f, 0x6b, 0x69, 0x65, 0x12, 0x6c, 0x0a, 0x0a, 0x6f, 0x6e, 0x5f, 0x70, 0x72, 0x65, 0x73, 0x65,
	0x6e, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x4d, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74,
	0x65, 0x72, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f,
	0x74, 0x6f, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x76, 0x34, 0x61, 0x6c,
	0x70, 0x68, 0x61, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x4b, 0x65, 0x79, 0x56, 0x61,
	0x6c, 0x75, 0x65, 0x50, 0x61, 0x69, 0x72, 0x52, 0x09, 0x6f, 0x6e, 0x50, 0x72, 0x65, 0x73, 0x65,
	0x6e, 0x74, 0x12, 0x6c, 0x0a, 0x0a, 0x6f, 0x6e, 0x5f, 0x6d, 0x69, 0x73, 0x73, 0x69, 0x6e, 0x67,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x4d, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65,
	0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72,
	0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x74, 0x6f,
	0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x76, 0x34, 0x61, 0x6c, 0x70, 0x68,
	0x61, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x4b, 0x65, 0x79, 0x56, 0x61, 0x6c, 0x75,
	0x65, 0x50, 0x61, 0x69, 0x72, 0x52, 0x09, 0x6f, 0x6e, 0x4d, 0x69, 0x73, 0x73, 0x69, 0x6e, 0x67,
	0x12, 0x16, 0x0a, 0x06, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x18, 0x04, 0x20, 0x01, 0x28, 0x08,
	0x52, 0x06, 0x72, 0x65, 0x6d, 0x6f, 0x76, 0x65, 0x3a, 0x46, 0x9a, 0xc5, 0x88, 0x1e, 0x41, 0x0a,
	0x3f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e,
	0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x68,
	0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x74, 0x6f, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0x2e, 0x76, 0x33, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x2e, 0x52, 0x75, 0x6c, 0x65,
	0x42, 0x19, 0x0a, 0x17, 0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x63, 0x6f, 0x6f, 0x6b, 0x69,
	0x65, 0x5f, 0x73, 0x70, 0x65, 0x63, 0x69, 0x66, 0x69, 0x65, 0x72, 0x22, 0x37, 0x0a, 0x09, 0x56,
	0x61, 0x6c, 0x75, 0x65, 0x54, 0x79, 0x70, 0x65, 0x12, 0x0a, 0x0a, 0x06, 0x53, 0x54, 0x52, 0x49,
	0x4e, 0x47, 0x10, 0x00, 0x12, 0x0a, 0x0a, 0x06, 0x4e, 0x55, 0x4d, 0x42, 0x45, 0x52, 0x10, 0x01,
	0x12, 0x12, 0x0a, 0x0e, 0x50, 0x52, 0x4f, 0x54, 0x4f, 0x42, 0x55, 0x46, 0x5f, 0x56, 0x41, 0x4c,
	0x55, 0x45, 0x10, 0x02, 0x22, 0x23, 0x0a, 0x0b, 0x56, 0x61, 0x6c, 0x75, 0x65, 0x45, 0x6e, 0x63,
	0x6f, 0x64, 0x65, 0x12, 0x08, 0x0a, 0x04, 0x4e, 0x4f, 0x4e, 0x45, 0x10, 0x00, 0x12, 0x0a, 0x0a,
	0x06, 0x42, 0x41, 0x53, 0x45, 0x36, 0x34, 0x10, 0x01, 0x3a, 0x41, 0x9a, 0xc5, 0x88, 0x1e, 0x3c,
	0x0a, 0x3a, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e,
	0x68, 0x65, 0x61, 0x64, 0x65, 0x72, 0x5f, 0x74, 0x6f, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61,
	0x74, 0x61, 0x2e, 0x76, 0x33, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x42, 0x69, 0x0a, 0x46,
	0x69, 0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2e, 0x65, 0x78, 0x74, 0x65, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x66,
	0x69, 0x6c, 0x74, 0x65, 0x72, 0x73, 0x2e, 0x68, 0x74, 0x74, 0x70, 0x2e, 0x68, 0x65, 0x61, 0x64,
	0x65, 0x72, 0x5f, 0x74, 0x6f, 0x5f, 0x6d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x2e, 0x76,
	0x34, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x42, 0x15, 0x48, 0x65, 0x61, 0x64, 0x65, 0x72, 0x54, 0x6f,
	0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74, 0x61, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0xba,
	0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10, 0x03, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDescOnce sync.Once
	file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDescData = file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDesc
)

func file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDescGZIP() []byte {
	file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDescOnce.Do(func() {
		file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDescData)
	})
	return file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDescData
}

var file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_enumTypes = make([]protoimpl.EnumInfo, 2)
var file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_msgTypes = make([]protoimpl.MessageInfo, 3)
var file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_goTypes = []interface{}{
	(Config_ValueType)(0),                   // 0: envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.ValueType
	(Config_ValueEncode)(0),                 // 1: envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.ValueEncode
	(*Config)(nil),                          // 2: envoy.extensions.filters.http.header_to_metadata.v4alpha.Config
	(*Config_KeyValuePair)(nil),             // 3: envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.KeyValuePair
	(*Config_Rule)(nil),                     // 4: envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.Rule
	(*v4alpha.RegexMatchAndSubstitute)(nil), // 5: envoy.type.matcher.v4alpha.RegexMatchAndSubstitute
}
var file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_depIdxs = []int32{
	4, // 0: envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.request_rules:type_name -> envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.Rule
	4, // 1: envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.response_rules:type_name -> envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.Rule
	5, // 2: envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.KeyValuePair.regex_value_rewrite:type_name -> envoy.type.matcher.v4alpha.RegexMatchAndSubstitute
	0, // 3: envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.KeyValuePair.type:type_name -> envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.ValueType
	1, // 4: envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.KeyValuePair.encode:type_name -> envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.ValueEncode
	3, // 5: envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.Rule.on_present:type_name -> envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.KeyValuePair
	3, // 6: envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.Rule.on_missing:type_name -> envoy.extensions.filters.http.header_to_metadata.v4alpha.Config.KeyValuePair
	7, // [7:7] is the sub-list for method output_type
	7, // [7:7] is the sub-list for method input_type
	7, // [7:7] is the sub-list for extension type_name
	7, // [7:7] is the sub-list for extension extendee
	0, // [0:7] is the sub-list for field type_name
}

func init() {
	file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_init()
}
func file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_init() {
	if File_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
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
		file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Config_KeyValuePair); i {
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
		file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Config_Rule); i {
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
	file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_msgTypes[1].OneofWrappers = []interface{}{
		(*Config_KeyValuePair_Value)(nil),
		(*Config_KeyValuePair_RegexValueRewrite)(nil),
	}
	file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_msgTypes[2].OneofWrappers = []interface{}{
		(*Config_Rule_Header)(nil),
		(*Config_Rule_Cookie)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDesc,
			NumEnums:      2,
			NumMessages:   3,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_goTypes,
		DependencyIndexes: file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_depIdxs,
		EnumInfos:         file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_enumTypes,
		MessageInfos:      file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_msgTypes,
	}.Build()
	File_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto = out.File
	file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_rawDesc = nil
	file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_goTypes = nil
	file_envoy_extensions_filters_http_header_to_metadata_v4alpha_header_to_metadata_proto_depIdxs = nil
}
