// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/api/v2/core/base.proto

package core

import (
	fmt "fmt"
	_ "github.com/gogo/protobuf/gogoproto"
	proto "github.com/golang/protobuf/proto"
	_struct "github.com/golang/protobuf/ptypes/struct"
	wrappers "github.com/golang/protobuf/ptypes/wrappers"
	_ "github.com/lyft/protoc-gen-validate/validate"
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

// Envoy supports :ref:`upstream priority routing
// <arch_overview_http_routing_priority>` both at the route and the virtual
// cluster level. The current priority implementation uses different connection
// pool and circuit breaking settings for each priority level. This means that
// even for HTTP/2 requests, two physical connections will be used to an
// upstream host. In the future Envoy will likely support true HTTP/2 priority
// over a single upstream connection.
type RoutingPriority int32

const (
	RoutingPriority_DEFAULT RoutingPriority = 0
	RoutingPriority_HIGH    RoutingPriority = 1
)

var RoutingPriority_name = map[int32]string{
	0: "DEFAULT",
	1: "HIGH",
}

var RoutingPriority_value = map[string]int32{
	"DEFAULT": 0,
	"HIGH":    1,
}

func (x RoutingPriority) String() string {
	return proto.EnumName(RoutingPriority_name, int32(x))
}

func (RoutingPriority) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_a7738c0f9e1bfff4, []int{0}
}

// HTTP request method.
type RequestMethod int32

const (
	RequestMethod_METHOD_UNSPECIFIED RequestMethod = 0
	RequestMethod_GET                RequestMethod = 1
	RequestMethod_HEAD               RequestMethod = 2
	RequestMethod_POST               RequestMethod = 3
	RequestMethod_PUT                RequestMethod = 4
	RequestMethod_DELETE             RequestMethod = 5
	RequestMethod_CONNECT            RequestMethod = 6
	RequestMethod_OPTIONS            RequestMethod = 7
	RequestMethod_TRACE              RequestMethod = 8
)

var RequestMethod_name = map[int32]string{
	0: "METHOD_UNSPECIFIED",
	1: "GET",
	2: "HEAD",
	3: "POST",
	4: "PUT",
	5: "DELETE",
	6: "CONNECT",
	7: "OPTIONS",
	8: "TRACE",
}

var RequestMethod_value = map[string]int32{
	"METHOD_UNSPECIFIED": 0,
	"GET":                1,
	"HEAD":               2,
	"POST":               3,
	"PUT":                4,
	"DELETE":             5,
	"CONNECT":            6,
	"OPTIONS":            7,
	"TRACE":              8,
}

func (x RequestMethod) String() string {
	return proto.EnumName(RequestMethod_name, int32(x))
}

func (RequestMethod) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_a7738c0f9e1bfff4, []int{1}
}

type SocketOption_SocketState int32

const (
	// Socket options are applied after socket creation but before binding the socket to a port
	SocketOption_STATE_PREBIND SocketOption_SocketState = 0
	// Socket options are applied after binding the socket to a port but before calling listen()
	SocketOption_STATE_BOUND SocketOption_SocketState = 1
	// Socket options are applied after calling listen()
	SocketOption_STATE_LISTENING SocketOption_SocketState = 2
)

var SocketOption_SocketState_name = map[int32]string{
	0: "STATE_PREBIND",
	1: "STATE_BOUND",
	2: "STATE_LISTENING",
}

var SocketOption_SocketState_value = map[string]int32{
	"STATE_PREBIND":   0,
	"STATE_BOUND":     1,
	"STATE_LISTENING": 2,
}

func (x SocketOption_SocketState) String() string {
	return proto.EnumName(SocketOption_SocketState_name, int32(x))
}

func (SocketOption_SocketState) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_a7738c0f9e1bfff4, []int{8, 0}
}

// Identifies location of where either Envoy runs or where upstream hosts run.
type Locality struct {
	// Region this :ref:`zone <envoy_api_field_core.Locality.zone>` belongs to.
	Region string `protobuf:"bytes,1,opt,name=region,proto3" json:"region,omitempty"`
	// Defines the local service zone where Envoy is running. Though optional, it
	// should be set if discovery service routing is used and the discovery
	// service exposes :ref:`zone data <config_cluster_manager_sds_api_host_az>`,
	// either in this message or via :option:`--service-zone`. The meaning of zone
	// is context dependent, e.g. `Availability Zone (AZ)
	// <https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/using-regions-availability-zones.html>`_
	// on AWS, `Zone <https://cloud.google.com/compute/docs/regions-zones/>`_ on
	// GCP, etc.
	Zone string `protobuf:"bytes,2,opt,name=zone,proto3" json:"zone,omitempty"`
	// When used for locality of upstream hosts, this field further splits zone
	// into smaller chunks of sub-zones so they can be load balanced
	// independently.
	SubZone              string   `protobuf:"bytes,3,opt,name=sub_zone,json=subZone,proto3" json:"sub_zone,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Locality) Reset()         { *m = Locality{} }
func (m *Locality) String() string { return proto.CompactTextString(m) }
func (*Locality) ProtoMessage()    {}
func (*Locality) Descriptor() ([]byte, []int) {
	return fileDescriptor_a7738c0f9e1bfff4, []int{0}
}

func (m *Locality) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Locality.Unmarshal(m, b)
}
func (m *Locality) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Locality.Marshal(b, m, deterministic)
}
func (m *Locality) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Locality.Merge(m, src)
}
func (m *Locality) XXX_Size() int {
	return xxx_messageInfo_Locality.Size(m)
}
func (m *Locality) XXX_DiscardUnknown() {
	xxx_messageInfo_Locality.DiscardUnknown(m)
}

var xxx_messageInfo_Locality proto.InternalMessageInfo

func (m *Locality) GetRegion() string {
	if m != nil {
		return m.Region
	}
	return ""
}

func (m *Locality) GetZone() string {
	if m != nil {
		return m.Zone
	}
	return ""
}

func (m *Locality) GetSubZone() string {
	if m != nil {
		return m.SubZone
	}
	return ""
}

// Identifies a specific Envoy instance. The node identifier is presented to the
// management server, which may use this identifier to distinguish per Envoy
// configuration for serving.
type Node struct {
	// An opaque node identifier for the Envoy node. This also provides the local
	// service node name. It should be set if any of the following features are
	// used: :ref:`statsd <arch_overview_statistics>`, :ref:`CDS
	// <config_cluster_manager_cds>`, and :ref:`HTTP tracing
	// <arch_overview_tracing>`, either in this message or via
	// :option:`--service-node`.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// Defines the local service cluster name where Envoy is running. Though
	// optional, it should be set if any of the following features are used:
	// :ref:`statsd <arch_overview_statistics>`, :ref:`health check cluster
	// verification <config_cluster_manager_cluster_hc_service_name>`,
	// :ref:`runtime override directory <config_runtime_override_subdirectory>`,
	// :ref:`user agent addition <config_http_conn_man_add_user_agent>`,
	// :ref:`HTTP global rate limiting <config_http_filters_rate_limit>`,
	// :ref:`CDS <config_cluster_manager_cds>`, and :ref:`HTTP tracing
	// <arch_overview_tracing>`, either in this message or via
	// :option:`--service-cluster`.
	Cluster string `protobuf:"bytes,2,opt,name=cluster,proto3" json:"cluster,omitempty"`
	// Opaque metadata extending the node identifier. Envoy will pass this
	// directly to the management server.
	Metadata *_struct.Struct `protobuf:"bytes,3,opt,name=metadata,proto3" json:"metadata,omitempty"`
	// Locality specifying where the Envoy instance is running.
	Locality *Locality `protobuf:"bytes,4,opt,name=locality,proto3" json:"locality,omitempty"`
	// This is motivated by informing a management server during canary which
	// version of Envoy is being tested in a heterogeneous fleet. This will be set
	// by Envoy in management server RPCs.
	BuildVersion         string   `protobuf:"bytes,5,opt,name=build_version,json=buildVersion,proto3" json:"build_version,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Node) Reset()         { *m = Node{} }
func (m *Node) String() string { return proto.CompactTextString(m) }
func (*Node) ProtoMessage()    {}
func (*Node) Descriptor() ([]byte, []int) {
	return fileDescriptor_a7738c0f9e1bfff4, []int{1}
}

func (m *Node) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Node.Unmarshal(m, b)
}
func (m *Node) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Node.Marshal(b, m, deterministic)
}
func (m *Node) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Node.Merge(m, src)
}
func (m *Node) XXX_Size() int {
	return xxx_messageInfo_Node.Size(m)
}
func (m *Node) XXX_DiscardUnknown() {
	xxx_messageInfo_Node.DiscardUnknown(m)
}

var xxx_messageInfo_Node proto.InternalMessageInfo

func (m *Node) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *Node) GetCluster() string {
	if m != nil {
		return m.Cluster
	}
	return ""
}

func (m *Node) GetMetadata() *_struct.Struct {
	if m != nil {
		return m.Metadata
	}
	return nil
}

func (m *Node) GetLocality() *Locality {
	if m != nil {
		return m.Locality
	}
	return nil
}

func (m *Node) GetBuildVersion() string {
	if m != nil {
		return m.BuildVersion
	}
	return ""
}

// Metadata provides additional inputs to filters based on matched listeners,
// filter chains, routes and endpoints. It is structured as a map from filter
// name (in reverse DNS format) to metadata specific to the filter. Metadata
// key-values for a filter are merged as connection and request handling occurs,
// with later values for the same key overriding earlier values.
//
// An example use of metadata is providing additional values to
// http_connection_manager in the envoy.http_connection_manager.access_log
// namespace.
//
// For load balancing, Metadata provides a means to subset cluster endpoints.
// Endpoints have a Metadata object associated and routes contain a Metadata
// object to match against. There are some well defined metadata used today for
// this purpose:
//
// * ``{"envoy.lb": {"canary": <bool> }}`` This indicates the canary status of an
//   endpoint and is also used during header processing
//   (x-envoy-upstream-canary) and for stats purposes.
type Metadata struct {
	// Key is the reverse DNS filter name, e.g. com.acme.widget. The envoy.*
	// namespace is reserved for Envoy's built-in filters.
	FilterMetadata       map[string]*_struct.Struct `protobuf:"bytes,1,rep,name=filter_metadata,json=filterMetadata,proto3" json:"filter_metadata,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}                   `json:"-"`
	XXX_unrecognized     []byte                     `json:"-"`
	XXX_sizecache        int32                      `json:"-"`
}

func (m *Metadata) Reset()         { *m = Metadata{} }
func (m *Metadata) String() string { return proto.CompactTextString(m) }
func (*Metadata) ProtoMessage()    {}
func (*Metadata) Descriptor() ([]byte, []int) {
	return fileDescriptor_a7738c0f9e1bfff4, []int{2}
}

func (m *Metadata) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Metadata.Unmarshal(m, b)
}
func (m *Metadata) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Metadata.Marshal(b, m, deterministic)
}
func (m *Metadata) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Metadata.Merge(m, src)
}
func (m *Metadata) XXX_Size() int {
	return xxx_messageInfo_Metadata.Size(m)
}
func (m *Metadata) XXX_DiscardUnknown() {
	xxx_messageInfo_Metadata.DiscardUnknown(m)
}

var xxx_messageInfo_Metadata proto.InternalMessageInfo

func (m *Metadata) GetFilterMetadata() map[string]*_struct.Struct {
	if m != nil {
		return m.FilterMetadata
	}
	return nil
}

// Runtime derived uint32 with a default when not specified.
type RuntimeUInt32 struct {
	// Default value if runtime value is not available.
	DefaultValue uint32 `protobuf:"varint,2,opt,name=default_value,json=defaultValue,proto3" json:"default_value,omitempty"`
	// Runtime key to get value for comparison. This value is used if defined.
	RuntimeKey           string   `protobuf:"bytes,3,opt,name=runtime_key,json=runtimeKey,proto3" json:"runtime_key,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RuntimeUInt32) Reset()         { *m = RuntimeUInt32{} }
func (m *RuntimeUInt32) String() string { return proto.CompactTextString(m) }
func (*RuntimeUInt32) ProtoMessage()    {}
func (*RuntimeUInt32) Descriptor() ([]byte, []int) {
	return fileDescriptor_a7738c0f9e1bfff4, []int{3}
}

func (m *RuntimeUInt32) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RuntimeUInt32.Unmarshal(m, b)
}
func (m *RuntimeUInt32) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RuntimeUInt32.Marshal(b, m, deterministic)
}
func (m *RuntimeUInt32) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RuntimeUInt32.Merge(m, src)
}
func (m *RuntimeUInt32) XXX_Size() int {
	return xxx_messageInfo_RuntimeUInt32.Size(m)
}
func (m *RuntimeUInt32) XXX_DiscardUnknown() {
	xxx_messageInfo_RuntimeUInt32.DiscardUnknown(m)
}

var xxx_messageInfo_RuntimeUInt32 proto.InternalMessageInfo

func (m *RuntimeUInt32) GetDefaultValue() uint32 {
	if m != nil {
		return m.DefaultValue
	}
	return 0
}

func (m *RuntimeUInt32) GetRuntimeKey() string {
	if m != nil {
		return m.RuntimeKey
	}
	return ""
}

// Header name/value pair.
type HeaderValue struct {
	// Header name.
	Key string `protobuf:"bytes,1,opt,name=key,proto3" json:"key,omitempty"`
	// Header value.
	//
	// The same :ref:`format specifier <config_access_log_format>` as used for
	// :ref:`HTTP access logging <config_access_log>` applies here, however
	// unknown header values are replaced with the empty string instead of `-`.
	Value                string   `protobuf:"bytes,2,opt,name=value,proto3" json:"value,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *HeaderValue) Reset()         { *m = HeaderValue{} }
func (m *HeaderValue) String() string { return proto.CompactTextString(m) }
func (*HeaderValue) ProtoMessage()    {}
func (*HeaderValue) Descriptor() ([]byte, []int) {
	return fileDescriptor_a7738c0f9e1bfff4, []int{4}
}

func (m *HeaderValue) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HeaderValue.Unmarshal(m, b)
}
func (m *HeaderValue) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HeaderValue.Marshal(b, m, deterministic)
}
func (m *HeaderValue) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HeaderValue.Merge(m, src)
}
func (m *HeaderValue) XXX_Size() int {
	return xxx_messageInfo_HeaderValue.Size(m)
}
func (m *HeaderValue) XXX_DiscardUnknown() {
	xxx_messageInfo_HeaderValue.DiscardUnknown(m)
}

var xxx_messageInfo_HeaderValue proto.InternalMessageInfo

func (m *HeaderValue) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func (m *HeaderValue) GetValue() string {
	if m != nil {
		return m.Value
	}
	return ""
}

// Header name/value pair plus option to control append behavior.
type HeaderValueOption struct {
	// Header name/value pair that this option applies to.
	Header *HeaderValue `protobuf:"bytes,1,opt,name=header,proto3" json:"header,omitempty"`
	// Should the value be appended? If true (default), the value is appended to
	// existing values.
	Append               *wrappers.BoolValue `protobuf:"bytes,2,opt,name=append,proto3" json:"append,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *HeaderValueOption) Reset()         { *m = HeaderValueOption{} }
func (m *HeaderValueOption) String() string { return proto.CompactTextString(m) }
func (*HeaderValueOption) ProtoMessage()    {}
func (*HeaderValueOption) Descriptor() ([]byte, []int) {
	return fileDescriptor_a7738c0f9e1bfff4, []int{5}
}

func (m *HeaderValueOption) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_HeaderValueOption.Unmarshal(m, b)
}
func (m *HeaderValueOption) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_HeaderValueOption.Marshal(b, m, deterministic)
}
func (m *HeaderValueOption) XXX_Merge(src proto.Message) {
	xxx_messageInfo_HeaderValueOption.Merge(m, src)
}
func (m *HeaderValueOption) XXX_Size() int {
	return xxx_messageInfo_HeaderValueOption.Size(m)
}
func (m *HeaderValueOption) XXX_DiscardUnknown() {
	xxx_messageInfo_HeaderValueOption.DiscardUnknown(m)
}

var xxx_messageInfo_HeaderValueOption proto.InternalMessageInfo

func (m *HeaderValueOption) GetHeader() *HeaderValue {
	if m != nil {
		return m.Header
	}
	return nil
}

func (m *HeaderValueOption) GetAppend() *wrappers.BoolValue {
	if m != nil {
		return m.Append
	}
	return nil
}

// Data source consisting of either a file or an inline value.
type DataSource struct {
	// Types that are valid to be assigned to Specifier:
	//	*DataSource_Filename
	//	*DataSource_InlineBytes
	//	*DataSource_InlineString
	Specifier            isDataSource_Specifier `protobuf_oneof:"specifier"`
	XXX_NoUnkeyedLiteral struct{}               `json:"-"`
	XXX_unrecognized     []byte                 `json:"-"`
	XXX_sizecache        int32                  `json:"-"`
}

func (m *DataSource) Reset()         { *m = DataSource{} }
func (m *DataSource) String() string { return proto.CompactTextString(m) }
func (*DataSource) ProtoMessage()    {}
func (*DataSource) Descriptor() ([]byte, []int) {
	return fileDescriptor_a7738c0f9e1bfff4, []int{6}
}

func (m *DataSource) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DataSource.Unmarshal(m, b)
}
func (m *DataSource) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DataSource.Marshal(b, m, deterministic)
}
func (m *DataSource) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DataSource.Merge(m, src)
}
func (m *DataSource) XXX_Size() int {
	return xxx_messageInfo_DataSource.Size(m)
}
func (m *DataSource) XXX_DiscardUnknown() {
	xxx_messageInfo_DataSource.DiscardUnknown(m)
}

var xxx_messageInfo_DataSource proto.InternalMessageInfo

type isDataSource_Specifier interface {
	isDataSource_Specifier()
}

type DataSource_Filename struct {
	Filename string `protobuf:"bytes,1,opt,name=filename,proto3,oneof"`
}

type DataSource_InlineBytes struct {
	InlineBytes []byte `protobuf:"bytes,2,opt,name=inline_bytes,json=inlineBytes,proto3,oneof"`
}

type DataSource_InlineString struct {
	InlineString string `protobuf:"bytes,3,opt,name=inline_string,json=inlineString,proto3,oneof"`
}

func (*DataSource_Filename) isDataSource_Specifier() {}

func (*DataSource_InlineBytes) isDataSource_Specifier() {}

func (*DataSource_InlineString) isDataSource_Specifier() {}

func (m *DataSource) GetSpecifier() isDataSource_Specifier {
	if m != nil {
		return m.Specifier
	}
	return nil
}

func (m *DataSource) GetFilename() string {
	if x, ok := m.GetSpecifier().(*DataSource_Filename); ok {
		return x.Filename
	}
	return ""
}

func (m *DataSource) GetInlineBytes() []byte {
	if x, ok := m.GetSpecifier().(*DataSource_InlineBytes); ok {
		return x.InlineBytes
	}
	return nil
}

func (m *DataSource) GetInlineString() string {
	if x, ok := m.GetSpecifier().(*DataSource_InlineString); ok {
		return x.InlineString
	}
	return ""
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*DataSource) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _DataSource_OneofMarshaler, _DataSource_OneofUnmarshaler, _DataSource_OneofSizer, []interface{}{
		(*DataSource_Filename)(nil),
		(*DataSource_InlineBytes)(nil),
		(*DataSource_InlineString)(nil),
	}
}

func _DataSource_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*DataSource)
	// specifier
	switch x := m.Specifier.(type) {
	case *DataSource_Filename:
		b.EncodeVarint(1<<3 | proto.WireBytes)
		b.EncodeStringBytes(x.Filename)
	case *DataSource_InlineBytes:
		b.EncodeVarint(2<<3 | proto.WireBytes)
		b.EncodeRawBytes(x.InlineBytes)
	case *DataSource_InlineString:
		b.EncodeVarint(3<<3 | proto.WireBytes)
		b.EncodeStringBytes(x.InlineString)
	case nil:
	default:
		return fmt.Errorf("DataSource.Specifier has unexpected type %T", x)
	}
	return nil
}

func _DataSource_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*DataSource)
	switch tag {
	case 1: // specifier.filename
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Specifier = &DataSource_Filename{x}
		return true, err
	case 2: // specifier.inline_bytes
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeRawBytes(true)
		m.Specifier = &DataSource_InlineBytes{x}
		return true, err
	case 3: // specifier.inline_string
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeStringBytes()
		m.Specifier = &DataSource_InlineString{x}
		return true, err
	default:
		return false, nil
	}
}

func _DataSource_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*DataSource)
	// specifier
	switch x := m.Specifier.(type) {
	case *DataSource_Filename:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(len(x.Filename)))
		n += len(x.Filename)
	case *DataSource_InlineBytes:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(len(x.InlineBytes)))
		n += len(x.InlineBytes)
	case *DataSource_InlineString:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(len(x.InlineString)))
		n += len(x.InlineString)
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

// Configuration for transport socket in :ref:`listeners <config_listeners>` and
// :ref:`clusters <config_cluster_manager_cluster>`. If the configuration is
// empty, a default transport socket implementation and configuration will be
// chosen based on the platform and existence of tls_context.
type TransportSocket struct {
	// The name of the transport socket to instantiate. The name must match a supported transport
	// socket implementation.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Implementation specific configuration which depends on the implementation being instantiated.
	// See the supported transport socket implementations for further documentation.
	Config               *_struct.Struct `protobuf:"bytes,2,opt,name=config,proto3" json:"config,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *TransportSocket) Reset()         { *m = TransportSocket{} }
func (m *TransportSocket) String() string { return proto.CompactTextString(m) }
func (*TransportSocket) ProtoMessage()    {}
func (*TransportSocket) Descriptor() ([]byte, []int) {
	return fileDescriptor_a7738c0f9e1bfff4, []int{7}
}

func (m *TransportSocket) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_TransportSocket.Unmarshal(m, b)
}
func (m *TransportSocket) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_TransportSocket.Marshal(b, m, deterministic)
}
func (m *TransportSocket) XXX_Merge(src proto.Message) {
	xxx_messageInfo_TransportSocket.Merge(m, src)
}
func (m *TransportSocket) XXX_Size() int {
	return xxx_messageInfo_TransportSocket.Size(m)
}
func (m *TransportSocket) XXX_DiscardUnknown() {
	xxx_messageInfo_TransportSocket.DiscardUnknown(m)
}

var xxx_messageInfo_TransportSocket proto.InternalMessageInfo

func (m *TransportSocket) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *TransportSocket) GetConfig() *_struct.Struct {
	if m != nil {
		return m.Config
	}
	return nil
}

// Generic socket option message. This would be used to set socket options that
// might not exist in upstream kernels or precompiled Envoy binaries.
type SocketOption struct {
	// An optional name to give this socket option for debugging, etc.
	// Uniqueness is not required and no special meaning is assumed.
	Description string `protobuf:"bytes,1,opt,name=description,proto3" json:"description,omitempty"`
	// Corresponding to the level value passed to setsockopt, such as IPPROTO_TCP
	Level int64 `protobuf:"varint,2,opt,name=level,proto3" json:"level,omitempty"`
	// The numeric name as passed to setsockopt
	Name int64 `protobuf:"varint,3,opt,name=name,proto3" json:"name,omitempty"`
	// Types that are valid to be assigned to Value:
	//	*SocketOption_IntValue
	//	*SocketOption_BufValue
	Value isSocketOption_Value `protobuf_oneof:"value"`
	// The state in which the option will be applied. When used in BindConfig
	// STATE_PREBIND is currently the only valid value.
	State                SocketOption_SocketState `protobuf:"varint,6,opt,name=state,proto3,enum=envoy.api.v2.core.SocketOption_SocketState" json:"state,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                 `json:"-"`
	XXX_unrecognized     []byte                   `json:"-"`
	XXX_sizecache        int32                    `json:"-"`
}

func (m *SocketOption) Reset()         { *m = SocketOption{} }
func (m *SocketOption) String() string { return proto.CompactTextString(m) }
func (*SocketOption) ProtoMessage()    {}
func (*SocketOption) Descriptor() ([]byte, []int) {
	return fileDescriptor_a7738c0f9e1bfff4, []int{8}
}

func (m *SocketOption) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_SocketOption.Unmarshal(m, b)
}
func (m *SocketOption) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_SocketOption.Marshal(b, m, deterministic)
}
func (m *SocketOption) XXX_Merge(src proto.Message) {
	xxx_messageInfo_SocketOption.Merge(m, src)
}
func (m *SocketOption) XXX_Size() int {
	return xxx_messageInfo_SocketOption.Size(m)
}
func (m *SocketOption) XXX_DiscardUnknown() {
	xxx_messageInfo_SocketOption.DiscardUnknown(m)
}

var xxx_messageInfo_SocketOption proto.InternalMessageInfo

func (m *SocketOption) GetDescription() string {
	if m != nil {
		return m.Description
	}
	return ""
}

func (m *SocketOption) GetLevel() int64 {
	if m != nil {
		return m.Level
	}
	return 0
}

func (m *SocketOption) GetName() int64 {
	if m != nil {
		return m.Name
	}
	return 0
}

type isSocketOption_Value interface {
	isSocketOption_Value()
}

type SocketOption_IntValue struct {
	IntValue int64 `protobuf:"varint,4,opt,name=int_value,json=intValue,proto3,oneof"`
}

type SocketOption_BufValue struct {
	BufValue []byte `protobuf:"bytes,5,opt,name=buf_value,json=bufValue,proto3,oneof"`
}

func (*SocketOption_IntValue) isSocketOption_Value() {}

func (*SocketOption_BufValue) isSocketOption_Value() {}

func (m *SocketOption) GetValue() isSocketOption_Value {
	if m != nil {
		return m.Value
	}
	return nil
}

func (m *SocketOption) GetIntValue() int64 {
	if x, ok := m.GetValue().(*SocketOption_IntValue); ok {
		return x.IntValue
	}
	return 0
}

func (m *SocketOption) GetBufValue() []byte {
	if x, ok := m.GetValue().(*SocketOption_BufValue); ok {
		return x.BufValue
	}
	return nil
}

func (m *SocketOption) GetState() SocketOption_SocketState {
	if m != nil {
		return m.State
	}
	return SocketOption_STATE_PREBIND
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*SocketOption) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _SocketOption_OneofMarshaler, _SocketOption_OneofUnmarshaler, _SocketOption_OneofSizer, []interface{}{
		(*SocketOption_IntValue)(nil),
		(*SocketOption_BufValue)(nil),
	}
}

func _SocketOption_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*SocketOption)
	// value
	switch x := m.Value.(type) {
	case *SocketOption_IntValue:
		b.EncodeVarint(4<<3 | proto.WireVarint)
		b.EncodeVarint(uint64(x.IntValue))
	case *SocketOption_BufValue:
		b.EncodeVarint(5<<3 | proto.WireBytes)
		b.EncodeRawBytes(x.BufValue)
	case nil:
	default:
		return fmt.Errorf("SocketOption.Value has unexpected type %T", x)
	}
	return nil
}

func _SocketOption_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*SocketOption)
	switch tag {
	case 4: // value.int_value
		if wire != proto.WireVarint {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeVarint()
		m.Value = &SocketOption_IntValue{int64(x)}
		return true, err
	case 5: // value.buf_value
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		x, err := b.DecodeRawBytes(true)
		m.Value = &SocketOption_BufValue{x}
		return true, err
	default:
		return false, nil
	}
}

func _SocketOption_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*SocketOption)
	// value
	switch x := m.Value.(type) {
	case *SocketOption_IntValue:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(x.IntValue))
	case *SocketOption_BufValue:
		n += 1 // tag and wire
		n += proto.SizeVarint(uint64(len(x.BufValue)))
		n += len(x.BufValue)
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

func init() {
	proto.RegisterEnum("envoy.api.v2.core.RoutingPriority", RoutingPriority_name, RoutingPriority_value)
	proto.RegisterEnum("envoy.api.v2.core.RequestMethod", RequestMethod_name, RequestMethod_value)
	proto.RegisterEnum("envoy.api.v2.core.SocketOption_SocketState", SocketOption_SocketState_name, SocketOption_SocketState_value)
	proto.RegisterType((*Locality)(nil), "envoy.api.v2.core.Locality")
	proto.RegisterType((*Node)(nil), "envoy.api.v2.core.Node")
	proto.RegisterType((*Metadata)(nil), "envoy.api.v2.core.Metadata")
	proto.RegisterMapType((map[string]*_struct.Struct)(nil), "envoy.api.v2.core.Metadata.FilterMetadataEntry")
	proto.RegisterType((*RuntimeUInt32)(nil), "envoy.api.v2.core.RuntimeUInt32")
	proto.RegisterType((*HeaderValue)(nil), "envoy.api.v2.core.HeaderValue")
	proto.RegisterType((*HeaderValueOption)(nil), "envoy.api.v2.core.HeaderValueOption")
	proto.RegisterType((*DataSource)(nil), "envoy.api.v2.core.DataSource")
	proto.RegisterType((*TransportSocket)(nil), "envoy.api.v2.core.TransportSocket")
	proto.RegisterType((*SocketOption)(nil), "envoy.api.v2.core.SocketOption")
}

func init() { proto.RegisterFile("envoy/api/v2/core/base.proto", fileDescriptor_a7738c0f9e1bfff4) }

var fileDescriptor_a7738c0f9e1bfff4 = []byte{
	// 960 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x84, 0x54, 0xcf, 0x6e, 0xe3, 0xd4,
	0x17, 0xae, 0xe3, 0x24, 0x4d, 0x8e, 0x93, 0xd6, 0xbd, 0x53, 0xcd, 0xf4, 0xd7, 0x99, 0x56, 0x95,
	0x7f, 0x0b, 0xaa, 0x22, 0x6c, 0x94, 0x2e, 0x40, 0xac, 0xa8, 0x1b, 0xb7, 0x89, 0x68, 0x93, 0x60,
	0xbb, 0x03, 0xea, 0x26, 0x38, 0xf1, 0x4d, 0xe6, 0x6a, 0x5c, 0xdf, 0x70, 0x7d, 0x1d, 0x94, 0x59,
	0x22, 0x16, 0x08, 0x1e, 0x83, 0x0d, 0x12, 0x2f, 0x80, 0x58, 0x55, 0xe2, 0x01, 0x78, 0x07, 0x76,
	0xf3, 0x16, 0xe8, 0x5e, 0xdf, 0x74, 0x02, 0x8d, 0x60, 0x77, 0xce, 0x77, 0xbe, 0xef, 0xfc, 0xbb,
	0xc7, 0x86, 0x17, 0x38, 0x9d, 0xd3, 0x85, 0x13, 0xcd, 0x88, 0x33, 0x6f, 0x39, 0x63, 0xca, 0xb0,
	0x33, 0x8a, 0x32, 0x6c, 0xcf, 0x18, 0xe5, 0x14, 0xed, 0xc8, 0xa8, 0x1d, 0xcd, 0x88, 0x3d, 0x6f,
	0xd9, 0x22, 0xba, 0xff, 0x62, 0x4a, 0xe9, 0x34, 0xc1, 0x8e, 0x24, 0x8c, 0xf2, 0x89, 0x93, 0x71,
	0x96, 0x8f, 0x79, 0x21, 0xd8, 0x3f, 0xfc, 0x67, 0xf4, 0x1b, 0x16, 0xcd, 0x66, 0x98, 0x65, 0x2a,
	0xfe, 0x6c, 0x1e, 0x25, 0x24, 0x8e, 0x38, 0x76, 0x96, 0x86, 0x0a, 0xec, 0x4e, 0xe9, 0x94, 0x4a,
	0xd3, 0x11, 0x56, 0x81, 0x5a, 0x9f, 0x43, 0xed, 0x8a, 0x8e, 0xa3, 0x84, 0xf0, 0x05, 0x7a, 0x0a,
	0x55, 0x86, 0xa7, 0x84, 0xa6, 0x7b, 0xda, 0x91, 0x76, 0x5c, 0xf7, 0x95, 0x87, 0x10, 0x94, 0xdf,
	0xd0, 0x14, 0xef, 0x95, 0x24, 0x2a, 0x6d, 0xf4, 0x3f, 0xa8, 0x65, 0xf9, 0x68, 0x28, 0x71, 0x5d,
	0xe2, 0x9b, 0x59, 0x3e, 0xba, 0xa5, 0x29, 0xb6, 0x7e, 0xd7, 0xa0, 0xdc, 0xa3, 0x31, 0x46, 0x5b,
	0x50, 0x22, 0xb1, 0xca, 0x55, 0x22, 0x31, 0xda, 0x83, 0xcd, 0x71, 0x92, 0x67, 0x1c, 0x33, 0x95,
	0x6a, 0xe9, 0xa2, 0x53, 0xa8, 0xdd, 0x61, 0x1e, 0xc5, 0x11, 0x8f, 0x64, 0x36, 0xa3, 0xf5, 0xcc,
	0x2e, 0xe6, 0xb4, 0x97, 0x73, 0xda, 0x81, 0xdc, 0x82, 0xff, 0x40, 0x44, 0x1f, 0x41, 0x2d, 0x51,
	0xad, 0xef, 0x95, 0xa5, 0xe8, 0xb9, 0xfd, 0x68, 0x9b, 0xf6, 0x72, 0x3a, 0xff, 0x81, 0x8c, 0xfe,
	0x0f, 0xcd, 0x51, 0x4e, 0x92, 0x78, 0x38, 0xc7, 0x2c, 0x13, 0xe3, 0x56, 0x64, 0x37, 0x0d, 0x09,
	0xbe, 0x2c, 0x30, 0xeb, 0x5e, 0x83, 0xda, 0xf5, 0xb2, 0xd4, 0x97, 0xb0, 0x3d, 0x21, 0x09, 0xc7,
	0x6c, 0xf8, 0xd0, 0xa6, 0x76, 0xa4, 0x1f, 0x1b, 0x2d, 0x67, 0x4d, 0xc5, 0xa5, 0xca, 0xbe, 0x90,
	0x92, 0xa5, 0xeb, 0xa5, 0x9c, 0x2d, 0xfc, 0xad, 0xc9, 0xdf, 0xc0, 0xfd, 0x5b, 0x78, 0xb2, 0x86,
	0x86, 0x4c, 0xd0, 0x5f, 0xe3, 0x85, 0xda, 0x9d, 0x30, 0xd1, 0x07, 0x50, 0x99, 0x47, 0x49, 0x5e,
	0xbc, 0xc2, 0xbf, 0xec, 0xa7, 0x60, 0x7d, 0x52, 0xfa, 0x58, 0xb3, 0xbe, 0x82, 0xa6, 0x9f, 0xa7,
	0x9c, 0xdc, 0xe1, 0x9b, 0x6e, 0xca, 0x4f, 0x5b, 0x62, 0xf0, 0x18, 0x4f, 0xa2, 0x3c, 0xe1, 0xc3,
	0x77, 0xb9, 0x9a, 0x7e, 0x43, 0x81, 0x2f, 0x05, 0x86, 0x4e, 0xc0, 0x60, 0x85, 0x6a, 0x28, 0x5a,
	0x90, 0x8f, 0xeb, 0xd6, 0x7f, 0x7b, 0x7b, 0xaf, 0x97, 0x59, 0xe9, 0x48, 0xf3, 0x41, 0x45, 0x3f,
	0xc3, 0x0b, 0xeb, 0x53, 0x30, 0x3a, 0x38, 0x8a, 0x31, 0x2b, 0xa4, 0xcf, 0x57, 0xba, 0x5e, 0x95,
	0xc8, 0x01, 0x76, 0x57, 0x07, 0xa8, 0xab, 0x3e, 0xad, 0x1f, 0x35, 0xd8, 0x59, 0x49, 0xd1, 0x9f,
	0x71, 0x71, 0x71, 0x2e, 0x54, 0x5f, 0x49, 0x50, 0xe6, 0x32, 0x5a, 0x87, 0x6b, 0xd6, 0xbc, 0xa2,
	0x72, 0x41, 0xd4, 0xaa, 0xfc, 0xa0, 0x95, 0x4c, 0xcd, 0x57, 0x4a, 0xd4, 0x82, 0xaa, 0xf8, 0x30,
	0xd2, 0x58, 0x6d, 0x6c, 0xff, 0xd1, 0xc6, 0x5c, 0x4a, 0x13, 0xa9, 0xf7, 0x15, 0xd3, 0xfa, 0x45,
	0x03, 0x68, 0x47, 0x3c, 0x0a, 0x68, 0xce, 0xc6, 0x18, 0xbd, 0x07, 0xb5, 0x09, 0x49, 0x70, 0x1a,
	0xdd, 0xe1, 0x47, 0x43, 0x75, 0x36, 0xfc, 0x87, 0x20, 0xb2, 0xa1, 0x41, 0xd2, 0x84, 0xa4, 0x78,
	0x38, 0x5a, 0x70, 0x9c, 0xc9, 0x8a, 0x0d, 0x45, 0x7e, 0x53, 0x32, 0x05, 0xd9, 0x28, 0x08, 0xae,
	0x88, 0xa3, 0x0f, 0xa1, 0xa9, 0xf8, 0x19, 0x67, 0x24, 0x9d, 0x3e, 0xda, 0x72, 0x67, 0xc3, 0x57,
	0x19, 0x03, 0x49, 0x70, 0x11, 0xd4, 0xb3, 0x19, 0x1e, 0x93, 0x09, 0xc1, 0x0c, 0x55, 0x7e, 0x7d,
	0x7b, 0xaf, 0x6b, 0x56, 0x04, 0xdb, 0x21, 0x8b, 0xd2, 0x6c, 0x46, 0x19, 0x0f, 0xe8, 0xf8, 0x35,
	0xe6, 0xe8, 0x00, 0xca, 0x6b, 0xbb, 0xf5, 0x25, 0x8c, 0x1c, 0xa8, 0x8e, 0x69, 0x3a, 0x21, 0xd3,
	0xff, 0xba, 0x22, 0x45, 0xb3, 0xfe, 0x28, 0x41, 0xa3, 0x48, 0xad, 0x5e, 0xe6, 0x08, 0x8c, 0x18,
	0x67, 0x63, 0x46, 0xa4, 0xab, 0x0e, 0x74, 0x15, 0x12, 0xef, 0x9c, 0xe0, 0x39, 0x4e, 0x64, 0x09,
	0xdd, 0x2f, 0x1c, 0xf1, 0x0f, 0x91, 0x8d, 0xe9, 0x12, 0x2c, 0xba, 0x39, 0x80, 0x3a, 0x49, 0x97,
	0xa7, 0x28, 0xbe, 0x60, 0x5d, 0x2c, 0x95, 0xa4, 0xea, 0x10, 0x0f, 0xa0, 0x3e, 0xca, 0x27, 0x2a,
	0x2c, 0x3e, 0xd1, 0x86, 0x08, 0x8f, 0xf2, 0x49, 0x11, 0xfe, 0x02, 0x2a, 0x19, 0x8f, 0x38, 0xde,
	0xab, 0x1e, 0x69, 0xc7, 0x5b, 0xad, 0xf7, 0xd7, 0x9c, 0xc8, 0x6a, 0xe7, 0xca, 0x09, 0x84, 0xc4,
	0xdd, 0x7d, 0x77, 0x2f, 0xd2, 0xfa, 0x56, 0x5e, 0x4e, 0x91, 0xcf, 0xba, 0x02, 0x63, 0x85, 0x8b,
	0x76, 0xa0, 0x19, 0x84, 0x67, 0xa1, 0x37, 0x1c, 0xf8, 0x9e, 0xdb, 0xed, 0xb5, 0xcd, 0x0d, 0xb4,
	0x0d, 0x46, 0x01, 0xb9, 0xfd, 0x9b, 0x5e, 0xdb, 0xd4, 0xd0, 0x13, 0xd8, 0x2e, 0x80, 0xab, 0x6e,
	0x10, 0x7a, 0xbd, 0x6e, 0xef, 0xd2, 0x2c, 0xed, 0x97, 0xbf, 0xff, 0xe9, 0x70, 0xc3, 0xdd, 0x52,
	0x67, 0xaf, 0x1e, 0xed, 0xe4, 0x18, 0xb6, 0x7d, 0x9a, 0x73, 0x92, 0x4e, 0x07, 0x8c, 0x50, 0x26,
	0xfe, 0x47, 0x06, 0x6c, 0xb6, 0xbd, 0x8b, 0xb3, 0x9b, 0xab, 0xd0, 0xdc, 0x40, 0x35, 0x28, 0x77,
	0xba, 0x97, 0x1d, 0x53, 0x3b, 0xf9, 0x4e, 0x83, 0xa6, 0x8f, 0xbf, 0xce, 0x71, 0xc6, 0xaf, 0x31,
	0x7f, 0x45, 0x63, 0xf4, 0x14, 0xd0, 0xb5, 0x17, 0x76, 0xfa, 0xed, 0xe1, 0x4d, 0x2f, 0x18, 0x78,
	0xe7, 0xdd, 0x8b, 0xae, 0x27, 0xfa, 0xd9, 0x04, 0xfd, 0xd2, 0x0b, 0x4d, 0x4d, 0x8a, 0xbd, 0xb3,
	0xb6, 0x59, 0x12, 0xd6, 0xa0, 0x1f, 0x84, 0xa6, 0x2e, 0x82, 0x83, 0x9b, 0xd0, 0x2c, 0x23, 0x80,
	0x6a, 0xdb, 0xbb, 0xf2, 0x42, 0xcf, 0xac, 0x88, 0x92, 0xe7, 0xfd, 0x5e, 0xcf, 0x3b, 0x0f, 0xcd,
	0xaa, 0x70, 0xfa, 0x83, 0xb0, 0xdb, 0xef, 0x05, 0xe6, 0x26, 0xaa, 0x43, 0x25, 0xf4, 0xcf, 0xce,
	0x3d, 0xb3, 0xa6, 0x06, 0x80, 0x9f, 0xff, 0x3c, 0xd4, 0x6e, 0xcb, 0x62, 0xa1, 0xa3, 0xaa, 0xbc,
	0x93, 0xd3, 0xbf, 0x02, 0x00, 0x00, 0xff, 0xff, 0xd1, 0xa8, 0x81, 0x8e, 0xd4, 0x06, 0x00, 0x00,
}
