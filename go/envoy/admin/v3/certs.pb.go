// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.25.0
// 	protoc        v3.14.0
// source: envoy/admin/v3/certs.proto

package envoy_admin_v3

import (
	_ "github.com/cncf/udpa/go/udpa/annotations"
	proto "github.com/golang/protobuf/proto"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
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

// Proto representation of certificate details. Admin endpoint uses this wrapper for `/certs` to
// display certificate information. See :ref:`/certs <operations_admin_interface_certs>` for more
// information.
type Certificates struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// List of certificates known to an Envoy.
	Certificates []*Certificate `protobuf:"bytes,1,rep,name=certificates,proto3" json:"certificates,omitempty"`
}

func (x *Certificates) Reset() {
	*x = Certificates{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_admin_v3_certs_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Certificates) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Certificates) ProtoMessage() {}

func (x *Certificates) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_admin_v3_certs_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Certificates.ProtoReflect.Descriptor instead.
func (*Certificates) Descriptor() ([]byte, []int) {
	return file_envoy_admin_v3_certs_proto_rawDescGZIP(), []int{0}
}

func (x *Certificates) GetCertificates() []*Certificate {
	if x != nil {
		return x.Certificates
	}
	return nil
}

type Certificate struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Details of CA certificate.
	CaCert []*CertificateDetails `protobuf:"bytes,1,rep,name=ca_cert,json=caCert,proto3" json:"ca_cert,omitempty"`
	// Details of Certificate Chain
	CertChain []*CertificateDetails `protobuf:"bytes,2,rep,name=cert_chain,json=certChain,proto3" json:"cert_chain,omitempty"`
}

func (x *Certificate) Reset() {
	*x = Certificate{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_admin_v3_certs_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Certificate) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Certificate) ProtoMessage() {}

func (x *Certificate) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_admin_v3_certs_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Certificate.ProtoReflect.Descriptor instead.
func (*Certificate) Descriptor() ([]byte, []int) {
	return file_envoy_admin_v3_certs_proto_rawDescGZIP(), []int{1}
}

func (x *Certificate) GetCaCert() []*CertificateDetails {
	if x != nil {
		return x.CaCert
	}
	return nil
}

func (x *Certificate) GetCertChain() []*CertificateDetails {
	if x != nil {
		return x.CertChain
	}
	return nil
}

// [#next-free-field: 8]
type CertificateDetails struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Path of the certificate.
	Path string `protobuf:"bytes,1,opt,name=path,proto3" json:"path,omitempty"`
	// Certificate Serial Number.
	SerialNumber string `protobuf:"bytes,2,opt,name=serial_number,json=serialNumber,proto3" json:"serial_number,omitempty"`
	// List of Subject Alternate names.
	SubjectAltNames []*SubjectAlternateName `protobuf:"bytes,3,rep,name=subject_alt_names,json=subjectAltNames,proto3" json:"subject_alt_names,omitempty"`
	// Minimum of days until expiration of certificate and it's chain.
	DaysUntilExpiration uint64 `protobuf:"varint,4,opt,name=days_until_expiration,json=daysUntilExpiration,proto3" json:"days_until_expiration,omitempty"`
	// Indicates the time from which the certificate is valid.
	ValidFrom *timestamppb.Timestamp `protobuf:"bytes,5,opt,name=valid_from,json=validFrom,proto3" json:"valid_from,omitempty"`
	// Indicates the time at which the certificate expires.
	ExpirationTime *timestamppb.Timestamp `protobuf:"bytes,6,opt,name=expiration_time,json=expirationTime,proto3" json:"expiration_time,omitempty"`
	// Details related to the OCSP response associated with this certificate, if any.
	OcspDetails *CertificateDetails_OcspDetails `protobuf:"bytes,7,opt,name=ocsp_details,json=ocspDetails,proto3" json:"ocsp_details,omitempty"`
}

func (x *CertificateDetails) Reset() {
	*x = CertificateDetails{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_admin_v3_certs_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CertificateDetails) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CertificateDetails) ProtoMessage() {}

func (x *CertificateDetails) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_admin_v3_certs_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CertificateDetails.ProtoReflect.Descriptor instead.
func (*CertificateDetails) Descriptor() ([]byte, []int) {
	return file_envoy_admin_v3_certs_proto_rawDescGZIP(), []int{2}
}

func (x *CertificateDetails) GetPath() string {
	if x != nil {
		return x.Path
	}
	return ""
}

func (x *CertificateDetails) GetSerialNumber() string {
	if x != nil {
		return x.SerialNumber
	}
	return ""
}

func (x *CertificateDetails) GetSubjectAltNames() []*SubjectAlternateName {
	if x != nil {
		return x.SubjectAltNames
	}
	return nil
}

func (x *CertificateDetails) GetDaysUntilExpiration() uint64 {
	if x != nil {
		return x.DaysUntilExpiration
	}
	return 0
}

func (x *CertificateDetails) GetValidFrom() *timestamppb.Timestamp {
	if x != nil {
		return x.ValidFrom
	}
	return nil
}

func (x *CertificateDetails) GetExpirationTime() *timestamppb.Timestamp {
	if x != nil {
		return x.ExpirationTime
	}
	return nil
}

func (x *CertificateDetails) GetOcspDetails() *CertificateDetails_OcspDetails {
	if x != nil {
		return x.OcspDetails
	}
	return nil
}

type SubjectAlternateName struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Subject Alternate Name.
	//
	// Types that are assignable to Name:
	//	*SubjectAlternateName_Dns
	//	*SubjectAlternateName_Uri
	//	*SubjectAlternateName_IpAddress
	Name isSubjectAlternateName_Name `protobuf_oneof:"name"`
}

func (x *SubjectAlternateName) Reset() {
	*x = SubjectAlternateName{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_admin_v3_certs_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *SubjectAlternateName) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*SubjectAlternateName) ProtoMessage() {}

func (x *SubjectAlternateName) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_admin_v3_certs_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use SubjectAlternateName.ProtoReflect.Descriptor instead.
func (*SubjectAlternateName) Descriptor() ([]byte, []int) {
	return file_envoy_admin_v3_certs_proto_rawDescGZIP(), []int{3}
}

func (m *SubjectAlternateName) GetName() isSubjectAlternateName_Name {
	if m != nil {
		return m.Name
	}
	return nil
}

func (x *SubjectAlternateName) GetDns() string {
	if x, ok := x.GetName().(*SubjectAlternateName_Dns); ok {
		return x.Dns
	}
	return ""
}

func (x *SubjectAlternateName) GetUri() string {
	if x, ok := x.GetName().(*SubjectAlternateName_Uri); ok {
		return x.Uri
	}
	return ""
}

func (x *SubjectAlternateName) GetIpAddress() string {
	if x, ok := x.GetName().(*SubjectAlternateName_IpAddress); ok {
		return x.IpAddress
	}
	return ""
}

type isSubjectAlternateName_Name interface {
	isSubjectAlternateName_Name()
}

type SubjectAlternateName_Dns struct {
	Dns string `protobuf:"bytes,1,opt,name=dns,proto3,oneof"`
}

type SubjectAlternateName_Uri struct {
	Uri string `protobuf:"bytes,2,opt,name=uri,proto3,oneof"`
}

type SubjectAlternateName_IpAddress struct {
	IpAddress string `protobuf:"bytes,3,opt,name=ip_address,json=ipAddress,proto3,oneof"`
}

func (*SubjectAlternateName_Dns) isSubjectAlternateName_Name() {}

func (*SubjectAlternateName_Uri) isSubjectAlternateName_Name() {}

func (*SubjectAlternateName_IpAddress) isSubjectAlternateName_Name() {}

type CertificateDetails_OcspDetails struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Indicates the time from which the OCSP response is valid.
	ValidFrom *timestamppb.Timestamp `protobuf:"bytes,1,opt,name=valid_from,json=validFrom,proto3" json:"valid_from,omitempty"`
	// Indicates the time at which the OCSP response expires.
	Expiration *timestamppb.Timestamp `protobuf:"bytes,2,opt,name=expiration,proto3" json:"expiration,omitempty"`
}

func (x *CertificateDetails_OcspDetails) Reset() {
	*x = CertificateDetails_OcspDetails{}
	if protoimpl.UnsafeEnabled {
		mi := &file_envoy_admin_v3_certs_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CertificateDetails_OcspDetails) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CertificateDetails_OcspDetails) ProtoMessage() {}

func (x *CertificateDetails_OcspDetails) ProtoReflect() protoreflect.Message {
	mi := &file_envoy_admin_v3_certs_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CertificateDetails_OcspDetails.ProtoReflect.Descriptor instead.
func (*CertificateDetails_OcspDetails) Descriptor() ([]byte, []int) {
	return file_envoy_admin_v3_certs_proto_rawDescGZIP(), []int{2, 0}
}

func (x *CertificateDetails_OcspDetails) GetValidFrom() *timestamppb.Timestamp {
	if x != nil {
		return x.ValidFrom
	}
	return nil
}

func (x *CertificateDetails_OcspDetails) GetExpiration() *timestamppb.Timestamp {
	if x != nil {
		return x.Expiration
	}
	return nil
}

var File_envoy_admin_v3_certs_proto protoreflect.FileDescriptor

var file_envoy_admin_v3_certs_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2f, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2f, 0x76, 0x33,
	0x2f, 0x63, 0x65, 0x72, 0x74, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0e, 0x65, 0x6e,
	0x76, 0x6f, 0x79, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x33, 0x1a, 0x1f, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1d, 0x75,
	0x64, 0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f,
	0x73, 0x74, 0x61, 0x74, 0x75, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x21, 0x75, 0x64,
	0x70, 0x61, 0x2f, 0x61, 0x6e, 0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x76,
	0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x78, 0x0a, 0x0c, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x12,
	0x3f, 0x0a, 0x0c, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1b, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61, 0x64,
	0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x33, 0x2e, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61,
	0x74, 0x65, 0x52, 0x0c, 0x63, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73,
	0x3a, 0x27, 0x9a, 0xc5, 0x88, 0x1e, 0x22, 0x0a, 0x20, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61,
	0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x32, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x43, 0x65, 0x72,
	0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x73, 0x22, 0xb5, 0x01, 0x0a, 0x0b, 0x43, 0x65,
	0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x12, 0x3b, 0x0a, 0x07, 0x63, 0x61, 0x5f,
	0x63, 0x65, 0x72, 0x74, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x65, 0x6e, 0x76,
	0x6f, 0x79, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x33, 0x2e, 0x43, 0x65, 0x72, 0x74,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x52, 0x06,
	0x63, 0x61, 0x43, 0x65, 0x72, 0x74, 0x12, 0x41, 0x0a, 0x0a, 0x63, 0x65, 0x72, 0x74, 0x5f, 0x63,
	0x68, 0x61, 0x69, 0x6e, 0x18, 0x02, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x22, 0x2e, 0x65, 0x6e, 0x76,
	0x6f, 0x79, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x33, 0x2e, 0x43, 0x65, 0x72, 0x74,
	0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x52, 0x09,
	0x63, 0x65, 0x72, 0x74, 0x43, 0x68, 0x61, 0x69, 0x6e, 0x3a, 0x26, 0x9a, 0xc5, 0x88, 0x1e, 0x21,
	0x0a, 0x1f, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x32,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
	0x65, 0x22, 0xdc, 0x04, 0x0a, 0x12, 0x43, 0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74,
	0x65, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x12, 0x12, 0x0a, 0x04, 0x70, 0x61, 0x74, 0x68,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x70, 0x61, 0x74, 0x68, 0x12, 0x23, 0x0a, 0x0d,
	0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x5f, 0x6e, 0x75, 0x6d, 0x62, 0x65, 0x72, 0x18, 0x02, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x0c, 0x73, 0x65, 0x72, 0x69, 0x61, 0x6c, 0x4e, 0x75, 0x6d, 0x62, 0x65,
	0x72, 0x12, 0x50, 0x0a, 0x11, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x5f, 0x61, 0x6c, 0x74,
	0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x73, 0x18, 0x03, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x24, 0x2e, 0x65,
	0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x33, 0x2e, 0x53, 0x75,
	0x62, 0x6a, 0x65, 0x63, 0x74, 0x41, 0x6c, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x74, 0x65, 0x4e, 0x61,
	0x6d, 0x65, 0x52, 0x0f, 0x73, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x41, 0x6c, 0x74, 0x4e, 0x61,
	0x6d, 0x65, 0x73, 0x12, 0x32, 0x0a, 0x15, 0x64, 0x61, 0x79, 0x73, 0x5f, 0x75, 0x6e, 0x74, 0x69,
	0x6c, 0x5f, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x18, 0x04, 0x20, 0x01,
	0x28, 0x04, 0x52, 0x13, 0x64, 0x61, 0x79, 0x73, 0x55, 0x6e, 0x74, 0x69, 0x6c, 0x45, 0x78, 0x70,
	0x69, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x39, 0x0a, 0x0a, 0x76, 0x61, 0x6c, 0x69, 0x64,
	0x5f, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x05, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x46, 0x72,
	0x6f, 0x6d, 0x12, 0x43, 0x0a, 0x0f, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69,
	0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0e, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x54, 0x69, 0x6d, 0x65, 0x12, 0x51, 0x0a, 0x0c, 0x6f, 0x63, 0x73, 0x70, 0x5f,
	0x64, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2e, 0x2e,
	0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x33, 0x2e, 0x43,
	0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c,
	0x73, 0x2e, 0x4f, 0x63, 0x73, 0x70, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x52, 0x0b, 0x6f,
	0x63, 0x73, 0x70, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x1a, 0x84, 0x01, 0x0a, 0x0b, 0x4f,
	0x63, 0x73, 0x70, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73, 0x12, 0x39, 0x0a, 0x0a, 0x76, 0x61,
	0x6c, 0x69, 0x64, 0x5f, 0x66, 0x72, 0x6f, 0x6d, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x76, 0x61, 0x6c, 0x69,
	0x64, 0x46, 0x72, 0x6f, 0x6d, 0x12, 0x3a, 0x0a, 0x0a, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74,
	0x69, 0x6f, 0x6e, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65,
	0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x0a, 0x65, 0x78, 0x70, 0x69, 0x72, 0x61, 0x74, 0x69, 0x6f,
	0x6e, 0x3a, 0x2d, 0x9a, 0xc5, 0x88, 0x1e, 0x28, 0x0a, 0x26, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x2e,
	0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x32, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x43, 0x65,
	0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x44, 0x65, 0x74, 0x61, 0x69, 0x6c, 0x73,
	0x22, 0x98, 0x01, 0x0a, 0x14, 0x53, 0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x41, 0x6c, 0x74, 0x65,
	0x72, 0x6e, 0x61, 0x74, 0x65, 0x4e, 0x61, 0x6d, 0x65, 0x12, 0x12, 0x0a, 0x03, 0x64, 0x6e, 0x73,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x03, 0x64, 0x6e, 0x73, 0x12, 0x12, 0x0a,
	0x03, 0x75, 0x72, 0x69, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x03, 0x75, 0x72,
	0x69, 0x12, 0x1f, 0x0a, 0x0a, 0x69, 0x70, 0x5f, 0x61, 0x64, 0x64, 0x72, 0x65, 0x73, 0x73, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x09, 0x48, 0x00, 0x52, 0x09, 0x69, 0x70, 0x41, 0x64, 0x64, 0x72, 0x65,
	0x73, 0x73, 0x3a, 0x2f, 0x9a, 0xc5, 0x88, 0x1e, 0x2a, 0x0a, 0x28, 0x65, 0x6e, 0x76, 0x6f, 0x79,
	0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x32, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x2e, 0x53,
	0x75, 0x62, 0x6a, 0x65, 0x63, 0x74, 0x41, 0x6c, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x74, 0x65, 0x4e,
	0x61, 0x6d, 0x65, 0x42, 0x06, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x42, 0x34, 0x0a, 0x1c, 0x69,
	0x6f, 0x2e, 0x65, 0x6e, 0x76, 0x6f, 0x79, 0x70, 0x72, 0x6f, 0x78, 0x79, 0x2e, 0x65, 0x6e, 0x76,
	0x6f, 0x79, 0x2e, 0x61, 0x64, 0x6d, 0x69, 0x6e, 0x2e, 0x76, 0x33, 0x42, 0x0a, 0x43, 0x65, 0x72,
	0x74, 0x73, 0x50, 0x72, 0x6f, 0x74, 0x6f, 0x50, 0x01, 0xba, 0x80, 0xc8, 0xd1, 0x06, 0x02, 0x10,
	0x02, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_envoy_admin_v3_certs_proto_rawDescOnce sync.Once
	file_envoy_admin_v3_certs_proto_rawDescData = file_envoy_admin_v3_certs_proto_rawDesc
)

func file_envoy_admin_v3_certs_proto_rawDescGZIP() []byte {
	file_envoy_admin_v3_certs_proto_rawDescOnce.Do(func() {
		file_envoy_admin_v3_certs_proto_rawDescData = protoimpl.X.CompressGZIP(file_envoy_admin_v3_certs_proto_rawDescData)
	})
	return file_envoy_admin_v3_certs_proto_rawDescData
}

var file_envoy_admin_v3_certs_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_envoy_admin_v3_certs_proto_goTypes = []interface{}{
	(*Certificates)(nil),                   // 0: envoy.admin.v3.Certificates
	(*Certificate)(nil),                    // 1: envoy.admin.v3.Certificate
	(*CertificateDetails)(nil),             // 2: envoy.admin.v3.CertificateDetails
	(*SubjectAlternateName)(nil),           // 3: envoy.admin.v3.SubjectAlternateName
	(*CertificateDetails_OcspDetails)(nil), // 4: envoy.admin.v3.CertificateDetails.OcspDetails
	(*timestamppb.Timestamp)(nil),          // 5: google.protobuf.Timestamp
}
var file_envoy_admin_v3_certs_proto_depIdxs = []int32{
	1, // 0: envoy.admin.v3.Certificates.certificates:type_name -> envoy.admin.v3.Certificate
	2, // 1: envoy.admin.v3.Certificate.ca_cert:type_name -> envoy.admin.v3.CertificateDetails
	2, // 2: envoy.admin.v3.Certificate.cert_chain:type_name -> envoy.admin.v3.CertificateDetails
	3, // 3: envoy.admin.v3.CertificateDetails.subject_alt_names:type_name -> envoy.admin.v3.SubjectAlternateName
	5, // 4: envoy.admin.v3.CertificateDetails.valid_from:type_name -> google.protobuf.Timestamp
	5, // 5: envoy.admin.v3.CertificateDetails.expiration_time:type_name -> google.protobuf.Timestamp
	4, // 6: envoy.admin.v3.CertificateDetails.ocsp_details:type_name -> envoy.admin.v3.CertificateDetails.OcspDetails
	5, // 7: envoy.admin.v3.CertificateDetails.OcspDetails.valid_from:type_name -> google.protobuf.Timestamp
	5, // 8: envoy.admin.v3.CertificateDetails.OcspDetails.expiration:type_name -> google.protobuf.Timestamp
	9, // [9:9] is the sub-list for method output_type
	9, // [9:9] is the sub-list for method input_type
	9, // [9:9] is the sub-list for extension type_name
	9, // [9:9] is the sub-list for extension extendee
	0, // [0:9] is the sub-list for field type_name
}

func init() { file_envoy_admin_v3_certs_proto_init() }
func file_envoy_admin_v3_certs_proto_init() {
	if File_envoy_admin_v3_certs_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_envoy_admin_v3_certs_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Certificates); i {
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
		file_envoy_admin_v3_certs_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Certificate); i {
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
		file_envoy_admin_v3_certs_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CertificateDetails); i {
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
		file_envoy_admin_v3_certs_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*SubjectAlternateName); i {
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
		file_envoy_admin_v3_certs_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*CertificateDetails_OcspDetails); i {
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
	file_envoy_admin_v3_certs_proto_msgTypes[3].OneofWrappers = []interface{}{
		(*SubjectAlternateName_Dns)(nil),
		(*SubjectAlternateName_Uri)(nil),
		(*SubjectAlternateName_IpAddress)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_envoy_admin_v3_certs_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_envoy_admin_v3_certs_proto_goTypes,
		DependencyIndexes: file_envoy_admin_v3_certs_proto_depIdxs,
		MessageInfos:      file_envoy_admin_v3_certs_proto_msgTypes,
	}.Build()
	File_envoy_admin_v3_certs_proto = out.File
	file_envoy_admin_v3_certs_proto_rawDesc = nil
	file_envoy_admin_v3_certs_proto_goTypes = nil
	file_envoy_admin_v3_certs_proto_depIdxs = nil
}
