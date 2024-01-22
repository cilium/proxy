// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: cilium/api/bpf_metadata.proto

package cilium

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"google.golang.org/protobuf/types/known/anypb"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = anypb.Any{}
	_ = sort.Sort
)

// Validate checks the field values on BpfMetadata with the rules defined in
// the proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *BpfMetadata) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on BpfMetadata with the rules defined in
// the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in BpfMetadataMultiError, or
// nil if none found.
func (m *BpfMetadata) ValidateAll() error {
	return m.validate(true)
}

func (m *BpfMetadata) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	// no validation rules for BpfRoot

	// no validation rules for IsIngress

	// no validation rules for UseOriginalSourceAddress

	// no validation rules for IsL7Lb

	// no validation rules for Ipv4SourceAddress

	// no validation rules for Ipv6SourceAddress

	// no validation rules for EnforcePolicyOnL7Lb

	// no validation rules for ProxyId

	// no validation rules for EnableReusePort

	if len(errors) > 0 {
		return BpfMetadataMultiError(errors)
	}

	return nil
}

// BpfMetadataMultiError is an error wrapping multiple validation errors
// returned by BpfMetadata.ValidateAll() if the designated constraints aren't met.
type BpfMetadataMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m BpfMetadataMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m BpfMetadataMultiError) AllErrors() []error { return m }

// BpfMetadataValidationError is the validation error returned by
// BpfMetadata.Validate if the designated constraints aren't met.
type BpfMetadataValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e BpfMetadataValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e BpfMetadataValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e BpfMetadataValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e BpfMetadataValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e BpfMetadataValidationError) ErrorName() string { return "BpfMetadataValidationError" }

// Error satisfies the builtin error interface
func (e BpfMetadataValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sBpfMetadata.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = BpfMetadataValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = BpfMetadataValidationError{}
