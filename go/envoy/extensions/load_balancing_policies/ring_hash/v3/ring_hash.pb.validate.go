// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/load_balancing_policies/ring_hash/v3/ring_hash.proto

package ring_hashv3

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

// Validate checks the field values on RingHash with the rules defined in the
// proto definition for this message. If any rules are violated, the first
// error encountered is returned, or nil if there are no violations.
func (m *RingHash) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on RingHash with the rules defined in
// the proto definition for this message. If any rules are violated, the
// result is a list of violation errors wrapped in RingHashMultiError, or nil
// if none found.
func (m *RingHash) ValidateAll() error {
	return m.validate(true)
}

func (m *RingHash) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if _, ok := RingHash_HashFunction_name[int32(m.GetHashFunction())]; !ok {
		err := RingHashValidationError{
			field:  "HashFunction",
			reason: "value must be one of the defined enum values",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	if wrapper := m.GetMinimumRingSize(); wrapper != nil {

		if wrapper.GetValue() > 8388608 {
			err := RingHashValidationError{
				field:  "MinimumRingSize",
				reason: "value must be less than or equal to 8388608",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	}

	if wrapper := m.GetMaximumRingSize(); wrapper != nil {

		if wrapper.GetValue() > 8388608 {
			err := RingHashValidationError{
				field:  "MaximumRingSize",
				reason: "value must be less than or equal to 8388608",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	}

	// no validation rules for UseHostnameForHashing

	if wrapper := m.GetHashBalanceFactor(); wrapper != nil {

		if wrapper.GetValue() < 100 {
			err := RingHashValidationError{
				field:  "HashBalanceFactor",
				reason: "value must be greater than or equal to 100",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	}

	if len(errors) > 0 {
		return RingHashMultiError(errors)
	}
	return nil
}

// RingHashMultiError is an error wrapping multiple validation errors returned
// by RingHash.ValidateAll() if the designated constraints aren't met.
type RingHashMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m RingHashMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m RingHashMultiError) AllErrors() []error { return m }

// RingHashValidationError is the validation error returned by
// RingHash.Validate if the designated constraints aren't met.
type RingHashValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e RingHashValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e RingHashValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e RingHashValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e RingHashValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e RingHashValidationError) ErrorName() string { return "RingHashValidationError" }

// Error satisfies the builtin error interface
func (e RingHashValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRingHash.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = RingHashValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = RingHashValidationError{}
