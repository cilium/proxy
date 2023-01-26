// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: envoy/extensions/filters/http/stateful_session/v3/stateful_session.proto

package stateful_sessionv3

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

// Validate checks the field values on StatefulSession with the rules defined
// in the proto definition for this message. If any rules are violated, the
// first error encountered is returned, or nil if there are no violations.
func (m *StatefulSession) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on StatefulSession with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// StatefulSessionMultiError, or nil if none found.
func (m *StatefulSession) ValidateAll() error {
	return m.validate(true)
}

func (m *StatefulSession) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if all {
		switch v := interface{}(m.GetSessionState()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, StatefulSessionValidationError{
					field:  "SessionState",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, StatefulSessionValidationError{
					field:  "SessionState",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetSessionState()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return StatefulSessionValidationError{
				field:  "SessionState",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return StatefulSessionMultiError(errors)
	}
	return nil
}

// StatefulSessionMultiError is an error wrapping multiple validation errors
// returned by StatefulSession.ValidateAll() if the designated constraints
// aren't met.
type StatefulSessionMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m StatefulSessionMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m StatefulSessionMultiError) AllErrors() []error { return m }

// StatefulSessionValidationError is the validation error returned by
// StatefulSession.Validate if the designated constraints aren't met.
type StatefulSessionValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e StatefulSessionValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e StatefulSessionValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e StatefulSessionValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e StatefulSessionValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e StatefulSessionValidationError) ErrorName() string { return "StatefulSessionValidationError" }

// Error satisfies the builtin error interface
func (e StatefulSessionValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sStatefulSession.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = StatefulSessionValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = StatefulSessionValidationError{}

// Validate checks the field values on StatefulSessionPerRoute with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *StatefulSessionPerRoute) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on StatefulSessionPerRoute with the
// rules defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// StatefulSessionPerRouteMultiError, or nil if none found.
func (m *StatefulSessionPerRoute) ValidateAll() error {
	return m.validate(true)
}

func (m *StatefulSessionPerRoute) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	switch m.Override.(type) {

	case *StatefulSessionPerRoute_Disabled:

		if m.GetDisabled() != true {
			err := StatefulSessionPerRouteValidationError{
				field:  "Disabled",
				reason: "value must equal true",
			}
			if !all {
				return err
			}
			errors = append(errors, err)
		}

	case *StatefulSessionPerRoute_StatefulSession:

		if all {
			switch v := interface{}(m.GetStatefulSession()).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, StatefulSessionPerRouteValidationError{
						field:  "StatefulSession",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, StatefulSessionPerRouteValidationError{
						field:  "StatefulSession",
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(m.GetStatefulSession()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return StatefulSessionPerRouteValidationError{
					field:  "StatefulSession",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	default:
		err := StatefulSessionPerRouteValidationError{
			field:  "Override",
			reason: "value is required",
		}
		if !all {
			return err
		}
		errors = append(errors, err)

	}

	if len(errors) > 0 {
		return StatefulSessionPerRouteMultiError(errors)
	}
	return nil
}

// StatefulSessionPerRouteMultiError is an error wrapping multiple validation
// errors returned by StatefulSessionPerRoute.ValidateAll() if the designated
// constraints aren't met.
type StatefulSessionPerRouteMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m StatefulSessionPerRouteMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m StatefulSessionPerRouteMultiError) AllErrors() []error { return m }

// StatefulSessionPerRouteValidationError is the validation error returned by
// StatefulSessionPerRoute.Validate if the designated constraints aren't met.
type StatefulSessionPerRouteValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e StatefulSessionPerRouteValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e StatefulSessionPerRouteValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e StatefulSessionPerRouteValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e StatefulSessionPerRouteValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e StatefulSessionPerRouteValidationError) ErrorName() string {
	return "StatefulSessionPerRouteValidationError"
}

// Error satisfies the builtin error interface
func (e StatefulSessionPerRouteValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sStatefulSessionPerRoute.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = StatefulSessionPerRouteValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = StatefulSessionPerRouteValidationError{}
