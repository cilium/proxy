// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: xds/type/matcher/v3/range.proto

package v3

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

// Validate checks the field values on Int64RangeMatcher with the rules defined
// in the proto definition for this message. If any rules are violated, the
// first error encountered is returned, or nil if there are no violations.
func (m *Int64RangeMatcher) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Int64RangeMatcher with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// Int64RangeMatcherMultiError, or nil if none found.
func (m *Int64RangeMatcher) ValidateAll() error {
	return m.validate(true)
}

func (m *Int64RangeMatcher) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	for idx, item := range m.GetRangeMatchers() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, Int64RangeMatcherValidationError{
						field:  fmt.Sprintf("RangeMatchers[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, Int64RangeMatcherValidationError{
						field:  fmt.Sprintf("RangeMatchers[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return Int64RangeMatcherValidationError{
					field:  fmt.Sprintf("RangeMatchers[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if len(errors) > 0 {
		return Int64RangeMatcherMultiError(errors)
	}

	return nil
}

// Int64RangeMatcherMultiError is an error wrapping multiple validation errors
// returned by Int64RangeMatcher.ValidateAll() if the designated constraints
// aren't met.
type Int64RangeMatcherMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m Int64RangeMatcherMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m Int64RangeMatcherMultiError) AllErrors() []error { return m }

// Int64RangeMatcherValidationError is the validation error returned by
// Int64RangeMatcher.Validate if the designated constraints aren't met.
type Int64RangeMatcherValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Int64RangeMatcherValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Int64RangeMatcherValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Int64RangeMatcherValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Int64RangeMatcherValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Int64RangeMatcherValidationError) ErrorName() string {
	return "Int64RangeMatcherValidationError"
}

// Error satisfies the builtin error interface
func (e Int64RangeMatcherValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sInt64RangeMatcher.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Int64RangeMatcherValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Int64RangeMatcherValidationError{}

// Validate checks the field values on Int32RangeMatcher with the rules defined
// in the proto definition for this message. If any rules are violated, the
// first error encountered is returned, or nil if there are no violations.
func (m *Int32RangeMatcher) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Int32RangeMatcher with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// Int32RangeMatcherMultiError, or nil if none found.
func (m *Int32RangeMatcher) ValidateAll() error {
	return m.validate(true)
}

func (m *Int32RangeMatcher) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	for idx, item := range m.GetRangeMatchers() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, Int32RangeMatcherValidationError{
						field:  fmt.Sprintf("RangeMatchers[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, Int32RangeMatcherValidationError{
						field:  fmt.Sprintf("RangeMatchers[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return Int32RangeMatcherValidationError{
					field:  fmt.Sprintf("RangeMatchers[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if len(errors) > 0 {
		return Int32RangeMatcherMultiError(errors)
	}

	return nil
}

// Int32RangeMatcherMultiError is an error wrapping multiple validation errors
// returned by Int32RangeMatcher.ValidateAll() if the designated constraints
// aren't met.
type Int32RangeMatcherMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m Int32RangeMatcherMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m Int32RangeMatcherMultiError) AllErrors() []error { return m }

// Int32RangeMatcherValidationError is the validation error returned by
// Int32RangeMatcher.Validate if the designated constraints aren't met.
type Int32RangeMatcherValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Int32RangeMatcherValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Int32RangeMatcherValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Int32RangeMatcherValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Int32RangeMatcherValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Int32RangeMatcherValidationError) ErrorName() string {
	return "Int32RangeMatcherValidationError"
}

// Error satisfies the builtin error interface
func (e Int32RangeMatcherValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sInt32RangeMatcher.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Int32RangeMatcherValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Int32RangeMatcherValidationError{}

// Validate checks the field values on DoubleRangeMatcher with the rules
// defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *DoubleRangeMatcher) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on DoubleRangeMatcher with the rules
// defined in the proto definition for this message. If any rules are
// violated, the result is a list of violation errors wrapped in
// DoubleRangeMatcherMultiError, or nil if none found.
func (m *DoubleRangeMatcher) ValidateAll() error {
	return m.validate(true)
}

func (m *DoubleRangeMatcher) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	for idx, item := range m.GetRangeMatchers() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, DoubleRangeMatcherValidationError{
						field:  fmt.Sprintf("RangeMatchers[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, DoubleRangeMatcherValidationError{
						field:  fmt.Sprintf("RangeMatchers[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return DoubleRangeMatcherValidationError{
					field:  fmt.Sprintf("RangeMatchers[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if len(errors) > 0 {
		return DoubleRangeMatcherMultiError(errors)
	}

	return nil
}

// DoubleRangeMatcherMultiError is an error wrapping multiple validation errors
// returned by DoubleRangeMatcher.ValidateAll() if the designated constraints
// aren't met.
type DoubleRangeMatcherMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m DoubleRangeMatcherMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m DoubleRangeMatcherMultiError) AllErrors() []error { return m }

// DoubleRangeMatcherValidationError is the validation error returned by
// DoubleRangeMatcher.Validate if the designated constraints aren't met.
type DoubleRangeMatcherValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e DoubleRangeMatcherValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e DoubleRangeMatcherValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e DoubleRangeMatcherValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e DoubleRangeMatcherValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e DoubleRangeMatcherValidationError) ErrorName() string {
	return "DoubleRangeMatcherValidationError"
}

// Error satisfies the builtin error interface
func (e DoubleRangeMatcherValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sDoubleRangeMatcher.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = DoubleRangeMatcherValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = DoubleRangeMatcherValidationError{}

// Validate checks the field values on Int64RangeMatcher_RangeMatcher with the
// rules defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *Int64RangeMatcher_RangeMatcher) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Int64RangeMatcher_RangeMatcher with
// the rules defined in the proto definition for this message. If any rules
// are violated, the result is a list of violation errors wrapped in
// Int64RangeMatcher_RangeMatcherMultiError, or nil if none found.
func (m *Int64RangeMatcher_RangeMatcher) ValidateAll() error {
	return m.validate(true)
}

func (m *Int64RangeMatcher_RangeMatcher) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(m.GetRanges()) < 1 {
		err := Int64RangeMatcher_RangeMatcherValidationError{
			field:  "Ranges",
			reason: "value must contain at least 1 item(s)",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	for idx, item := range m.GetRanges() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, Int64RangeMatcher_RangeMatcherValidationError{
						field:  fmt.Sprintf("Ranges[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, Int64RangeMatcher_RangeMatcherValidationError{
						field:  fmt.Sprintf("Ranges[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return Int64RangeMatcher_RangeMatcherValidationError{
					field:  fmt.Sprintf("Ranges[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if all {
		switch v := interface{}(m.GetOnMatch()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, Int64RangeMatcher_RangeMatcherValidationError{
					field:  "OnMatch",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, Int64RangeMatcher_RangeMatcherValidationError{
					field:  "OnMatch",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetOnMatch()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return Int64RangeMatcher_RangeMatcherValidationError{
				field:  "OnMatch",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return Int64RangeMatcher_RangeMatcherMultiError(errors)
	}

	return nil
}

// Int64RangeMatcher_RangeMatcherMultiError is an error wrapping multiple
// validation errors returned by Int64RangeMatcher_RangeMatcher.ValidateAll()
// if the designated constraints aren't met.
type Int64RangeMatcher_RangeMatcherMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m Int64RangeMatcher_RangeMatcherMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m Int64RangeMatcher_RangeMatcherMultiError) AllErrors() []error { return m }

// Int64RangeMatcher_RangeMatcherValidationError is the validation error
// returned by Int64RangeMatcher_RangeMatcher.Validate if the designated
// constraints aren't met.
type Int64RangeMatcher_RangeMatcherValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Int64RangeMatcher_RangeMatcherValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Int64RangeMatcher_RangeMatcherValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Int64RangeMatcher_RangeMatcherValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Int64RangeMatcher_RangeMatcherValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Int64RangeMatcher_RangeMatcherValidationError) ErrorName() string {
	return "Int64RangeMatcher_RangeMatcherValidationError"
}

// Error satisfies the builtin error interface
func (e Int64RangeMatcher_RangeMatcherValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sInt64RangeMatcher_RangeMatcher.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Int64RangeMatcher_RangeMatcherValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Int64RangeMatcher_RangeMatcherValidationError{}

// Validate checks the field values on Int32RangeMatcher_RangeMatcher with the
// rules defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *Int32RangeMatcher_RangeMatcher) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on Int32RangeMatcher_RangeMatcher with
// the rules defined in the proto definition for this message. If any rules
// are violated, the result is a list of violation errors wrapped in
// Int32RangeMatcher_RangeMatcherMultiError, or nil if none found.
func (m *Int32RangeMatcher_RangeMatcher) ValidateAll() error {
	return m.validate(true)
}

func (m *Int32RangeMatcher_RangeMatcher) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(m.GetRanges()) < 1 {
		err := Int32RangeMatcher_RangeMatcherValidationError{
			field:  "Ranges",
			reason: "value must contain at least 1 item(s)",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	for idx, item := range m.GetRanges() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, Int32RangeMatcher_RangeMatcherValidationError{
						field:  fmt.Sprintf("Ranges[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, Int32RangeMatcher_RangeMatcherValidationError{
						field:  fmt.Sprintf("Ranges[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return Int32RangeMatcher_RangeMatcherValidationError{
					field:  fmt.Sprintf("Ranges[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if all {
		switch v := interface{}(m.GetOnMatch()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, Int32RangeMatcher_RangeMatcherValidationError{
					field:  "OnMatch",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, Int32RangeMatcher_RangeMatcherValidationError{
					field:  "OnMatch",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetOnMatch()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return Int32RangeMatcher_RangeMatcherValidationError{
				field:  "OnMatch",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return Int32RangeMatcher_RangeMatcherMultiError(errors)
	}

	return nil
}

// Int32RangeMatcher_RangeMatcherMultiError is an error wrapping multiple
// validation errors returned by Int32RangeMatcher_RangeMatcher.ValidateAll()
// if the designated constraints aren't met.
type Int32RangeMatcher_RangeMatcherMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m Int32RangeMatcher_RangeMatcherMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m Int32RangeMatcher_RangeMatcherMultiError) AllErrors() []error { return m }

// Int32RangeMatcher_RangeMatcherValidationError is the validation error
// returned by Int32RangeMatcher_RangeMatcher.Validate if the designated
// constraints aren't met.
type Int32RangeMatcher_RangeMatcherValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e Int32RangeMatcher_RangeMatcherValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e Int32RangeMatcher_RangeMatcherValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e Int32RangeMatcher_RangeMatcherValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e Int32RangeMatcher_RangeMatcherValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e Int32RangeMatcher_RangeMatcherValidationError) ErrorName() string {
	return "Int32RangeMatcher_RangeMatcherValidationError"
}

// Error satisfies the builtin error interface
func (e Int32RangeMatcher_RangeMatcherValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sInt32RangeMatcher_RangeMatcher.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = Int32RangeMatcher_RangeMatcherValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = Int32RangeMatcher_RangeMatcherValidationError{}

// Validate checks the field values on DoubleRangeMatcher_RangeMatcher with the
// rules defined in the proto definition for this message. If any rules are
// violated, the first error encountered is returned, or nil if there are no violations.
func (m *DoubleRangeMatcher_RangeMatcher) Validate() error {
	return m.validate(false)
}

// ValidateAll checks the field values on DoubleRangeMatcher_RangeMatcher with
// the rules defined in the proto definition for this message. If any rules
// are violated, the result is a list of violation errors wrapped in
// DoubleRangeMatcher_RangeMatcherMultiError, or nil if none found.
func (m *DoubleRangeMatcher_RangeMatcher) ValidateAll() error {
	return m.validate(true)
}

func (m *DoubleRangeMatcher_RangeMatcher) validate(all bool) error {
	if m == nil {
		return nil
	}

	var errors []error

	if len(m.GetRanges()) < 1 {
		err := DoubleRangeMatcher_RangeMatcherValidationError{
			field:  "Ranges",
			reason: "value must contain at least 1 item(s)",
		}
		if !all {
			return err
		}
		errors = append(errors, err)
	}

	for idx, item := range m.GetRanges() {
		_, _ = idx, item

		if all {
			switch v := interface{}(item).(type) {
			case interface{ ValidateAll() error }:
				if err := v.ValidateAll(); err != nil {
					errors = append(errors, DoubleRangeMatcher_RangeMatcherValidationError{
						field:  fmt.Sprintf("Ranges[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			case interface{ Validate() error }:
				if err := v.Validate(); err != nil {
					errors = append(errors, DoubleRangeMatcher_RangeMatcherValidationError{
						field:  fmt.Sprintf("Ranges[%v]", idx),
						reason: "embedded message failed validation",
						cause:  err,
					})
				}
			}
		} else if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return DoubleRangeMatcher_RangeMatcherValidationError{
					field:  fmt.Sprintf("Ranges[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if all {
		switch v := interface{}(m.GetOnMatch()).(type) {
		case interface{ ValidateAll() error }:
			if err := v.ValidateAll(); err != nil {
				errors = append(errors, DoubleRangeMatcher_RangeMatcherValidationError{
					field:  "OnMatch",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		case interface{ Validate() error }:
			if err := v.Validate(); err != nil {
				errors = append(errors, DoubleRangeMatcher_RangeMatcherValidationError{
					field:  "OnMatch",
					reason: "embedded message failed validation",
					cause:  err,
				})
			}
		}
	} else if v, ok := interface{}(m.GetOnMatch()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return DoubleRangeMatcher_RangeMatcherValidationError{
				field:  "OnMatch",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if len(errors) > 0 {
		return DoubleRangeMatcher_RangeMatcherMultiError(errors)
	}

	return nil
}

// DoubleRangeMatcher_RangeMatcherMultiError is an error wrapping multiple
// validation errors returned by DoubleRangeMatcher_RangeMatcher.ValidateAll()
// if the designated constraints aren't met.
type DoubleRangeMatcher_RangeMatcherMultiError []error

// Error returns a concatenation of all the error messages it wraps.
func (m DoubleRangeMatcher_RangeMatcherMultiError) Error() string {
	var msgs []string
	for _, err := range m {
		msgs = append(msgs, err.Error())
	}
	return strings.Join(msgs, "; ")
}

// AllErrors returns a list of validation violation errors.
func (m DoubleRangeMatcher_RangeMatcherMultiError) AllErrors() []error { return m }

// DoubleRangeMatcher_RangeMatcherValidationError is the validation error
// returned by DoubleRangeMatcher_RangeMatcher.Validate if the designated
// constraints aren't met.
type DoubleRangeMatcher_RangeMatcherValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e DoubleRangeMatcher_RangeMatcherValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e DoubleRangeMatcher_RangeMatcherValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e DoubleRangeMatcher_RangeMatcherValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e DoubleRangeMatcher_RangeMatcherValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e DoubleRangeMatcher_RangeMatcherValidationError) ErrorName() string {
	return "DoubleRangeMatcher_RangeMatcherValidationError"
}

// Error satisfies the builtin error interface
func (e DoubleRangeMatcher_RangeMatcherValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sDoubleRangeMatcher_RangeMatcher.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = DoubleRangeMatcher_RangeMatcherValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = DoubleRangeMatcher_RangeMatcherValidationError{}
