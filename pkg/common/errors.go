package common

import (
	"errors"
	"fmt"
)

// Standard tool errors
var (
	ErrBinaryNotFound   = errors.New("binary not found in PATH")
	ErrExecutionTimeout = errors.New("execution timed out")
	ErrParseError       = errors.New("failed to parse output")
	ErrInvalidInput     = errors.New("invalid input parameters")
)

// Error codes for structured error handling
const (
	ErrCodeBinaryNotFound    = "BINARY_NOT_FOUND"
	ErrCodeExecutionFailed   = "EXECUTION_FAILED"
	ErrCodeTimeout           = "TIMEOUT"
	ErrCodeParseError        = "PARSE_ERROR"
	ErrCodeInvalidInput      = "INVALID_INPUT"
	ErrCodeDependencyMissing = "DEPENDENCY_MISSING"
	ErrCodePermissionDenied  = "PERMISSION_DENIED"
	ErrCodeNetworkError      = "NETWORK_ERROR"
)

// ToolError wraps errors with tool context
type ToolError struct {
	Tool      string         `json:"tool"`
	Operation string         `json:"operation"`
	Code      string         `json:"code"`
	Message   string         `json:"message"`
	Details   map[string]any `json:"details,omitempty"`
	Cause     error          `json:"-"`
}

// Error implements the error interface
func (e *ToolError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s [%s/%s]: %s: %v", e.Tool, e.Operation, e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s [%s/%s]: %s", e.Tool, e.Operation, e.Code, e.Message)
}

// Unwrap implements the errors.Unwrap interface
func (e *ToolError) Unwrap() error {
	return e.Cause
}

// NewToolError creates a new ToolError
func NewToolError(tool, operation, code, message string) *ToolError {
	return &ToolError{
		Tool:      tool,
		Operation: operation,
		Code:      code,
		Message:   message,
	}
}

// WithCause adds a cause error to the ToolError
func (e *ToolError) WithCause(err error) *ToolError {
	e.Cause = err
	return e
}

// WithDetails adds details to the ToolError
func (e *ToolError) WithDetails(details map[string]any) *ToolError {
	e.Details = details
	return e
}
