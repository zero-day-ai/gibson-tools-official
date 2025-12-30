package executor

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"time"
)

// Result holds the execution result
type Result struct {
	Stdout   []byte
	Stderr   []byte
	ExitCode int
	Duration time.Duration
}

// Config holds execution configuration
type Config struct {
	Command   string
	Args      []string
	WorkDir   string
	Env       []string
	Timeout   time.Duration
	StdinData []byte
}

// Execute runs a command with the given configuration
func Execute(ctx context.Context, cfg Config) (*Result, error) {
	start := time.Now()

	// Create context with timeout if specified
	cmdCtx := ctx
	if cfg.Timeout > 0 {
		var cancel context.CancelFunc
		cmdCtx, cancel = context.WithTimeout(ctx, cfg.Timeout)
		defer cancel()
	}

	// Create command
	cmd := exec.CommandContext(cmdCtx, cfg.Command, cfg.Args...)

	// Set working directory if specified
	if cfg.WorkDir != "" {
		cmd.Dir = cfg.WorkDir
	}

	// Set environment variables if specified
	if len(cfg.Env) > 0 {
		cmd.Env = cfg.Env
	}

	// Set up buffers for stdout and stderr
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	// Set stdin if provided
	if len(cfg.StdinData) > 0 {
		cmd.Stdin = bytes.NewReader(cfg.StdinData)
	}

	// Execute command
	err := cmd.Run()

	// Calculate duration
	duration := time.Since(start)

	// Extract exit code
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if cmdCtx.Err() == context.DeadlineExceeded {
			return &Result{
				Stdout:   stdout.Bytes(),
				Stderr:   stderr.Bytes(),
				ExitCode: -1,
				Duration: duration,
			}, fmt.Errorf("execution timed out after %v: %w", cfg.Timeout, err)
		} else {
			return nil, fmt.Errorf("failed to execute command: %w", err)
		}
	}

	return &Result{
		Stdout:   stdout.Bytes(),
		Stderr:   stderr.Bytes(),
		ExitCode: exitCode,
		Duration: duration,
	}, nil
}

// BinaryExists checks if a binary is available in PATH
func BinaryExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// BinaryPath returns the full path to a binary
func BinaryPath(name string) (string, error) {
	path, err := exec.LookPath(name)
	if err != nil {
		return "", fmt.Errorf("binary %q not found in PATH: %w", name, err)
	}
	return path, nil
}
