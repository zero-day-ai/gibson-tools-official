package common

import (
	"fmt"
	"time"
)

// DefaultTimeout returns the default execution timeout (5 minutes)
func DefaultTimeout() time.Duration {
	return 5 * time.Minute
}

// GetTimeout extracts timeout from input or returns default
func GetTimeout(input map[string]any, key string, defaultVal time.Duration) time.Duration {
	if input == nil {
		return defaultVal
	}

	val, ok := input[key]
	if !ok {
		return defaultVal
	}

	// Handle various timeout representations
	switch v := val.(type) {
	case time.Duration:
		return v
	case int:
		return time.Duration(v) * time.Second
	case int64:
		return time.Duration(v) * time.Second
	case float64:
		return time.Duration(v) * time.Second
	case string:
		duration, err := time.ParseDuration(v)
		if err != nil {
			return defaultVal
		}
		return duration
	default:
		return defaultVal
	}
}

// GetString safely extracts a string from input map
func GetString(input map[string]any, key string, defaultVal string) string {
	if input == nil {
		return defaultVal
	}

	val, ok := input[key]
	if !ok {
		return defaultVal
	}

	str, ok := val.(string)
	if !ok {
		return defaultVal
	}

	return str
}

// GetInt safely extracts an int from input map
func GetInt(input map[string]any, key string, defaultVal int) int {
	if input == nil {
		return defaultVal
	}

	val, ok := input[key]
	if !ok {
		return defaultVal
	}

	switch v := val.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		// Try to parse string as int
		var i int
		_, err := fmt.Sscanf(v, "%d", &i)
		if err != nil {
			return defaultVal
		}
		return i
	default:
		return defaultVal
	}
}

// GetBool safely extracts a bool from input map
func GetBool(input map[string]any, key string, defaultVal bool) bool {
	if input == nil {
		return defaultVal
	}

	val, ok := input[key]
	if !ok {
		return defaultVal
	}

	b, ok := val.(bool)
	if !ok {
		return defaultVal
	}

	return b
}

// GetStringSlice safely extracts a string slice from input map
func GetStringSlice(input map[string]any, key string) []string {
	if input == nil {
		return nil
	}

	val, ok := input[key]
	if !ok {
		return nil
	}

	// Handle []string
	if strs, ok := val.([]string); ok {
		return strs
	}

	// Handle []interface{}
	if slice, ok := val.([]interface{}); ok {
		result := make([]string, 0, len(slice))
		for _, item := range slice {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}

	// Handle single string
	if str, ok := val.(string); ok {
		return []string{str}
	}

	return nil
}

// GetFloat64 safely extracts a float64 from input map
func GetFloat64(input map[string]any, key string, defaultVal float64) float64 {
	if input == nil {
		return defaultVal
	}

	val, ok := input[key]
	if !ok {
		return defaultVal
	}

	switch v := val.(type) {
	case float64:
		return v
	case int:
		return float64(v)
	case int64:
		return float64(v)
	default:
		return defaultVal
	}
}

// GetMap safely extracts a map from input map
func GetMap(input map[string]any, key string) map[string]any {
	if input == nil {
		return nil
	}

	val, ok := input[key]
	if !ok {
		return nil
	}

	m, ok := val.(map[string]any)
	if !ok {
		return nil
	}

	return m
}
