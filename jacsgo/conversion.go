package jacs

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// BinaryData represents binary data with type information for cross-language compatibility
type BinaryData struct {
	Type string `json:"__type__"`
	Data string `json:"data"`
}

// EncodeBinaryData encodes binary data for cross-language compatibility
func EncodeBinaryData(data []byte) interface{} {
	return BinaryData{
		Type: "bytes",
		Data: base64.StdEncoding.EncodeToString(data),
	}
}

// DecodeBinaryData decodes binary data from cross-language format
func DecodeBinaryData(data interface{}) ([]byte, error) {
	// Handle map[string]interface{} type
	if m, ok := data.(map[string]interface{}); ok {
		typeVal, hasType := m["__type__"]
		dataVal, hasData := m["data"]

		if hasType && hasData {
			if typeStr, ok := typeVal.(string); ok && typeStr == "bytes" {
				if dataStr, ok := dataVal.(string); ok {
					return base64.StdEncoding.DecodeString(dataStr)
				}
			}
		}
	}

	// Handle BinaryData struct type
	if bd, ok := data.(BinaryData); ok && bd.Type == "bytes" {
		return base64.StdEncoding.DecodeString(bd.Data)
	}

	// Handle *BinaryData type
	if bd, ok := data.(*BinaryData); ok && bd != nil && bd.Type == "bytes" {
		return base64.StdEncoding.DecodeString(bd.Data)
	}

	return nil, fmt.Errorf("not a valid binary data object")
}

// ConvertValue recursively converts values to handle special types
func ConvertValue(v interface{}) interface{} {
	switch val := v.(type) {
	case []byte:
		// Convert byte arrays to the cross-language format
		return EncodeBinaryData(val)
	case map[string]interface{}:
		// Recursively convert map values
		result := make(map[string]interface{})
		for k, v := range val {
			result[k] = ConvertValue(v)
		}
		return result
	case []interface{}:
		// Recursively convert slice elements
		result := make([]interface{}, len(val))
		for i, v := range val {
			result[i] = ConvertValue(v)
		}
		return result
	default:
		// Return other types as-is
		return val
	}
}

// RestoreValue recursively restores values from cross-language format
func RestoreValue(v interface{}) interface{} {
	switch val := v.(type) {
	case map[string]interface{}:
		// Check if this is a special type
		if typeVal, hasType := val["__type__"]; hasType {
			if typeStr, ok := typeVal.(string); ok && typeStr == "bytes" {
				if bytes, err := DecodeBinaryData(val); err == nil {
					return bytes
				}
			}
		}

		// Recursively restore map values
		result := make(map[string]interface{})
		for k, v := range val {
			result[k] = RestoreValue(v)
		}
		return result
	case []interface{}:
		// Recursively restore slice elements
		result := make([]interface{}, len(val))
		for i, v := range val {
			result[i] = RestoreValue(v)
		}
		return result
	default:
		// Return other types as-is
		return val
	}
}

// ToJSON converts a Go value to JSON with special type handling
func ToJSON(v interface{}) (string, error) {
	converted := ConvertValue(v)
	bytes, err := json.Marshal(converted)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// FromJSON parses JSON and restores special types
func FromJSON(jsonStr string) (interface{}, error) {
	var v interface{}
	err := json.Unmarshal([]byte(jsonStr), &v)
	if err != nil {
		return nil, err
	}
	return RestoreValue(v), nil
}
