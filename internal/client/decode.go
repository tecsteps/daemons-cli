package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strings"
)

// WireInt is an integer-valued API number. Laravel models may serialize a
// decimal-backed value as either 4, 4.0, or "4.00", so response structs use
// this type at every numeric resource field while still rejecting fractions.
type WireInt int64

func (value *WireInt) UnmarshalJSON(raw []byte) error {
	trimmed := bytes.TrimSpace(raw)
	if bytes.Equal(trimmed, []byte("null")) {
		*value = 0
		return nil
	}

	number := string(trimmed)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		if err := json.Unmarshal(trimmed, &number); err != nil {
			return err
		}
	}
	parsed, ok := parseWireInt(number)
	if !ok {
		return &json.UnmarshalTypeError{
			Value: "number " + number,
			Type:  reflect.TypeFor[WireInt](),
		}
	}
	*value = parsed
	return nil
}

func parseWireInt(number string) (WireInt, bool) {
	if len(number) == 0 || (number[0] != '-' && (number[0] < '0' || number[0] > '9')) || !json.Valid([]byte(number)) {
		return 0, false
	}
	rational, ok := new(big.Rat).SetString(number)
	if !ok || !rational.IsInt() || !rational.Num().IsInt64() {
		return 0, false
	}
	return WireInt(rational.Num().Int64()), true
}

type responseShapeError struct {
	field string
	value any
}

func (err *responseShapeError) Error() string {
	return fmt.Sprintf("unexpected value %v at field %s", err.value, err.field)
}

// decodeResponseJSON accepts PHP's representation of an empty object as []
// anywhere the destination response type expects a map or struct. The raw
// document remains untouched for canonical --json output.
func decodeResponseJSON(raw []byte, result any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var document any
	if err := decoder.Decode(&document); err != nil {
		return err
	}

	target := reflect.TypeOf(result)
	normalized, err := normalizeResponseValue(document, target, "")
	if err != nil {
		return err
	}
	normalizedRaw, err := json.Marshal(normalized)
	if err != nil {
		return err
	}
	return json.Unmarshal(normalizedRaw, result)
}

func normalizeResponseValue(value any, target reflect.Type, fieldPath string) (any, error) {
	for target != nil && target.Kind() == reflect.Pointer {
		target = target.Elem()
	}
	if target == nil || value == nil {
		return value, nil
	}

	if target == reflect.TypeFor[WireInt]() {
		var number string
		switch typed := value.(type) {
		case json.Number:
			number = string(typed)
		case string:
			number = typed
		default:
			return nil, &responseShapeError{field: fieldPath, value: value}
		}
		if _, valid := parseWireInt(number); !valid {
			return nil, &responseShapeError{field: fieldPath, value: value}
		}
		return value, nil
	}

	if items, ok := value.([]any); ok {
		if len(items) == 0 && (target.Kind() == reflect.Map || target.Kind() == reflect.Struct) {
			return map[string]any{}, nil
		}
		if target.Kind() == reflect.Slice || target.Kind() == reflect.Array {
			for index := range items {
				nestedPath := fmt.Sprintf("%s[%d]", fieldPath, index)
				normalized, err := normalizeResponseValue(items[index], target.Elem(), nestedPath)
				if err != nil {
					return nil, err
				}
				items[index] = normalized
			}
		}
		return items, nil
	}

	object, ok := value.(map[string]any)
	if !ok {
		return value, nil
	}
	switch target.Kind() {
	case reflect.Struct:
		for index := 0; index < target.NumField(); index++ {
			field := target.Field(index)
			name := field.Name
			if tag := field.Tag.Get("json"); tag != "" {
				name = strings.Split(tag, ",")[0]
			}
			if name == "-" || name == "" {
				continue
			}
			if nested, exists := object[name]; exists {
				nestedPath := name
				if fieldPath != "" {
					nestedPath = fieldPath + "." + name
				}
				normalized, err := normalizeResponseValue(nested, field.Type, nestedPath)
				if err != nil {
					return nil, err
				}
				object[name] = normalized
			}
		}
	case reflect.Map:
		for key, nested := range object {
			nestedPath := key
			if fieldPath != "" {
				nestedPath = fieldPath + "." + key
			}
			normalized, err := normalizeResponseValue(nested, target.Elem(), nestedPath)
			if err != nil {
				return nil, err
			}
			object[key] = normalized
		}
	}
	return object, nil
}
