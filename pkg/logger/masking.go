package logger

import (
	"encoding/json"
	"fmt"
	"strings"
)

type MaskingType int

const (
	MaskConfig MaskingType = iota
	MaskAll
	MaskCustom
)

type MaskingOption struct {
	IsArray      bool
	MaskingField string
	MaskingType  MaskingType
	// Optional callback for Custom Masking
	Callback func(string) string
}

// MaskingService interface
type MaskingService interface {
	Masking(value string, maskType MaskingType, callback ...func(string) string) string
}

type DefaultMaskingService struct{}

func (d *DefaultMaskingService) Masking(value string, maskType MaskingType, callback ...func(string) string) string {
	switch maskType {
	case MaskAll:
		return strings.Repeat("*", len(value))
	case MaskCustom:
		if len(callback) > 0 && callback[0] != nil {
			return callback[0](value)
		}
		return value
	default:
		// basic MaskConfig (e.g. keeping first/last few characters visible)
		if len(value) <= 2 {
			return "***"
		}
		return value[:1] + strings.Repeat("*", len(value)-2) + value[len(value)-1:]
	}
}

// DeepCloneAndMask converts an arbitrary object/struct into JSON and traverses it mapping the rules,
// returning the modified structure.
func DeepCloneAndMask(data any, opts []MaskingOption, svc MaskingService) any {
	if len(opts) == 0 {
		return data
	}

	b, err := json.Marshal(data)
	if err != nil {
		return data
	}

	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return data
	}

	for _, opt := range opts {
		applyMasking(m, opt, svc)
	}

	return m
}

func applyMasking(data map[string]any, opt MaskingOption, svc MaskingService) {
	if opt.IsArray {
		if strings.Contains(opt.MaskingField, "*") {
			parts := strings.SplitN(opt.MaskingField, "*", 2)
			root := strings.TrimSuffix(parts[0], ".")
			// Simplistic logic for array masking handling e.g. "users.*.password"
			val := getObjectByStringKeys(data, root)
			if arr, ok := val.([]any); ok {
				for i := range arr {
					newPath := strings.Replace(opt.MaskingField, "*", fmt.Sprintf("%d", i), 1)
					setNestedProperty(data, newPath, opt, svc)
				}
			}
		} else {
			setNestedProperty(data, opt.MaskingField, opt, svc)
		}
	} else {
		setNestedProperty(data, opt.MaskingField, opt, svc)
	}
}

func getObjectByStringKeys(obj map[string]any, keysString string) any {
	keys := strings.Split(keysString, ".")
	var currentObj any = obj

	for _, key := range keys {
		if m, ok := currentObj.(map[string]any); ok {
			currentObj = m[key]
		} else {
			return nil
		}
	}
	return currentObj
}

func setNestedProperty(obj map[string]any, propString string, opt MaskingOption, svc MaskingService) {
	keys := strings.Split(propString, ".")
	currentObj := obj

	for i := 0; i < len(keys)-1; i++ {
		key := keys[i]
		if _, ok := currentObj[key]; !ok {
			currentObj[key] = make(map[string]any)
		}
		if m, ok := currentObj[key].(map[string]any); ok {
			currentObj = m
		} else {
			return
		}
	}

	lastKey := keys[len(keys)-1]
	if val, ok := currentObj[lastKey]; ok {
		strVal := fmt.Sprintf("%v", val)
		currentObj[lastKey] = svc.Masking(strVal, opt.MaskingType, opt.Callback)
	}
}
