package utils

import (
	"reflect"
	"strings"
)

func MaskEmail(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return email
	}

	name := parts[0]
	domain := parts[1]

	switch len(name) {
	case 0:
		return "***@" + domain
	case 1:
		return name + "*@" + domain
	case 2:
		return name[:1] + "*@" + domain
	default:
		return name[:2] + strings.Repeat("*", len(name)-2) + "@" + domain
	}
}
func MaskUsername(username string) string {
	if len(username) <= 3 {
		return "***"
	}

	return username[:3] + strings.Repeat("*", len(username)-3)
}
func MaskUsernameOrEmail(input string) string {
	if IsEmail(input) {
		return MaskEmail(input)
	}
	return MaskUsername(input)
}
func MaskPassword(password string) string {
	return "******"
}
func MaskPhone(phone string) string {
	if len(phone) < 4 {
		return "***"
	}
	return phone[:3] + strings.Repeat("*", len(phone)-6) + phone[len(phone)-3:]
}
func MaskID(id string) string {
	if len(id) <= 4 {
		return "****"
	}
	return id[:2] + strings.Repeat("*", len(id)-4) + id[len(id)-2:]
}
func MaskCreditCard(cc string) string {
	if len(cc) < 4 {
		return "****"
	}
	return strings.Repeat("*", len(cc)-4) + cc[len(cc)-4:]
}

func MaskToken(token string) string {
	if len(token) <= 8 {
		return "****"
	}
	return token[:4] + "..." + token[len(token)-4:]
}

func MaskRecursive[T any](data T, rules map[string]func(string) string) T {
	return maskAny(data, rules).(T)
}

func maskAny(data any, rules map[string]func(string) string) any {
	v := reflect.ValueOf(data)
	if !v.IsValid() {
		return data
	}

	return maskValue(v, rules).Interface()
}

func maskValue(v reflect.Value, rules map[string]func(string) string) reflect.Value {
	if !v.IsValid() {
		return v
	}

	switch v.Kind() {
	case reflect.Interface:
		if v.IsNil() {
			return v
		}
		inner := maskValue(v.Elem(), rules)
		return inner

	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		ptr := reflect.New(v.Elem().Type())
		ptr.Elem().Set(maskValue(v.Elem(), rules))
		return ptr

	case reflect.Map:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		for _, k := range v.MapKeys() {
			val := v.MapIndex(k)

			if k.Kind() == reflect.String {
				if fn, ok := rules[k.String()]; ok {
					if str, ok := val.Interface().(string); ok {
						out.SetMapIndex(k, reflect.ValueOf(fn(str)).Convert(v.Type().Elem()))
						continue
					}
				}

				if fn, ok := rules[k.String()]; ok && val.Kind() == reflect.String {
					out.SetMapIndex(k, reflect.ValueOf(fn(val.String())).Convert(v.Type().Elem()))
					continue
				}
			}

			masked := maskValue(val, rules)
			if masked.IsValid() && masked.Type().AssignableTo(v.Type().Elem()) {
				out.SetMapIndex(k, masked)
			} else if masked.IsValid() && masked.Type().ConvertibleTo(v.Type().Elem()) {
				out.SetMapIndex(k, masked.Convert(v.Type().Elem()))
			} else {
				out.SetMapIndex(k, val)
			}
		}
		return out

	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Len())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(maskValue(v.Index(i), rules))
		}
		return out

	case reflect.Array:
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(maskValue(v.Index(i), rules))
		}
		return out

	case reflect.Struct:
		out := reflect.New(v.Type()).Elem()
		out.Set(v)

		for i := 0; i < v.NumField(); i++ {
			fieldInfo := v.Type().Field(i)
			if fieldInfo.PkgPath != "" {
				continue
			}

			fieldVal := v.Field(i)
			if fn, ok := findMaskRule(fieldInfo, rules); ok && fieldVal.Kind() == reflect.String {
				out.Field(i).SetString(fn(fieldVal.String()))
				continue
			}

			masked := maskValue(fieldVal, rules)
			if masked.IsValid() && masked.Type().AssignableTo(fieldVal.Type()) {
				out.Field(i).Set(masked)
			} else if masked.IsValid() && masked.Type().ConvertibleTo(fieldVal.Type()) {
				out.Field(i).Set(masked.Convert(fieldVal.Type()))
			}
		}

		return out

	default:
		return v
	}
}

func findMaskRule(field reflect.StructField, rules map[string]func(string) string) (func(string) string, bool) {
	if tag, ok := field.Tag.Lookup("json"); ok {
		name := strings.Split(tag, ",")[0]
		if name != "" && name != "-" {
			if fn, found := rules[name]; found {
				return fn, true
			}
		}
	}

	if fn, ok := rules[field.Name]; ok {
		return fn, true
	}

	if fn, ok := rules[strings.ToLower(field.Name)]; ok {
		return fn, true
	}

	return nil, false
}
