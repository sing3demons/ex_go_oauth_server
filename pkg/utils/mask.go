package utils

import "strings"

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
	switch v := data.(type) {
	case map[string]any:
		for k, val := range v {
			if fn, ok := rules[k]; ok {
				if str, ok := val.(string); ok {
					v[k] = fn(str)
					continue
				}
			}
			v[k] = maskAny(val, rules)
		}
		return v

	case []any:
		for i := range v {
			v[i] = maskAny(v[i], rules)
		}
		return v

	default:
		return v
	}
}
