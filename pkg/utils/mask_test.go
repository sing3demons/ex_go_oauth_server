package utils

import (
	"encoding/json"
	"reflect"
	"testing"
)

type MaskRecursiveTest struct {
	name     string
	input    map[string]any
	expected map[string]any
}

func TestMaskRecursive(t *testing.T) {
	t.Run("MaskRecursive multi", func(t *testing.T) {
		rules := map[string]func(string) string{
			"email":    MaskEmail,
			"password": MaskPassword,
			"phone":    MaskPhone,
		}

		tests := []MaskRecursiveTest{
			{
				name: "simple fields",
				input: map[string]any{
					"email":    "test@test.com",
					"password": "123456",
				},
				expected: map[string]any{
					"email":    "te**@test.com",
					"password": "******",
				},
			},
			{
				name: "nested object",
				input: map[string]any{
					"profile": map[string]any{
						"phone": "0812345678",
					},
				},
				expected: map[string]any{
					"profile": map[string]any{
						"phone": "081****678",
					},
				},
			},
			{
				name: "array of objects",
				input: map[string]any{
					"users": []any{
						map[string]any{
							"email": "a@test.com",
						},
						map[string]any{
							"phone": "0899999999",
						},
					},
				},
				expected: map[string]any{
					"users": []any{
						map[string]any{
							"email": "a*@test.com",
						},
						map[string]any{
							"phone": "089****999",
						},
					},
				},
			},
			{
				name: "no matching rules",
				input: map[string]any{
					"name": "john",
				},
				expected: map[string]any{
					"name": "john",
				},
			},
		}

		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				result := MaskRecursive(tt.input, rules)

				if !reflect.DeepEqual(result, tt.expected) {
					t.Errorf("expected %+v, got %+v", tt.expected, result)
				}
			})
		}
	})

	t.Run("test body", func(t *testing.T) {
		reqBody := `{
			"body": {
				"username": "test",
				"password": "122345"
			}
		}`

		body := map[string]any{}
		if err := json.Unmarshal([]byte(reqBody), &body); err != nil {
			t.Fatalf("failed to unmarshal request body: %v", err)
		}

		rules := map[string]func(string) string{
			"username": MaskUsername,
			"password": MaskPassword,
		}
		expected := map[string]any{
			"body": map[string]any{
				"username": "tes*",
				"password": "******",
			},
		}

		result := MaskRecursive(body, rules)
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("expected %+v, got %+v", expected, result)
		}
	})

	t.Run("test []", func(t *testing.T) {
		type Data struct {
			ID         string `json:"id"`
			UserID     string `json:"user_id"`
			Type       string `json:"type"`
			Identifier string `json:"identifier"`
			Secret     string `json:"secret"`
			Verified   bool   `json:"verified"`
		}
		rules := map[string]func(string) string{
			"secret": MaskPassword,
		}
		// []
		input := []Data{
			{ID: "65454f0a-cfe6-4687-9c47-ba5d1e658e1d",
				UserID:     "48d88564-5ccf-4a1c-bf78-cb40ab46caad",
				Type:       "password",
				Identifier: "test1@test.com", Secret: "$2a$10$aovE9TlK5aR5Wyfc2Yrciev5lp3cYxpJ236ll8VfOJcA3uPO7GKkG", Verified: true},
			{ID: "8db97cf6-e5ed-4eeb-bf87-7b4e770fc680", UserID: "48d88564-5ccf-4a1c-bf78-cb40ab46caad", Type: "password", Identifier: "test1", Secret: "$2a$10$aovE9TlK5aR5Wyfc2Yrciev5lp3cYxpJ236ll8VfOJcA3uPO7GKkG", Verified: true},
			{ID: "6468cf2a-249f-4a53-a61f-e74751ac7ffc", UserID: "48d88564-5ccf-4a1c-bf78-cb40ab46caad", Type: "password", Identifier: "66987654321", Secret: "$2a$10$aovE9TlK5aR5Wyfc2Yrciev5lp3cYxpJ236ll8VfOJcA3uPO7GKkG", Verified: true},
		}
		result := MaskRecursive(input, rules)
		expected := []Data{
			{ID: "65454f0a-cfe6-4687-9c47-ba5d1e658e1d",
				UserID:     "48d88564-5ccf-4a1c-bf78-cb40ab46caad",
				Type:       "password",
				Identifier: "test1@test.com", Secret: "******", Verified: true},
			{ID: "8db97cf6-e5ed-4eeb-bf87-7b4e770fc680", UserID: "48d88564-5ccf-4a1c-bf78-cb40ab46caad", Type: "password", Identifier: "test1", Secret: "******", Verified: true},
			{ID: "6468cf2a-249f-4a53-a61f-e74751ac7ffc", UserID: "48d88564-5ccf-4a1c-bf78-cb40ab46caad", Type: "password", Identifier: "66987654321", Secret: "******", Verified: true},
		}
		if !reflect.DeepEqual(result, expected) {
			t.Errorf("expected %+v, got %+v", expected, result)
		}

	})
}
