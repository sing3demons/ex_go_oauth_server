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
}
