package kp

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type TemplateManager struct {
	templates map[string]*template.Template
	mu        sync.RWMutex
	funcMap   template.FuncMap
}

func NewTemplateManager() *TemplateManager {
	return &TemplateManager{
		templates: make(map[string]*template.Template),
		funcMap: template.FuncMap{
			"contains": strings.Contains,
			"substr": func(s string, start, end int) string {
				if len(s) < end {
					return s[start:]
				}
				return s[start:end]
			},
			"upper": strings.ToUpper,
		},
	}
}

// LoadTemplates parses all .html files in the directory and caches them.
func (m *TemplateManager) LoadTemplates(dir string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && filepath.Ext(path) == ".html" {
			// Normalize name for cache key (e.g. templates/login.html -> templates/login.html)
			// But for easier lookup we might want just "templates/login.html"
			name := path
			tmpl, err := template.New(filepath.Base(path)).Funcs(m.funcMap).ParseFiles(path)
			if err != nil {
				return fmt.Errorf("failed to parse template %s: %w", path, err)
			}
			m.templates[name] = tmpl
		}
		return nil
	})

	return err
}

func (m *TemplateManager) GetTemplate(name string) (*template.Template, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	tmpl, ok := m.templates[name]
	if !ok {
		return nil, fmt.Errorf("template %s not found in cache", name)
	}
	return tmpl, nil
}
