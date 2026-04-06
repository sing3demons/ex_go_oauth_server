package config

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"gopkg.in/yaml.v3"
)

type Config struct {
	ServiceName   string
	Version       string
	ComponentName string

	Port                 string
	MongoURI             string
	MongoDBName          string
	RedisURI             string
	Issuer               string
	KeyRotationDuration  time.Duration
	KeyGracePeriod       time.Duration
	KeyMaxRetentionCount int
	AdminUsername        string
	AdminPassword        string

	Oidc           OIDC
	TrustedIssuers []TrustedIssuer

	LoggerConfig LogConfig
}

type TrustedIssuer struct {
	Issuer string `yaml:"issuer"`
	Name   string `yaml:"name"`
}

type OIDC struct {
	SupportedScopes          []string `yaml:"scopes_supported"`
	SupportedResponseTypes   []string `yaml:"response_types_supported"`
	SupportedGrantTypes      []string `yaml:"grant_types_supported"`
	SupportedSubjectTypes    []string `yaml:"subject_types_supported"`
	IdTokenSigningAlgs       []string `yaml:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethods []string `yaml:"token_endpoint_auth_methods_supported"`
	ClaimsSupported          []string `yaml:"claims_supported"`
}

type YamlConfig struct {
	App            AppConfig       `yaml:"app"`
	Log            LogConfig       `yaml:"log"`
	Oidc           OIDC            `yaml:"oidc"`
	TrustedIssuers []TrustedIssuer `yaml:"trusted_issuers"`
}
type AppConfig struct {
	Name          string `yaml:"name"`
	ComponentName string `yaml:"component-name"`
	Description   string `yaml:"description"`
	Version       string `yaml:"version"`

	Issuer               string        `yaml:"issuer"`
	KeyRotationDuration  time.Duration `yaml:"key-rotation-duration"`
	KeyGracePeriod       time.Duration `yaml:"key-grace-period"`
	KeyMaxRetentionCount int           `yaml:"key-max-retention-count"`
}
type LogConfig struct {
	Detail  LogOutputConfig `yaml:"detail"`
	Summary LogOutputConfig `yaml:"summary"`
}
type LogOutputConfig struct {
	Level             string            `yaml:"level"`
	EnableFileLogging bool              `yaml:"enable-file-logging"`
	Console           bool              `yaml:"console"`
	LogFileProperties LogFileProperties `yaml:"log-file-properties"`
	Rotation          RotationConfig    `yaml:"rotation"`
}
type LogFileProperties struct {
	Dirname     string `yaml:"dirname"`
	Filename    string `yaml:"filename"`
	DatePattern string `yaml:"date-pattern"`
	Extension   string `yaml:"extension"`
}
type RotationConfig struct {
	MaxSize    int  `yaml:"max-size"`
	MaxAge     int  `yaml:"max-age"`
	MaxBackups int  `yaml:"max-backups"`
	Compress   bool `yaml:"compress"`
}

func LoadYamlConfig(path string) (*YamlConfig, error) {
	absPath, err := resolveConfigPath(path)
	if err != nil {
		return nil, fmt.Errorf("resolve config path: %w", err)
	}

	// 🔥 เช็ค file stat ก่อน
	info, err := os.Stat(absPath)
	if err != nil {
		return nil, fmt.Errorf("stat config file (%s): %w", absPath, err)
	}

	if info.IsDir() {
		return nil, fmt.Errorf("config path (%s) is a directory, not a file", absPath)
	}

	file, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open config file %s: %w", absPath, err)
	}
	defer file.Close()

	var cfg YamlConfig
	if err := yaml.NewDecoder(file).Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to parse yaml config: %w", err)
	}

	return &cfg, nil
}
func resolveConfigPath(path string) (string, error) {
	if filepath.IsAbs(path) {
		return path, nil
	}

	// หา root จาก go.mod
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, path), nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}

	return "", fmt.Errorf("cannot find project root")
}

func LoadConfig() *Config {
	if os.Getenv("ENV") != "production" {
		env := os.Getenv("ENV")
		if env != "" {
			env = ".env." + env
		} else {
			env = ".env"
		}

		godotenv.Load(env)
	}

	zone := os.Getenv("ZONE")
	configFile := "config/local.config.yaml"
	if zone != "" {
		configFile = "config/" + zone + ".config.yaml"
	}

	yamlCfg, err := LoadYamlConfig(configFile)
	if err != nil {
		panic("Failed to load YAML config: " + err.Error())
	}

	mongoUri := os.Getenv("MONGO_URI")
	if mongoUri == "" {
		panic("MONGO_URI is required")
	}

	redisURI := os.Getenv("REDIS_URI")
	if redisURI == "" {
		panic("REDIS_URI is required")
	}

	return &Config{
		ServiceName:   yamlCfg.App.Name,
		Version:       yamlCfg.App.Version,
		ComponentName: yamlCfg.App.ComponentName,

		Port:                 getEnv("PORT", "8080"),
		MongoURI:             mongoUri,
		MongoDBName:          getEnv("MONGO_DB_NAME", "oidc_db"),
		RedisURI:             redisURI,
		Issuer:               yamlCfg.App.Issuer,
		KeyRotationDuration:  yamlCfg.App.KeyRotationDuration,
		KeyGracePeriod:       yamlCfg.App.KeyGracePeriod,
		KeyMaxRetentionCount: yamlCfg.App.KeyMaxRetentionCount,
		AdminUsername:        getEnv("ADMIN_USERNAME", ""),
		AdminPassword:        getEnv("ADMIN_PASSWORD", ""),
		LoggerConfig:         yamlCfg.Log,
		Oidc:                 yamlCfg.Oidc,
		TrustedIssuers:       yamlCfg.TrustedIssuers,
	}
}

func (c *Config) Get(key string) any {
	fieldMap := map[string]any{
		"service_name":   c.ServiceName,
		"version":        c.Version,
		"component_name": c.ComponentName,
		"port":           c.Port,
		"mongo_uri":      c.MongoURI,
		"mongo_db_name":  c.MongoDBName,
		"redis_uri":      c.RedisURI,
		"issuer":         c.Issuer,
		"admin_username": c.AdminUsername,
		"admin_password": c.AdminPassword,
		"logger_config":  c.LoggerConfig,
		"oidc":           c.Oidc,
	}

	parts := strings.SplitN(key, ".", 2)
	val, ok := fieldMap[parts[0]]
	if !ok {
		return nil
	}

	if len(parts) == 1 {
		return val
	}

	return getNestedField(val, parts[1])
}

func (c *Config) GetArray(key string) []string {
	result := []string{}

	if val := c.Get(key); val != nil {
		if arr, ok := val.([]string); ok {
			result = arr
		}
	}

	return result
}

func getNestedField(obj any, key string) any {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}

	parts := strings.SplitN(key, ".", 2)
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		field := t.Field(i)
		tag := field.Tag.Get("yaml")
		tag = strings.SplitN(tag, ",", 2)[0]

		name := strings.ReplaceAll(tag, "-", "_")
		if name == "" {
			name = strings.ToLower(field.Name)
		}

		if name == parts[0] {
			fv := v.Field(i).Interface()
			if len(parts) == 1 {
				return fv
			}
			return getNestedField(fv, parts[1])
		}
	}
	return nil
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}
