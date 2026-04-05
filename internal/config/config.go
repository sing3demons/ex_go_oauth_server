package config

import (
	"fmt"
	"os"
	"path/filepath"
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

	LoggerConfig LogConfig
}

type YamlConfig struct {
	App AppConfig `yaml:"app"`
	Log LogConfig `yaml:"log"`
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
		AdminUsername:        getEnv("ADMIN_USERNAME", "admin"),
		AdminPassword:        getEnv("ADMIN_PASSWORD", "adminsecret"),
		LoggerConfig:         yamlCfg.Log,
	}
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}
