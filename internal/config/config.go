package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port                 string
	MongoURI             string
	MongoDBName          string
	RedisURI             string
	Issuer               string
	KeyRotationDuration  time.Duration
	KeyGracePeriod       time.Duration
	KeyMaxRetentionCount int
}

func LoadConfig() *Config {
	return &Config{
		Port:                 getEnv("PORT", "8080"),
		MongoURI:             getEnv("MONGO_URI", "mongodb://localhost:27017"),
		MongoDBName:          getEnv("MONGO_DB_NAME", "oidc_db"),
		RedisURI:             getEnv("REDIS_URI", "redis://localhost:6379/0"),
		Issuer:               getEnv("ISSUER", "http://localhost:8080"),
		KeyRotationDuration:  getDurationEnv("KEY_ROTATION_DURATION", 30*24*time.Hour),
		KeyGracePeriod:       getDurationEnv("KEY_GRACE_PERIOD", 14*24*time.Hour),
		KeyMaxRetentionCount: getIntEnv("KEY_MAX_RETENTION_COUNT", 5),
	}
}

func getEnv(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

func getDurationEnv(key string, defaultVal time.Duration) time.Duration {
	if val, ok := os.LookupEnv(key); ok {
		if d, err := time.ParseDuration(val); err == nil {
			return d
		}
	}
	return defaultVal
}

func getIntEnv(key string, defaultVal int) int {
	if val, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}
