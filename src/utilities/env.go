package utilities

import "os"

var env = map[string]string{
	"DB_HOST":     "localhost",
	"DB_PORT":     "5420",
	"DB_USER":     "postgres",
	"DB_PASSWORD": "password",
	"DB_NAME":     "postgres",
	"DB_SSLMODE":  "disable",

	"KEYCLOAK_API":     "http://localhost:8080",
	"AUTH_SERVICE_API": "http://localhost:5020",
	"BACKEND_API":      "http://localhost:5010",
}

func GetEnv(key string) string {
	value := os.Getenv(key)

	if value == "" {
		value, exists := env[key]
		if exists {
			return value
		}
	}

	return value
}
