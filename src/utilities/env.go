package utilities

import "os"

var env = map[string]string{
	"DB_HOST":     "localhost",
	"DB_PORT":     "5432",
	"DB_USER":     "postgres",
	"DB_PASSWORD": "password",
	"DB_NAME":     "postgres",
	"DB_SSLMODE":  "disable",

	"REDIS_ADDR":     "localhost:6379",
	"REDIS_PASSWORD": "",
	"REDIS_DB":       "0",

	"KEYCLOAK_API":            "http://localhost:8080",
	"AUTH_SERVICE_API":        "http://localhost:5020",
	"PUBLIC_AUTH_SERVICE_API": "http://localhost:5020", // used for redirects
	"PUBLIC_BACKEND_API":      "http://localhost:5010", // used for redirects

	"SMTP_EMAIL":    "john.rukstalis@gmail.com",
	"SMTP_PASSWORD": "yblqksffjcjlzbwq",

	"KEYCLOAK_ADMIN_USERNAME": "admin",
	"KEYCLOAK_ADMIN_PASSWORD": "admin",
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
