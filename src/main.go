package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strconv"

	_ "github.com/lib/pq"
	"github.com/redis/go-redis/v9"

	"github.com/retroruk/centralized-devops-auth/src/controllers"
	"github.com/retroruk/centralized-devops-auth/src/services"
	"github.com/retroruk/centralized-devops-auth/src/utilities"
)

func main() {
	connStr := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		utilities.GetEnv("DB_HOST"),
		utilities.GetEnv("DB_PORT"),
		utilities.GetEnv("DB_USER"),
		utilities.GetEnv("DB_PASSWORD"),
		utilities.GetEnv("DB_NAME"),
		utilities.GetEnv("DB_SSLMODE"),
	)

	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	err = db.Ping()
	if err != nil {
		log.Fatal("Cannot connect to database:", err)
	}

	redisDB, err := strconv.Atoi(utilities.GetEnv("REDIS_DB"))
	if err != nil {
		log.Fatal("failed to parse int for redis db", err)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     utilities.GetEnv("REDIS_ADDR"),
		Password: utilities.GetEnv("REDIS_PASSWORD"),
		DB:       redisDB,
	})

	_, err = rdb.Ping(context.Background()).Result()
	if err != nil {
		log.Fatal("failed to connect to redis")
	}

	mux := http.NewServeMux()

	emailActionService := services.InitEmailActionService()

	controllers.InitKeycloakController(mux, services.InitKeycloakService(db, rdb))

	sessionService := services.InitSessionService(db, rdb)
	controllers.InitSessionController(mux, sessionService)

	userService := services.InitUserService(db, rdb, emailActionService)
	controllers.InitUserController(mux, userService)

	log.Println("Server started on port 5020")
	if err := http.ListenAndServe(":5020", mux); err != nil {
		log.Fatal("failed to start server", err)
	}
}

func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Allow-Credentials", "true")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		h.ServeHTTP(w, r)
	})
}
