package services

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/redis/go-redis/v9"
	"github.com/retroRUK/zlog"
	"github.com/retroruk/centralized-devops-auth/src/models"
	"github.com/retroruk/centralized-devops-auth/src/utilities"
)

type UserService struct {
	db                 *sql.DB
	rdb                *redis.Client
	client             *http.Client
	keycloakAPI        string
	emailActionService *EmailActionService
}

func InitUserService(db *sql.DB, rdb *redis.Client, emailActionService *EmailActionService) *UserService {
	return &UserService{
		db:                 db,
		rdb:                rdb,
		client:             utilities.NewHttpClient(),
		keycloakAPI:        utilities.GetEnv("KEYCLOAK_API"),
		emailActionService: emailActionService,
	}
}

func (s UserService) List(tenant string) (users []models.KeycloakUser, err error) {
	token, err := s.LoginAsAdmin()
	if err != nil {
		zlog.Error("failed to login as admin", err)
		return users, err
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/admin/realms/%s/users", s.keycloakAPI, tenant), nil)
	if err != nil {
		zlog.Error("failed to create request", err)
		return users, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	res, err := s.client.Do(req)
	if err != nil {
		zlog.Error("failed http request", err)
		return users, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		zlog.Error("failed to read res body", err)
		return users, err
	}

	if err := json.Unmarshal(body, &users); err != nil {
		zlog.Error("failed to unmarshal res body", err)
		return users, err
	}

	return users, nil
}

func (s UserService) GetByID(tenant string, id string) (user models.KeycloakUser, err error) {
	token, err := s.LoginAsAdmin()
	if err != nil {
		zlog.Error("failed to login as admin", err)
		return user, err
	}

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/admin/realms/%s/users/%s", s.keycloakAPI, tenant, id), nil)
	if err != nil {
		zlog.Error("failed to create request", err)
		return user, err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	res, err := s.client.Do(req)
	if err != nil {
		zlog.Error("failed http request", err)
		return user, err
	}
	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		zlog.Error("failed to read res body", err)
		return user, err
	}

	if err := json.Unmarshal(body, &user); err != nil {
		zlog.Error("failed to unmarshal res body", err)
		return user, err
	}

	return user, nil
}

func (s UserService) DeleteByID(tenant string, id string) (err error) {
	token, err := s.LoginAsAdmin()
	if err != nil {
		zlog.Error("failed to login as admin", err)
		return err
	}

	req, err := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/admin/realms/%s/users/%s", s.keycloakAPI, tenant, id), nil)
	if err != nil {
		zlog.Error("failed to create request", err)
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token)

	res, err := s.client.Do(req)
	if err != nil {
		zlog.Error("failed http request", err)
		return err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusNoContent {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			zlog.Error("failed to read res body", err)
			return err
		}
		msg := fmt.Sprintf("status code: %d, error: %s", res.StatusCode, string(body))
		zlog.Error(msg, fmt.Errorf(msg))
		return fmt.Errorf(msg)
	}

	return nil
}

func (s UserService) Create(tenant string, email string) (string, error) {
	token, err := s.LoginAsAdmin()
	if err != nil {
		zlog.Error("failed to login as admin", err)
		return "", err
	}

	username, _, found := strings.Cut(email, "@")
	if !found {
		msg := "invalid email address"
		zlog.Error(msg, nil)
		return "", fmt.Errorf(msg)
	}

	payload := models.KeycloakCreateUserRequest{
		Username: username,
		Email:    email,
		Enabled:  true,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		zlog.Error("failed to marshal payload", err)
		return "", err
	}

	url := fmt.Sprintf("%s/admin/realms/%s/users", s.keycloakAPI, tenant)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payloadBytes))
	if err != nil {
		zlog.Error("failed to create http req", err)
		return "", err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	res, err := s.client.Do(req)
	if err != nil {
		zlog.Error("failed http res", err)
		return "", err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusCreated {
		msg := fmt.Sprintf("status code: %d", res.StatusCode)
		zlog.Error(msg, nil)
		return "", fmt.Errorf(msg)
	}

	location := res.Header.Get("Location")
	userID := path.Base(location)

	err = s.emailActionService.SendExecuteActionsEmail(
		tenant,
		tenant,
		userID,
		token,
		[]models.EmailAction{models.EmailActions.VerifyEmail, models.EmailActions.UpdatePassword})

	if err != nil {
		zlog.Error("failed to send execute actios email", err)
		return "", err
	}

	return userID, nil
}

func (s UserService) LoginAsAdmin() (string, error) {
	return s.Login("admin", "admin", "admin-cli", nil)
}

func (s UserService) Login(username, password, clientID string, clientSecret *string) (string, error) {
	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("username", username)
	form.Set("password", password)
	form.Set("grant_type", "password")

	if clientSecret != nil {
		form.Set("client_secret", *clientSecret)
	}

	url := fmt.Sprintf("%s/realms/master/protocol/openid-connect/token", s.keycloakAPI)

	req, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := s.client.Do(req)
	if err != nil {
		zlog.Error("failed http req", err)
		return "", err
	}

	defer res.Body.Close()

	body, err := io.ReadAll(res.Body)
	if err != nil {
		zlog.Error("failed to read res body", err)
		return "", err
	}

	var data struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresIn   int    `json:"expires_in"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
		zlog.Error("failed to unmarshal data", err)
		return "", err
	}

	return data.AccessToken, nil
}
