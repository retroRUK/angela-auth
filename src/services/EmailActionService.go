package services

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/johnrukstalis/angela-auth/src/models"
	"github.com/johnrukstalis/angela-auth/src/utilities"
	"github.com/johnrukstalis/zlog"
)

type EmailActionService struct {
	authServiceAPI       string
	keycloakAPI          string
	client               *http.Client
	publicAuthServiceAPI string
}

func InitEmailActionService() *EmailActionService {
	return &EmailActionService{
		client:               utilities.NewHttpClient(),
		keycloakAPI:          utilities.GetEnv("KEYCLOAK_API"),
		authServiceAPI:       utilities.GetEnv("AUTH_SERVICE_API"),
		publicAuthServiceAPI: utilities.GetEnv("PUBLIC_AUTH_SERVICE_API"),
	}
}

func (s EmailActionService) SendExecuteActionsEmail(tenant, clientID, userID, token string, actions []models.EmailAction) error {
	redirectURI := fmt.Sprintf("%s/api/v1/auth/emailAction/callback", s.publicAuthServiceAPI)
	url := fmt.Sprintf("%s/admin/realms/%s/users/%s/execute-actions-email?client_id=%s&redirect_uri=%s",
		s.keycloakAPI, tenant, userID, clientID, url.QueryEscape(redirectURI))

	payloadBytes, err := json.Marshal(actions)
	if err != nil {
		zlog.Error("failed to marshal payload", err)
		return err
	}

	req, err := http.NewRequest(http.MethodPut, url, bytes.NewReader(payloadBytes))
	if err != nil {
		zlog.Error("failed to create http req", err)
		return err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	res, err := s.client.Do(req)
	if err != nil {
		zlog.Error("failed http res", err)
		return err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusNoContent {
		body, err := io.ReadAll(res.Body)
		if err != nil {
			zlog.Error("failed to parse res body", err)
			return err
		}
		msg := fmt.Sprintf("status code: %d, error: %s", res.StatusCode, body)
		zlog.Error(msg, nil)
		return fmt.Errorf(msg)
	}

	return nil
}
