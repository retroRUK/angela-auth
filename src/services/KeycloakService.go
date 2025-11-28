package services

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/redis/go-redis/v9"
	"github.com/retroRUK/zlog"
	"github.com/retroruk/centralized-devops-auth/src/models"
	"github.com/retroruk/centralized-devops-auth/src/utilities"
	"golang.org/x/oauth2"
)

var stateConfig = make(map[string]models.OauthSession)

type KeycloakClient struct {
	config   *models.KeycloakConfig
	verifier *oidc.IDTokenVerifier
}

type KeycloakService struct {
	db          *sql.DB
	rdb         *redis.Client
	client      *http.Client
	keycloakAPI string
	authSvcAPI  string
}

func InitKeycloakService(db *sql.DB, rdb *redis.Client) *KeycloakService {
	return &KeycloakService{
		db:          db,
		rdb:         rdb,
		client:      utilities.NewHttpClient(),
		keycloakAPI: utilities.GetEnv("KEYCLOAK_API"),
		authSvcAPI:  utilities.GetEnv("AUTH_SERVICE_API"),
	}
}

func (s KeycloakService) CreateSession(realm string) (models.OauthSession, string, error) {
	oauthConfig := &oauth2.Config{
		RedirectURL: fmt.Sprintf("%s/api/v1/auth/callback/login", s.authSvcAPI),
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
	}

	row := s.db.QueryRow("SELECT client_id, client_secret FROM keycloak WHERE realm = $1;", realm)
	if row.Err() != nil {
		zlog.Error("failed sql query", row.Err())
		return models.OauthSession{}, "", row.Err()
	}

	if err := row.Scan(&oauthConfig.ClientID, &oauthConfig.ClientSecret); err != nil {
		zlog.Error("failed to scan db row", err)
		return models.OauthSession{}, "", err
	}

	provider, err := oidc.NewProvider(context.Background(), fmt.Sprintf("%s/realms/%s", s.keycloakAPI, realm))
	if err != nil {
		zlog.Error("failed to create new provider", err)
		return models.OauthSession{}, "", err
	}

	oauthConfig.Endpoint = provider.Endpoint()
	sessionID := utilities.GenerateRandomEncodedByteString(32)
	session := models.OauthSession{OauthConfig: oauthConfig, Realm: realm}

	if err := s.SaveSession(sessionID, session, 30*time.Minute); err != nil {
		zlog.Error("failed to save session", err)
		return models.OauthSession{}, "", err
	}
	return session, sessionID, nil
}

func (s KeycloakService) SaveSession(sessionID string, session models.OauthSession, ttl time.Duration) error {
	sessionBytes, err := json.Marshal(session)
	if err != nil {
		zlog.Error("failed to marshal session", err)
		return err
	}

	if err := s.rdb.Set(context.Background(), sessionID, sessionBytes, ttl).Err(); err != nil {
		zlog.Error("failed to set redis session", err)
		return err
	}

	return nil
}

func (s KeycloakService) GetSession(sessionID string) (models.OauthSession, error) {
	data, err := s.rdb.Get(context.Background(), sessionID).Result()
	if err != nil {
		zlog.Error("failed to get redis session", err)
		return models.OauthSession{}, err
	}

	var session models.OauthSession
	if err := json.Unmarshal([]byte(data), &session); err != nil {
		zlog.Error("failed to unmarshal session", err)
		return models.OauthSession{}, err
	}

	return session, nil
}

func (s KeycloakService) HandleLoginCallback(sessionID string, code string) (string, error) {
	ctx := context.Background()

	session, err := s.GetSession(sessionID)
	if err != nil {
		zlog.Error("failed to get session", err)
		return sessionID, err
	}

	tokens, err := s.ExchangeCodeForTokens(ctx, sessionID, code)
	if err != nil {
		zlog.Error("failed to exchange code for token", err)
		return sessionID, err
	}

	claims, err := s.GetClaims(ctx, tokens.IDToken, session.Realm)
	if err != nil {
		return sessionID, err
	}

	userInfo, err := s.GetUserInfo(session.Realm, tokens.AccessToken)
	if err != nil {
		zlog.Error("failed to get user info", err)
		return sessionID, err
	}

	session.Tokens = tokens
	session.Claims = claims
	session.UserInfo = userInfo
	session.OauthConfig = nil // set to nil because it's not needed after the callback

	if err := s.SaveSession(sessionID, session, time.Duration(tokens.ExpiresIn*int64(time.Second))); err != nil {
		zlog.Error("failed to save session", err)
		return sessionID, err
	}

	return sessionID, nil
}

func (s KeycloakService) GetClaims(ctx context.Context, rawIdToken string, realm string) (models.KeycloakClaims, error) {
	var claims models.KeycloakClaims

	idToken, ok := s.ValidateIdToken(ctx, rawIdToken, realm)
	if !ok {
		zlog.Error("could not validate token", nil)
		return claims, fmt.Errorf("could not validate id token")
	}

	if err := idToken.Claims(&claims); err != nil {
		zlog.Error("could not get claims", err)
		return claims, err
	}

	return claims, nil
}

func (s KeycloakService) ExchangeCodeForTokens(ctx context.Context, sessionID string, code string) (models.KeycloakTokens, error) {
	var tokens models.KeycloakTokens

	session, err := s.GetSession(sessionID)
	if err != nil {
		zlog.Error("failed to get session", err)
		return tokens, err
	}

	t, err := session.OauthConfig.Exchange(ctx, code)
	if err != nil {
		zlog.Error("failed to exchange code", err)
		return tokens, err
	}

	rawIdToken, ok := t.Extra("id_token").(string)
	if !ok {
		zlog.Error("no raw id token found in token response", err)
		return tokens, fmt.Errorf("no raw id token found in token response")
	}

	tokens.AccessToken = t.AccessToken
	tokens.ExpiresIn = t.ExpiresIn
	tokens.TokenType = t.TokenType
	tokens.IDToken = rawIdToken
	tokens.TokenType = t.TokenType
	tokens.RefreshToken = t.RefreshToken

	return tokens, nil
}

func (s KeycloakService) GetUserInfo(realm string, accessToken string) (models.KeycloakUserInfo, error) {
	var userInfo models.KeycloakUserInfo

	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/userinfo", s.keycloakAPI, realm)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		zlog.Error("failed to create http req", err)
		return userInfo, err
	}

	req.Header.Set("Authorization", "Bearer "+accessToken)

	res, err := s.client.Do(req)
	if err != nil {
		zlog.Error("failed http res", err)
		return userInfo, err
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		zlog.Error(fmt.Sprintf("failed to get user info, status: %d", res.StatusCode), err)
		return userInfo, fmt.Errorf("failed to get user info, status: %d", res.StatusCode)
	}

	if err := json.NewDecoder(res.Body).Decode(&userInfo); err != nil {
		zlog.Error("failed to decode res body", err)
		return userInfo, err
	}

	return userInfo, nil
}

func (s KeycloakService) ValidateIdToken(ctx context.Context, rawIdToken string, realm string) (*oidc.IDToken, bool) {
	provider, err := oidc.NewProvider(ctx, fmt.Sprintf("%s/realms/%s", s.keycloakAPI, realm))
	if err != nil {
		zlog.Error("failed to create new provider", err)
		return nil, false
	}

	row := s.db.QueryRow("SELECT client_id FROM keycloak WHERE realm = $1", realm)
	var clientID string
	if err := row.Scan(&clientID); err != nil {
		zlog.Error("failed to scan db row", err)
		return nil, false
	}

	verifier := provider.Verifier(&oidc.Config{
		ClientID:          clientID,
		SkipClientIDCheck: false,
		SkipExpiryCheck:   false,
	})

	idToken, err := verifier.Verify(ctx, rawIdToken)
	if err != nil {
		zlog.Error("failed to verify idToken", err)
		return nil, false
	}

	return idToken, true
}

func (s KeycloakService) RefreshTokens(sessionID string) (int64, error) {
	session, err := s.GetSession(sessionID)
	if err != nil {
		zlog.Error("failed to get session", err)
		return -1, err
	}

	var clientID string
	var clientSecret string
	row := s.db.QueryRow("SELECT client_id, client_secret FROM keycloak WHERE realm = $1", session.Realm)
	if err := row.Scan(&clientID, &clientSecret); err != nil {
		zlog.Error("failed to scan row", err)
		return -1, err
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("refresh_token", session.Tokens.RefreshToken)
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)

	req, err := http.NewRequest("POST", fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", s.keycloakAPI, session.Realm), strings.NewReader(data.Encode()))
	if err != nil {
		zlog.Error("faild to create http req", err)
		return -1, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := s.client.Do(req)
	if err != nil {
		zlog.Error("failed http res", err)
		return -1, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		msg := fmt.Sprintf("status code: %d", res.StatusCode)
		zlog.Error(msg, fmt.Errorf(msg))
		return -1, fmt.Errorf(msg)
	}

	var tokens models.KeycloakTokens
	if err := json.NewDecoder(res.Body).Decode(&tokens); err != nil {
		zlog.Error("failed to decode tokens", err)
		return -1, err
	}

	session.Tokens = tokens

	return session.Tokens.ExpiresIn, s.SaveSession(sessionID, session, time.Duration(session.Tokens.ExpiresIn*int64(time.Second)))
}

func (s KeycloakService) Logout(sessionID string) error {
	session, err := s.GetSession(sessionID)
	if err != nil {
		zlog.Error("failed to get session", err)
		return err
	}

	var clientID string
	var clientSecret string
	row := s.db.QueryRow("SELECT client_id, client_secret FROM keycloak WHERE realm = $1;", session.Realm)
	if err := row.Scan(&clientID, &clientSecret); err != nil {
		zlog.Error("failed to scan row", err)
		return err
	}

	form := url.Values{}
	form.Set("client_id", clientID)
	form.Set("client_secret", clientSecret)
	form.Set("refresh_token", session.Tokens.RefreshToken)

	url := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout", s.keycloakAPI, session.Realm)
	req, _ := http.NewRequest("POST", url, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	res, err := s.client.Do(req)
	if err != nil {
		zlog.Error("failed http res", err)
		return err
	}

	if res.StatusCode != http.StatusNoContent {
		msg := fmt.Sprintf("status code: %d", res.StatusCode)
		zlog.Error(msg, nil)
		return fmt.Errorf(msg)
	}

	if err := s.rdb.Del(context.Background(), sessionID).Err(); err != nil {
		zlog.Error("failed to del session", err)
		return err
	}

	return nil
}

func (s KeycloakService) RealmExists(realm string) (bool, error) {
	url := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", s.keycloakAPI, realm)

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	res, err := s.client.Do(req)
	if err != nil {
		zlog.Error("failed http res", err)
		return false, err
	}
	return res.StatusCode == http.StatusOK, nil
}

func (s KeycloakService) LoginAsAdmin() (string, error) {
	form := url.Values{}
	form.Set("client_id", "admin-cli")
	form.Set("username", "admin") //TODO: update this to pull from secret store
	form.Set("password", "admin") //TODO: update this to pull form secret store
	form.Set("grant_type", "password")

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

func (s KeycloakService) CreateRealm(createRealmRequest models.CreateRealmRequest) error {
	payload := map[string]any{
		"realm":   createRealmRequest.Realm,
		"enabled": true,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		zlog.Error("failed to marshal payload", err)
		return err
	}

	url := fmt.Sprintf("%s/admin/realms", s.keycloakAPI)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payloadBytes))
	if err != nil {
		zlog.Error("failed to create http req", err)
		return err
	}

	token, err := s.LoginAsAdmin()
	if err != nil {
		zlog.Error("failed to login as admin", err)
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

	if res.StatusCode != http.StatusCreated {
		msg := fmt.Sprintf("status code: %d", res.StatusCode)
		zlog.Error(msg, nil)
		return fmt.Errorf(msg)
	}

	if err := s.SetupRealmEmail(
		createRealmRequest.Realm,
		token,
		createRealmRequest.SmtpEmail,
		createRealmRequest.SmtpPassword,
	); err != nil {
		zlog.Error("failed to setup realm email", err)
		return err
	}

	clientSecret, err := s.CreateClient(createRealmRequest.Realm, token)
	if err != nil {
		zlog.Error("failed to create client", err)
		return err
	}

	_, err = s.db.Query("INSERT INTO keycloak (client_id, client_secret, realm) VALUES ($1, $2, $3);", createRealmRequest.Realm, clientSecret, createRealmRequest.Realm)
	if err != nil {
		zlog.Error("failed to insert row into keylocak", err)
		return err
	}

	userID, err := s.CreateUser(createRealmRequest.Realm, createRealmRequest.Email, token)
	if err != nil {
		zlog.Error("failed to create user", err)
		return err
	}

	if err := s.SendExecuteActionsEmail(createRealmRequest.Realm, createRealmRequest.Realm, userID, token); err != nil {
		zlog.Error("failed to send actions email", err)
		return err
	}

	return nil
}

func (s KeycloakService) SetupRealmEmail(realm, token, smtpEmail, smtpPassword string) error {
	payload := models.KeycloakRealmStmpRequest{
		SMTPServer: models.KeycloakSmtpServer{
			Host:            "smtp.gmail.com",
			Port:            "587",
			From:            smtpEmail,
			FromDisplayName: "Angela",
			User:            smtpEmail,
			Password:        smtpPassword,
			Auth:            "true",
			SSL:             "false",
			StartTLS:        "true",
			AllowUTF8:       "true",
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		zlog.Error("failed to marshal payload", err)
		return err
	}

	url := fmt.Sprintf("%s/admin/realms/%s", s.keycloakAPI, realm)

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
		msg := fmt.Sprintf("status code: %d", res.StatusCode)
		zlog.Error(msg, nil)
		return fmt.Errorf(msg)
	}

	return nil
}

func (s KeycloakService) CreateClient(realm string, token string) (string, error) {
	clientSecret := utilities.GenerateRandomEncodedByteString(32)

	payload := models.KeycloakCreateClientRequest{
		ClientID:     realm,
		Secret:       clientSecret,
		Protocol:     "openid-connect",
		PublicClient: false,
		RedirectURIs: []string{
			fmt.Sprintf("%s/api/v1/auth/callback/login", s.authSvcAPI),
			fmt.Sprintf("%s/api/v1/auth/callback/emailActions", s.authSvcAPI),
		},
		StandardFlowEnabled:       true,
		DirectAccessGrantsEnabled: true,
		ServiceAccountsEnabled:    true,
		RootURL:                   fmt.Sprintf("%s", s.authSvcAPI),
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		zlog.Error("failed to marshal payload", err)
		return "", err
	}

	url := fmt.Sprintf("%s/admin/realms/%s/clients", s.keycloakAPI, realm)

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

	return clientSecret, nil
}

func (s KeycloakService) CreateUser(realm string, email string, token string) (string, error) {
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

	url := fmt.Sprintf("%s/admin/realms/%s/users", s.keycloakAPI, realm)

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

	return userID, nil
}

func (s KeycloakService) SendExecuteActionsEmail(realm string, clientID string, userID string, token string) error {
	redirectURI := fmt.Sprintf("%s/api/v1/auth/callback/emailActions", s.authSvcAPI)
	url := fmt.Sprintf("%s/admin/realms/%s/users/%s/execute-actions-email?client_id=%s&redirect_uri=%s",
		s.keycloakAPI, realm, userID, clientID, url.QueryEscape(redirectURI))

	payload := []string{"VERIFY_EMAIL", "UPDATE_PASSWORD"}

	payloadBytes, err := json.Marshal(payload)
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
