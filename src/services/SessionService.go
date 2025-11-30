package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc"
	"github.com/redis/go-redis/v9"
	"github.com/retroRUK/zlog"
	"github.com/retroruk/angela-auth/src/models"
	"github.com/retroruk/angela-auth/src/utilities"
	"golang.org/x/oauth2"
)

type SessionService struct {
	db             *sql.DB
	rdb            *redis.Client
	client         *http.Client
	keycloakAPI    string
	authServiceAPI string
}

func InitSessionService(db *sql.DB, rdb *redis.Client) *SessionService {
	return &SessionService{
		db:             db,
		rdb:            rdb,
		client:         utilities.NewHttpClient(),
		keycloakAPI:    utilities.GetEnv("KEYCLOAK_API"),
		authServiceAPI: utilities.GetEnv("AUTH_SERVICE_API"),
	}
}

func (s SessionService) GetSession(sessionID string) (models.OauthSession, error) {
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

func (s SessionService) CreateSession(realm string) (models.OauthSession, string, error) {
	oauthConfig := &oauth2.Config{
		RedirectURL: fmt.Sprintf("%s/api/v1/auth/session/callback/login", s.authServiceAPI),
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

func (s SessionService) SaveSession(sessionID string, session models.OauthSession, ttl time.Duration) error {
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

func (s SessionService) GetUserInfo(sessionID string) (models.OauthSession, error) {
	var session models.OauthSession

	sessionStr, err := s.rdb.Get(context.Background(), sessionID).Result()
	if err != nil {
		return session, err
	}

	if err := json.Unmarshal([]byte(sessionStr), &session); err != nil {
		return session, err
	}

	return session, nil
}

func (s SessionService) LoginCallback(sessionID string, code string) (string, error) {
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

	userInfo, err := s.getUserInfo(session.Realm, tokens.AccessToken)
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

func (s SessionService) GetClaims(ctx context.Context, rawIdToken string, realm string) (models.KeycloakClaims, error) {
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

func (s SessionService) ExchangeCodeForTokens(ctx context.Context, sessionID string, code string) (models.KeycloakTokens, error) {
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

func (s SessionService) ValidateIdToken(ctx context.Context, rawIdToken string, realm string) (*oidc.IDToken, bool) {
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

func (s SessionService) getUserInfo(realm string, accessToken string) (models.KeycloakUserInfo, error) {
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

	log.Println(userInfo)

	return userInfo, nil
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

func (s SessionService) Logout(sessionID string) error {
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
