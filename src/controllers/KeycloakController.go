package controllers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/retroRUK/zlog"
	"github.com/retroruk/centralized-devops-auth/src/models"
	"github.com/retroruk/centralized-devops-auth/src/services"
	"github.com/retroruk/centralized-devops-auth/src/utilities"
)

type KeycloakController struct {
	keycloakService *services.KeycloakService
	backendAPI      string
}

func InitKeycloakController(mux *http.ServeMux, keycloakService *services.KeycloakService) {
	c := &KeycloakController{
		keycloakService: keycloakService,
		backendAPI:      utilities.GetEnv("BACKEND_API"),
	}

	mux.HandleFunc("/api/v1/auth/login", c.login)
	mux.HandleFunc("/api/v1/auth/logout", c.logout)
	mux.HandleFunc("/api/v1/auth/callback/login", c.handleLoginCallback)
	mux.HandleFunc("/api/v1/auth/checkSession", c.checkSession)
	mux.HandleFunc("/api/v1/auth/refreshToken", c.refreshToken)
	mux.HandleFunc("/api/v1/auth/realmExists", c.realmExists)
	mux.HandleFunc("/api/v1/auth/createRealm", c.createRealm)
	mux.HandleFunc("/api/v1/auth/createClient", c.createClient)
	mux.HandleFunc("/api/v1/auth/callback/emailActions", c.handleEmailActionsCallback)
}

func (c KeycloakController) login(w http.ResponseWriter, r *http.Request) {
	realm := r.URL.Query().Get("realm")
	if realm == "" {
		http.Redirect(w, r, fmt.Sprintf("%s/?error=invalid_realm", c.backendAPI), http.StatusFound)
		return
	}

	session, sessionID, err := c.keycloakService.CreateSession(realm)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("%s/?error=invalid_realm", c.backendAPI), http.StatusFound)
		return
	}

	url := session.OauthConfig.AuthCodeURL(sessionID)
	http.Redirect(w, r, url, http.StatusFound)
}

func (c KeycloakController) logout(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("sessionID")
	if sessionID == "" {
		http.Error(w, "sessionID paramter is missing", http.StatusBadRequest)
		return
	}

	if err := c.keycloakService.Logout(sessionID); err != nil {
		http.Error(w, fmt.Sprintf("failed to logout: %v", err), http.StatusInternalServerError)
		return
	}
}

func (c KeycloakController) handleEmailActionsCallback(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, fmt.Sprintf("%s/api/v1/auth/callback/emailActions", c.backendAPI), http.StatusFound)
}

func (c KeycloakController) handleLoginCallback(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("state")
	if sessionID == "" {
		zlog.HttpError(w, "missing state param", nil, http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		zlog.HttpError(w, "missing keycloak code", nil, http.StatusBadRequest)
		return
	}

	_, err := c.keycloakService.HandleLoginCallback(sessionID, code)
	if err != nil {
		zlog.HttpError(w, "failed login callback", err, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("%s/api/v1/auth/callback/login?sessionID=%s", c.backendAPI, sessionID), http.StatusFound)
}

func (c KeycloakController) checkSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("sessionID")
	if sessionID == "" {
		zlog.HttpError(w, "sessionID param missing", nil, http.StatusBadRequest)
		return
	}

	_, err := c.keycloakService.GetSession(sessionID)
	if err != nil {
		zlog.HttpError(w, "no session exists", err, http.StatusUnauthorized)
		return
	}
}

func (c KeycloakController) refreshToken(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("sessionID")
	if sessionID == "" {
		http.Error(w, "sessionID paramter is required", http.StatusBadRequest)
		return
	}

	expiresIn, err := c.keycloakService.RefreshTokens(sessionID)
	if err != nil {
		http.Error(w, "failed to refresh token", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]int64{"expiresIn": expiresIn})
}

func (c KeycloakController) realmExists(w http.ResponseWriter, r *http.Request) {
	realm := r.URL.Query().Get("realm")
	if realm == "" {
		http.Error(w, "realm parameter is required", http.StatusBadRequest)
		return
	}

	exists, err := c.keycloakService.RealmExists(realm)
	if err != nil {
		http.Error(w, "failed to check if realm exists", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]bool{"exists": exists})
}

func (c KeycloakController) createRealm(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var createRealmRequest models.CreateRealmRequest
	json.NewDecoder(r.Body).Decode(&createRealmRequest)

	if err := c.keycloakService.CreateRealm(createRealmRequest); err != nil {
		log.Println(err)
		http.Error(w, "failed to create realm", http.StatusInternalServerError)
		return
	}
}

func (c KeycloakController) createClient(w http.ResponseWriter, r *http.Request) {
	realm := r.URL.Query().Get("realm")
	if realm == "" {
		http.Error(w, "realm parameter required", http.StatusBadRequest)
		return
	}

	token, err := c.keycloakService.LoginAsAdmin()
	if err != nil {
		http.Error(w, "failed to login as admin", http.StatusUnauthorized)
		return
	}

	_, err = c.keycloakService.CreateClient(realm, token)
	if err != nil {
		http.Error(w, "failed to create client", http.StatusInternalServerError)
		return
	}
}
