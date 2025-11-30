package controllers

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/retroRUK/zlog"
	"github.com/retroruk/angela-auth/src/services"
	"github.com/retroruk/angela-auth/src/utilities"
)

type SessionController struct {
	sessionService *services.SessionService
	backendAPI     string
}

func InitSessionController(mux *http.ServeMux, sessionService *services.SessionService) {
	c := &SessionController{
		sessionService: sessionService,
		backendAPI:     utilities.GetEnv("BACKEND_API"),
	}

	sub := http.NewServeMux()

	sub.HandleFunc("/login", c.login)
	sub.HandleFunc("/logout", c.logout)
	sub.HandleFunc("/callback/login", c.loginCallback)
	sub.HandleFunc("/getSession", c.getSession)
	sub.HandleFunc("/getUserInfo", c.getUserInfo)
	sub.HandleFunc("/hasRole", c.hasRole)

	mux.Handle("/api/v1/auth/session/", http.StripPrefix("/api/v1/auth/session", sub))
}

// LOGIN
func (c SessionController) login(w http.ResponseWriter, r *http.Request) {
	realm := r.URL.Query().Get("realm")
	if realm == "" {
		http.Redirect(w, r, fmt.Sprintf("%s/?error=invalid_realm", c.backendAPI), http.StatusFound)
		return
	}

	session, sessionID, err := c.sessionService.CreateSession(realm)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("%s/?error=invalid_realm", c.backendAPI), http.StatusFound)
		return
	}

	url := session.OauthConfig.AuthCodeURL(sessionID)
	http.Redirect(w, r, url, http.StatusFound)
}

// LOGOUT
func (c SessionController) logout(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("sessionID")
	if sessionID == "" {
		http.Error(w, "sessionID paramter is missing", http.StatusBadRequest)
		return
	}

	if err := c.sessionService.Logout(sessionID); err != nil {
		http.Error(w, fmt.Sprintf("failed to logout: %v", err), http.StatusInternalServerError)
		return
	}
}

// GET USER INFO
func (c SessionController) getUserInfo(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("sessionID")
	if sessionID == "" {
		http.Error(w, "sessionID param required", http.StatusBadRequest)
		return
	}

	session, err := c.sessionService.GetUserInfo(sessionID)
	if err != nil {
		msg := fmt.Sprintf("failed to retrieve user info: %v", err)
		log.Println(msg)
		http.Error(w, msg, http.StatusInternalServerError)
		return
	}

	payload := map[string]any{
		"userInfo": session.UserInfo,
		"realm":    session.Realm,
	}

	json.NewEncoder(w).Encode(payload)
}

// LOGIN CALLBACK
func (c SessionController) loginCallback(w http.ResponseWriter, r *http.Request) {
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

	_, err := c.sessionService.LoginCallback(sessionID, code)
	if err != nil {
		zlog.HttpError(w, "failed login callback", err, http.StatusInternalServerError)
		return
	}

	http.Redirect(w, r, fmt.Sprintf("%s/api/v1/auth/session/callback/login?sessionID=%s", c.backendAPI, sessionID), http.StatusFound)
}

// GET SESSION
func (c SessionController) getSession(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("sessionID")
	if sessionID == "" {
		zlog.HttpError(w, "sessionID param missing", nil, http.StatusBadRequest)
		return
	}

	_, err := c.sessionService.GetSession(sessionID)
	if err != nil {
		zlog.HttpError(w, "no session exists", err, http.StatusUnauthorized)
		return
	}
}

// HAS ROLE
func (c SessionController) hasRole(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("sessionID")
	role := r.URL.Query().Get("role")
	if sessionID == "" {
		zlog.HttpError(w, "required param missing", nil, http.StatusBadRequest)
		return
	}

	allowed, err := c.sessionService.HasRole(sessionID, role)
	if err != nil {
		zlog.HttpError(w, "no session exists", err, http.StatusUnauthorized)
		return
	}

	if allowed {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusForbidden)
	}
}
