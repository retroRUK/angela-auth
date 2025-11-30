package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/retroRUK/zlog"
	"github.com/retroruk/angela-auth/src/services"
)

type RealmController struct {
	realmService *services.RealmService
}

func InitRealmController(mux *http.ServeMux, realmService *services.RealmService) {
	c := &RealmController{
		realmService: realmService,
	}

	sub := http.NewServeMux()

	sub.HandleFunc("/create", c.create)
	sub.HandleFunc("/exists", c.exists)

	mux.Handle("/api/v1/auth/realm/", http.StripPrefix("/api/v1/auth/realm", sub))
}

func (c RealmController) create(w http.ResponseWriter, r *http.Request) {
	var req map[string]string
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		zlog.HttpError(w, "invalid req body", err, http.StatusBadRequest)
		return
	}

	tenant, ok := req["tenant"]
	if !ok || tenant == "" {
		zlog.HttpError(w, "tenant key missing or invalid value", nil, http.StatusBadRequest)
		return
	}

	email, ok := req["email"]
	if !ok || email == "" {
		zlog.HttpError(w, "email key missing or invalid value", nil, http.StatusBadRequest)
		return
	}

	if err := c.realmService.Create(tenant, email); err != nil {
		zlog.HttpError(w, "failed to create realm", err, http.StatusInternalServerError)
		return
	}
}

func (c RealmController) exists(w http.ResponseWriter, r *http.Request) {
	realm := r.URL.Query().Get("realm")
	if realm == "" {
		zlog.HttpError(w, "missing realm param", nil, http.StatusBadRequest)
		return
	}

	exists, err := c.realmService.Exists(realm)
	if err != nil {
		zlog.HttpError(w, "failed to get exists res", err, http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(map[string]bool{"exists": exists}); err != nil {
		zlog.HttpError(w, "failed to encode res", err, http.StatusInternalServerError)
		return
	}
}
