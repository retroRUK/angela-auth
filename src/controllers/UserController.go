package controllers

import (
	"encoding/json"
	"net/http"

	"github.com/retroRUK/zlog"
	"github.com/retroruk/angela-auth/src/services"
)

type userController struct {
	userService *services.UserService
}

func InitUserController(mux *http.ServeMux, userService *services.UserService) {
	c := &userController{
		userService: userService,
	}

	// creates sub router
	sub := http.NewServeMux()

	sub.HandleFunc("/list", c.list)
	sub.HandleFunc("/getByID", c.getByID)
	sub.HandleFunc("/deleteByID", c.deleteByID)
	sub.HandleFunc("/create", c.create)

	// subrouter establishes prefix routes
	mux.Handle("/api/v1/auth/user/", http.StripPrefix("/api/v1/auth/user", sub))
}

func (c userController) list(w http.ResponseWriter, r *http.Request) {
	tenant := r.URL.Query().Get("tenant")
	if tenant == "" {
		zlog.HttpError(w, "missing required params", nil, http.StatusBadRequest)
		return
	}

	users, err := c.userService.List(tenant)
	if err != nil {
		zlog.HttpError(w, "failed to retrieve users", err, http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(users); err != nil {
		zlog.HttpError(w, "failed to encode users", err, http.StatusInternalServerError)
		return
	}
}

func (c userController) getByID(w http.ResponseWriter, r *http.Request) {
	tenant := r.URL.Query().Get("tenant")
	id := r.URL.Query().Get("id")
	if tenant == "" || id == "" {
		zlog.HttpError(w, "missing required params", nil, http.StatusBadRequest)
		return
	}

	user, err := c.userService.GetByID(tenant, id)
	if err != nil {
		zlog.HttpError(w, "failed to retrieve users", err, http.StatusInternalServerError)
		return
	}

	if err := json.NewEncoder(w).Encode(user); err != nil {
		zlog.HttpError(w, "failed to encode user", err, http.StatusInternalServerError)
		return
	}
}

func (c userController) deleteByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		zlog.HttpError(w, "method not allowed", nil, http.StatusMethodNotAllowed)
		return
	}

	tenant := r.URL.Query().Get("tenant")
	id := r.URL.Query().Get("id")
	if tenant == "" || id == "" {
		zlog.HttpError(w, "missing required params", nil, http.StatusBadRequest)
		return
	}

	if err := c.userService.DeleteByID(tenant, id); err != nil {
		zlog.HttpError(w, "failed to delete user", err, http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (c userController) create(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		zlog.HttpError(w, "method not allowed", nil, http.StatusMethodNotAllowed)
		return
	}

	var reqBody map[string]string
	if err := json.NewDecoder(r.Body).Decode(&reqBody); err != nil {
		zlog.HttpError(w, "invalid request body", err, http.StatusBadRequest)
		return
	}

	_, err := c.userService.Create(reqBody["tenant"], reqBody["email"])
	if err != nil {
		zlog.HttpError(w, "failed to create user", err, http.StatusInternalServerError)
		return
	}
}
