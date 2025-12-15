package controllers

import (
	"fmt"
	"net/http"

	"github.com/johnrukstalis/angela-auth/src/services"
	"github.com/johnrukstalis/angela-auth/src/utilities"
)

type EmailActionController struct {
	emailActionService *services.EmailActionService
	publicBackendAPI   string
}

func InitEmailActionController(mux *http.ServeMux, emailActionService *services.EmailActionService) {
	c := &EmailActionController{
		emailActionService: emailActionService,
		publicBackendAPI:   utilities.GetEnv("PUBLIC_BACKEND_API"),
	}

	sub := http.NewServeMux()

	sub.HandleFunc("/callback", c.callback)

	mux.Handle("/api/v1/auth/emailAction/", http.StripPrefix("/api/v1/auth/emailAction", sub))
}

func (c EmailActionController) callback(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, fmt.Sprintf("%s/backend/api/v1/auth/emailAction/callback", c.publicBackendAPI), http.StatusFound)
}
