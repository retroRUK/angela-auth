package controllers

import (
	"fmt"
	"net/http"

	"github.com/retroruk/angela-auth/src/services"
	"github.com/retroruk/angela-auth/src/utilities"
)

type EmailActionController struct {
	emailActionService *services.EmailActionService
	backendAPI         string
}

func InitEmailActionController(mux *http.ServeMux, emailActionService *services.EmailActionService) {
	c := &EmailActionController{
		emailActionService: emailActionService,
		backendAPI:         utilities.GetEnv("BACKEND_API"),
	}

	sub := http.NewServeMux()

	sub.HandleFunc("/callback", c.callback)

	mux.Handle("/api/v1/auth/emailAction/", http.StripPrefix("/api/v1/auth/emailAction", sub))
}

func (c EmailActionController) callback(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, fmt.Sprintf("%s/api/v1/auth/emailAction/callback", c.backendAPI), http.StatusFound)
}
