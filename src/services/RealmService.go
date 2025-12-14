package services

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/johnrukstalis/angela-auth/src/models"
	"github.com/johnrukstalis/angela-auth/src/utilities"
	"github.com/johnrukstalis/zlog"
)

type RealmService struct {
	client             *http.Client
	db                 *sql.DB
	authServiceAPI     string
	keycloakAPI        string
	userService        *UserService
	emailActionService *EmailActionService
	hostname           string
	smtpEmail          string
	smtpPassword       string
}

func InitRealmService(db *sql.DB, userService *UserService, emailActionService *EmailActionService) *RealmService {
	return &RealmService{
		client:             utilities.NewHttpClient(),
		db:                 db,
		keycloakAPI:        utilities.GetEnv("KEYCLOAK_API"),
		authServiceAPI:     utilities.GetEnv("AUTH_SERVICE_API"),
		hostname:           utilities.GetEnv("HOSTNAME"),
		userService:        userService,
		emailActionService: emailActionService,
		smtpEmail:          utilities.GetEnv("SMTP_EMAIL"),
		smtpPassword:       utilities.GetEnv("SMTP_PASSWORD"),
	}
}

func (s RealmService) Create(tenant, email string) error {
	clientSecret := utilities.GenerateRandomEncodedByteString(32)

	payload := models.RealmRepresentation{
		Realm:   tenant,
		Enabled: true,
		Clients: []models.ClientRepresentation{
			{
				ClientID:     tenant,
				Secret:       clientSecret,
				Protocol:     "openid-connect",
				PublicClient: false,
				RedirectURIs: []string{
					fmt.Sprintf("%s/api/v1/auth/session/callback/login", s.hostname),
					fmt.Sprintf("%s/api/v1/auth/emailAction/callback", s.hostname),
				},
				StandardFlowEnabled:       true,
				DirectAccessGrantsEnabled: true,
				ServiceAccountsEnabled:    true,
				RootURL:                   fmt.Sprintf("%s", s.authServiceAPI),
			},
		},
		Users: []models.UserRepresentation{
			{
				Username:      email,
				Enabled:       true,
				Email:         email,
				EmailVerified: false,
				RequiredActions: []models.EmailAction{
					models.EmailActions.UpdatePassword,
					models.EmailActions.VerifyEmail,
				},
				ClientRoles: map[string][]string{
					tenant: s.getAllClientRoles(),
				},
			},
		},
		SMTPServer: models.SMTPRepresentation{
			Host:            "smtp.gmail.com",
			Port:            "587",
			From:            s.smtpEmail,
			FromDisplayName: "Angela",
			User:            s.smtpEmail,
			Password:        s.smtpPassword,
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

	url := fmt.Sprintf("%s/admin/realms", s.keycloakAPI)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payloadBytes))
	if err != nil {
		zlog.Error("failed to create http req", err)
		return err
	}

	token, err := s.userService.LoginAsAdmin()
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
		body, err := io.ReadAll(res.Body)
		if err != nil {
			msg := fmt.Sprintf("status code: %d", res.StatusCode)
			zlog.Error(msg, nil)
			return err
		}
		msg := fmt.Sprintf("status code: %d, error: %s", res.StatusCode, string(body))
		zlog.Error(msg, nil)
		return fmt.Errorf(msg)
	}

	row := s.db.QueryRow("INSERT INTO auth.keycloak (client_id, client_secret, realm) VALUES ($1, $2, $3);", tenant, clientSecret, tenant)
	if row.Err() != nil {
		zlog.Error("failed to insert row", err)
		return err
	}

	user, err := s.userService.GetByUsername(tenant, email, token)
	if err != nil {
		zlog.Error("failed to get user", err)
		return err
	}

	actions := []models.EmailAction{
		models.EmailActions.UpdatePassword,
		models.EmailActions.VerifyEmail,
	}

	if err := s.emailActionService.SendExecuteActionsEmail(tenant, tenant, user.ID, token, actions); err != nil {
		zlog.Error("failed to send email actions", err)
		return err
	}

	return nil
}

func (s RealmService) Exists(realm string) (bool, error) {
	url := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", s.keycloakAPI, realm)

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	res, err := s.client.Do(req)
	if err != nil {
		zlog.Error("failed http res", err)
		return false, err
	}
	return res.StatusCode == http.StatusOK, nil
}

func (s RealmService) getAllClientRoles() []string {
	return []string{
		"auth::read",
		"auth::write",
		"auth::delete",
		"cloud::read",
		"cloud::write",
		"cloud::delete",
		"git::read",
		"git::write",
		"git::delete",
	}
}
