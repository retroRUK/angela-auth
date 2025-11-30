package models

type KeycloakUserInfo struct {
	Email             string   `json:"email"`
	EmailVerified     bool     `json:"email_verified"`
	FamilyName        string   `json:"family_name"`
	GivenName         string   `json:"given_name"`
	Name              string   `json:"name"`
	PreferredUsername string   `json:"preferred_username"`
	Roles             []string `json:"roles"`
	Sub               string   `json:"sub"`
}
