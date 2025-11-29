package models

type KeycloakUser struct {
	ID               string `json:"id"`
	Username         string `json:"username"`
	FirstName        string `json:"firstName"`
	LastName         string `json:"lastName"`
	Email            string `json:"email"`
	EmailVerified    bool   `json:"emailVerified"`
	Enabled          bool   `json:"enabled"`
	CreatedTimestamp int64  `json:"createdTimestamp"`
}
