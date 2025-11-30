package models

import "time"

type KeycloakTokens struct {
	AccessToken      string    `json:"access_token"`
	ExpiresIn        int64     `json:"expires_in"`
	AccessTokenExp   time.Time `json:"access_token_exp"`
	RefreshToken     string    `json:"refresh_token"`
	RefreshExpiresIn int64     `json:"refresh_expires_in"`
	RefreshTokenExp  time.Time `json:"refresh_token_exp"`
	IDToken          string    `json:"id_token"`
	TokenType        string    `json:"token_type"`
	Scope            string    `json:"scope"`
}
