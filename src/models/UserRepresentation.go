package models

type UserRepresentation struct {
	ID               string              `json:"id,omitempty"`
	Username         string              `json:"username"`
	FirstName        string              `json:"firstName,omitempty"`
	LastName         string              `json:"lastName,omitempty"`
	Email            string              `json:"email"`
	EmailVerified    bool                `json:"emailVerified"`
	Enabled          bool                `json:"enabled"`
	CreatedTimestamp int64               `json:"createdTimestamp,omitempty"`
	RealmRoles       []string            `json:"realmRoles,omitempty"`
	ClientRoles      map[string][]string `json:"clientRoles,omitempty"`
	RequiredActions  []EmailAction       `json:"requiredActions"`
}
