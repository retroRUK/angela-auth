package models

type RealmRepresentation struct {
	Realm      string                 `json:"realm"`
	Enabled    bool                   `json:"enabled"`
	Clients    []ClientRepresentation `json:"clients"`
	Users      []UserRepresentation   `json:"users"`
	SMTPServer SMTPRepresentation     `json:"smtpServer"`
}
