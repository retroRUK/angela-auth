package models

type KeycloakRealmMappings struct {
	Roles []KeycloakRole `json:"realmMappings"`
}

type KeycloakRole struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Composite   bool   `json:"composite"`
	ClientRole  bool   `json:"clientRole"`
	ContainerID string `json:"containterId"`
}
