package models

type SMTPRepresentation struct {
	Host            string `json:"host"`
	Port            string `json:"port"`
	From            string `json:"from"`
	FromDisplayName string `json:"fromDisplayName"`
	User            string `json:"user"`
	Password        string `json:"password"`
	Auth            string `json:"auth"`
	SSL             string `json:"ssl"`
	StartTLS        string `json:"starttls"`
	AllowUTF8       string `json:"allowUtf8"`
}
