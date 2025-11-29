package models

type EmailAction string

var EmailActions = struct {
	VerifyEmail    EmailAction
	UpdatePassword EmailAction
}{
	VerifyEmail:    EmailAction("VERIFY_EMAIL"),
	UpdatePassword: EmailAction("UPDATE_PASSWORD"),
}
