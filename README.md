# Angela Auth Service

## Set up required services

- docker compose -f docker-compose.develop.yml up -d

## How to set up Keycloak

- go to http://localhost:8080
- go to Users
- click the admin user link
- update the email (use test email), first and last names
- check email verified
- click Save
- go to email tab
- click Realm Settings
- go to the Email tab
- update From to be the same test email as the admin user
- set host to smtp.gmail.com
- set port to 587
- check Enable StartTLS
- check Authentication enabled
- set username to the test email
- update password to the app password
- set UTF-8 to enabled
- click Save
- click Test Connection, ensure it worked

## Database

Below is the schema for the auth service, it is very simple and holds the information about tenants.

```mermaid
erDiagram
    tenants {
        BIGINT id
        VARCHAR(50) tenant
        VARCHAR(50) client_id
        VARCHAR(50) client_secret
    }
```

## Create Realm Sequence Diagram (Successful)

```mermaid
sequenceDiagram
    User ->> UI: Submits Form
    UI ->> Backend: Does realm exist?
    Backend ->> Auth Service: Does realm exist?
    Auth Service ->> Keycloak: Does realm exist?
    Keycloak -->> Auth Service: false
    Auth Service -->> Backend: false
    Backend -->> UI: false
    UI ->> Backend: Create Realm Request
    Backend ->> Auth Service: Create Realm Request
    Auth Service->>Keycloak: Create Realm with Client, Roles and User
    Keycloak -->> Auth Service: Respond OK
    Auth Service ->> Database: Insert tenant, realm and client info into Database
    Database -->> Auth Service: Successful
    Auth Service -->> Backend: Respond OK
    Backend -->> UI: Respond OK.
    UI -->> User: Display check email message
```

## Create Realm Sequence Diagram (Realm Already Exists)

```mermaid
sequenceDiagram
    User ->> UI: Submits Form
    UI ->> Backend: Submit Request
    Backend ->> Auth Service: Does realm exist?
    Auth Service ->> Keycloak: Does realm exist?
    Keycloak -->> Auth Service: true
    Auth Service -->> Backend: true
    Backend -->> UI: true
    UI -->> User: Display Tenant already exists
```

## Login Sequence Diagram

```mermaid
sequenceDiagram
    User ->> UI: Submits form
    UI ->> Backend: Redirect (Avoids CORS)
    Backend ->> Auth Service: Redirect
    Auth Service ->>  Redis: Create Oauth Session
    Redis -->> Auth Service: No errors
    Auth Service ->> Database: Get tenant's client secret
    Database --> Auth Service: Return client secret
    Auth Service ->> Auth Service: Add client creds to session
    Auth Service ->> Auth Service: Create OpenID Provider
    Auth Service ->> Auth Service: Generate session ID
    Auth Service ->> Redis: Save session
    Redis -->> Auth Service: No errors
    Auth Service ->> Keycloak: Redirect
    Keycloak ->> Keycloak: User inputs login credentls
    Keycloak -->> Auth Service: Callback
    Auth Service -->> Backend: Callback
    Backend -->> UI: Callback
    UI -->> User: Display Dashboard
```

## Logout Sequence Diagram

```mermaid
sequenceDiagram
    User ->> UI: Click Logout
    UI ->> Backend: Send Request
    Backend ->> Auth Service: Forward Request
    Auth Service ->> Redis: Get session
    Redis -->> Auth Service: Return session
    Auth Service ->> Database: Get tenant's client secret
    Database --> Auth Service: Return client secret
    Auth Service ->> Keycloak: POST Logout Request
    Keycloak -->> Auth Service: 204 No Content
    Auth Service ->> Redis: Delete session
    Redis -->> Auth Service: No errors
    Auth Service -->> Backend: 200 OK
    Backend -->> UI: 200 OK
    UI -->> User: Login View
```
