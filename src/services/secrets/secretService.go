package secretServices

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/retroRUK/zlog"
	"github.com/retroruk/angela-auth/src/utilities"
)

type SecretService struct {
	secretServiceAPI string
	httpClient       *http.Client
}

func InitSecretService() *SecretService {
	return &SecretService{
		secretServiceAPI: utilities.GetEnv("SECRET_SERVICE_API"),
		httpClient:       utilities.NewHttpClient(),
	}
}

func (s SecretService) GetKV(mount, path string) (map[string]string, error) {
	url := fmt.Sprintf("%s/api/v1/secret/kv/get?mount=%s&path=%s", s.secretServiceAPI, mount, path)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		zlog.Error("failed to create req", err)
		return nil, err
	}

	res, err := s.httpClient.Do(req)
	if err != nil {
		zlog.Error("failed http req", err)
		return nil, err
	}
	defer res.Body.Close()

	secrets := make(map[string]string)
	if err := json.NewDecoder(res.Body).Decode(&secrets); err != nil {
		zlog.Error("failed to decode res body", err)
		return nil, err
	}

	return secrets, nil
}
