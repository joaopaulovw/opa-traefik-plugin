// Package opaplugin traefik plugin.
package opaplugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/MicahParks/keyfunc/v2"
	"github.com/golang-jwt/jwt/v5"
)

// Config the plugin configuration.
type Config struct {
	Endpoint string
	Allow    string
	Jwks     string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// Opa opa Opa plugin.
type Opa struct {
	next     http.Handler
	endpoint string
	allow    string
	jwks     string
}

// New created a new Opa plugin.
func New(_ context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	return &Opa{
		next:     next,
		endpoint: config.Endpoint,
		allow:    config.Allow,
		jwks:     config.Jwks,
	}, nil
}

func (opa *Opa) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	input := Input{
		Host:       req.Host,
		Method:     req.Method,
		Path:       strings.Split(req.URL.Path, "/")[1:],
		Parameters: req.URL.Query(),
		Headers:    req.Header,
	}

	authorization := req.Header.Get("Authorization")

	if len(authorization) > 0 {
		bearerToken := strings.Split(authorization, " ")[1]

		token, err := opa.ParseJWT(bearerToken)
		if err != nil {
			http.Error(rw, fmt.Sprintf("Unauthorized: %s", err.Error()), http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(rw, "Unauthorized: invalid token", http.StatusUnauthorized)
			return
		}

		bts, err := json.Marshal(token)
		if err != nil {
			http.Error(rw, fmt.Sprintf("InternalServerError: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		err = json.Unmarshal(bts, &input.Token)

		if err != nil {
			http.Error(rw, fmt.Sprintf("InternalServerError: %s", err.Error()), http.StatusInternalServerError)
			return
		}
	}

	if (len(opa.allow) == 0) || (len(opa.endpoint) == 0) {
		http.Error(rw, "Forbidden: opa 'allow' or 'bundlePath' not found", http.StatusForbidden)
		return
	}

	result, err := opa.ValidatePolicies(input)

	if err != nil || !result {
		http.Error(rw, fmt.Sprintf("Forbidden: %s", err.Error()), http.StatusForbidden)
		return
	}

	opa.next.ServeHTTP(rw, req)
}

// Input represent opa input.
type Input struct {
	Host       string                 `json:"host"`
	Method     string                 `json:"method"`
	Path       []string               `json:"path"`
	Parameters url.Values             `json:"parameters"`
	Headers    map[string][]string    `json:"headers"`
	Token      map[string]interface{} `json:"token"`
}

// Body represent opa body post request.
type Body struct {
	Input Input `json:"input"`
}

// Response represent opa body post response.
type Response struct {
	Result map[string]json.RawMessage `json:"result"`
}

// ValidatePolicies validate policies.
func (opa *Opa) ValidatePolicies(input Input) (bool, error) {
	body := Body{
		Input: input,
	}

	data, err := json.Marshal(body)
	if err != nil {
		return false, err
	}

	response, err := http.Post(opa.endpoint, "application/json", bytes.NewBuffer(data))
	if err != nil {
		return false, err
	}

	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return false, err
	}

	var responseData Response
	err = json.Unmarshal(responseBody, &responseData)
	if err != nil {
		return false, err
	}

	allowResponseData := responseData.Result[opa.allow]

	var allow bool
	if err = json.Unmarshal(allowResponseData, &allow); err != nil {
		return false, err
	}

	return allow, nil
}

// ParseJWT return parsed token.
func (opa *Opa) ParseJWT(bearerToken string) (*jwt.Token, error) {
	if len(opa.jwks) == 0 {
		return nil, errors.New("opa 'jwks' not founded")
	}

	ctx := context.Background()

	options := keyfunc.Options{
		Ctx:               ctx,
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}

	jwks, err := keyfunc.Get(opa.jwks, options)
	if err != nil {
		return nil, err
	}

	return jwt.Parse(bearerToken, jwks.Keyfunc)
}
