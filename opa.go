// Package opa_traefik_plugin traefik plugin.
package opa_traefik_plugin

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

// nolint
var (
	// LoggerDEBUG level.
	LoggerDEBUG = log.New(ioutil.Discard, "DEBUG: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile)
	// LoggerINFO level.
	LoggerINFO = log.New(ioutil.Discard, "INFO: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile)
	// LoggerERROR level.
	LoggerERROR = log.New(ioutil.Discard, "ERROR: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile)
)

// Config the plugin configuration.
type Config struct {
	Endpoint string `json:"endpoint,omitempty"`
	Allow    string `json:"allow,omitempty"`
	Jwks     string `json:"jwks,omitempty"`
	LogLevel string `json:"logLevel,omitempty"`
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
	SetLogger(config.LogLevel)

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
		token, parseJWTErr := parseJWT(authorization)
		if parseJWTErr != nil {
			http.Error(rw, fmt.Sprintf("Unauthorized: %s", parseJWTErr.Error()), http.StatusUnauthorized)
			return
		}

		jwk, fetchKeysErr := fetchKeys(opa.jwks)
		if fetchKeysErr != nil {
			http.Error(rw, fmt.Sprintf("InternalServerError: %s", fetchKeysErr.Error()), http.StatusInternalServerError)
			return
		}

		tokenValid := false
		var publicKey *rsa.PublicKey
		for _, key := range jwk.Keys {
			pubkey, err := key.GetPublicKey()
			if err != nil {
				continue
			}
			publicKey = pubkey

			if token.Verify(pubkey) {
				tokenValid = true
				break
			}
		}

		keys, err := json.Marshal(jwk)
		if err == nil {
			LoggerDEBUG.Printf("fetch keys result: '%s'", string(keys))
		} else {
			LoggerDEBUG.Printf("error: '%s'", err.Error())
		}

		if publicKey == nil {
			LoggerDEBUG.Printf("public key is nil")
		} else {
			LoggerDEBUG.Printf("public key: '%T'", publicKey.Size())
		}

		if !tokenValid {
			http.Error(rw, "Unauthorized: invalid token", http.StatusUnauthorized)
			return
		}

		input.TokenPayload = token.payload
	}

	if (len(opa.allow) == 0) || (len(opa.endpoint) == 0) {
		http.Error(rw, "Forbidden: opa 'allow' or 'bundlePath' not found", http.StatusForbidden)
		return
	}

	result, validatePoliciesErr := validatePolicies(opa.endpoint, opa.allow, input)
	if validatePoliciesErr != nil {
		http.Error(rw, fmt.Sprintf("Forbidden: %s", validatePoliciesErr.Error()), http.StatusForbidden)
		return
	}

	if !result {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}

	opa.next.ServeHTTP(rw, req)
}

// Input represent opa input.
type Input struct {
	Host         string                 `json:"host"`
	Method       string                 `json:"method"`
	Path         []string               `json:"path"`
	Parameters   url.Values             `json:"parameters"`
	Headers      map[string][]string    `json:"headers"`
	TokenPayload map[string]interface{} `json:"tokenPayload"`
}

// Body represent opa body post request.
type Body struct {
	Input Input `json:"input"`
}

// Response represent opa body post response.
type Response struct {
	Result map[string]json.RawMessage `json:"result"`
}

// validatePolicies validate policies.
func validatePolicies(endpoint, allow string, input Input) (bool, error) {
	body := Body{
		Input: input,
	}

	data, MarshalErr := json.Marshal(body)
	if MarshalErr != nil {
		return false, MarshalErr
	}

	response, postErr := http.Post(endpoint, "application/json", bytes.NewBuffer(data))
	if postErr != nil {
		return false, postErr
	}

	responseBody, readErr := io.ReadAll(response.Body)
	if readErr != nil {
		return false, readErr
	}

	var responseData Response
	if bodyUnmarshalErr := json.Unmarshal(responseBody, &responseData); bodyUnmarshalErr != nil {
		return false, bodyUnmarshalErr
	}

	allowResponseData := responseData.Result[allow]

	var allowed bool
	if allowUnmarshalErr := json.Unmarshal(allowResponseData, &allowed); allowUnmarshalErr != nil {
		return false, allowUnmarshalErr
	}

	return allowed, nil
}

// SetLogger define global logger based in logLevel conf.
func SetLogger(level string) {
	switch level {
	case "ERROR":
		LoggerERROR.SetOutput(os.Stderr)
	case "INFO":
		LoggerERROR.SetOutput(os.Stderr)
		LoggerINFO.SetOutput(os.Stdout)
	case "DEBUG":
		LoggerERROR.SetOutput(os.Stderr)
		LoggerINFO.SetOutput(os.Stdout)
		LoggerDEBUG.SetOutput(os.Stdout)
	default:
		LoggerERROR.SetOutput(os.Stderr)
		LoggerINFO.SetOutput(os.Stdout)
	}
}
