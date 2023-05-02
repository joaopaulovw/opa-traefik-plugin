package opa_plugin

import (
	"context"
	"github.com/MicahParks/keyfunc/v2"
	"github.com/goccy/go-json"
	"github.com/golang-jwt/jwt/v5"
	"github.com/open-policy-agent/opa/rego"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Config the plugin configuration.
type Config struct {
	BundlePath string
	Allow      string
	Jwks       string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// Opa opa Opa plugin.
type Opa struct {
	next       http.Handler
	bundlePath string
	allow      string
	jwks       string
}

// New created a new Opa plugin.
func New(_ context.Context, next http.Handler, config *Config, _ string) (http.Handler, error) {
	return &Opa{
		next:       next,
		bundlePath: config.BundlePath,
		allow:      config.Allow,
		jwks:       config.Jwks,
	}, nil
}

func (opa *Opa) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	input := &Input{
		Host:       req.Host,
		Method:     req.Method,
		Path:       strings.Split(req.URL.Path, "/")[1:],
		Parameters: req.URL.Query(),
		Headers:    req.Header,
	}

	authorization := req.Header.Get("Authorization")

	if len(authorization) > 0 {
		bearerToken := strings.Split(authorization, " ")[1]

		if len(opa.jwks) <= 0 {
			http.Error(rw, "BadRequest", http.StatusBadRequest)
			return
		}

		token, err := parseJWT(bearerToken, opa.jwks)

		if err != nil {
			http.Error(rw, "Unauthorized", http.StatusUnauthorized)
			return
		}

		if !token.Valid {
			http.Error(rw, "Unauthorized", http.StatusUnauthorized)
			return
		}

		bytes, err := json.Marshal(token)

		if json.Unmarshal(bytes, &input.Token) != nil {
			http.Error(rw, "InternalServerError", http.StatusInternalServerError)
			return
		}
	}

	if (len(opa.allow) <= 0) || (len(opa.bundlePath) <= 0) {
		http.Error(rw, "BadRequest", http.StatusBadRequest)
		return
	}

	result, err := validatePolicies(opa.allow, opa.bundlePath, input)

	if err != nil || !result {
		http.Error(rw, "BadRequest", http.StatusForbidden)
		return
	}

	opa.next.ServeHTTP(rw, req)
}

type Input struct {
	Host       string                 `json:"host"`
	Method     string                 `json:"method"`
	Path       []string               `json:"path"`
	Parameters url.Values             `json:"parameters"`
	Headers    map[string][]string    `json:"headers"`
	Token      map[string]interface{} `json:"token"`
}

func validatePolicies(allow string, bundlePath string, input *Input) (bool, error) {
	results, err := opaQuery(allow, bundlePath, input)

	if err != nil {
		return false, err
	}

	if !results.Allowed() {
		return false, nil
	}

	return true, nil
}

func opaQuery(allow string, bundlePath string, input *Input) (rego.ResultSet, error) {
	ctx := context.Background()

	query, err := rego.New(rego.Query(allow), rego.LoadBundle(bundlePath)).PrepareForEval(ctx)

	if err != nil {
		return nil, err
	}

	return query.Eval(ctx, rego.EvalInput(input))
}

func parseJWT(bearerToken string, jwksURL string) (*jwt.Token, error) {
	ctx := context.Background()

	options := keyfunc.Options{
		Ctx:               ctx,
		RefreshInterval:   time.Hour,
		RefreshRateLimit:  time.Minute * 5,
		RefreshTimeout:    time.Second * 10,
		RefreshUnknownKID: true,
	}

	jwks, err := keyfunc.Get(jwksURL, options)

	if err != nil {
		return nil, err
	}

	return jwt.Parse(bearerToken, jwks.Keyfunc)
}
