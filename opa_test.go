package opaplugin_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	opa "github.com/joaopaulovw/opa-traefik-plugin"
)

func TestOpa(t *testing.T) {
	cfg := opa.CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := opa.New(ctx, next, cfg, "opa-plugin")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)
}
