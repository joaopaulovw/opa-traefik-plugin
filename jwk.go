package opa_traefik_plugin

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
)

// JWK representation.
type JWK struct {
	Keys []Key `json:"keys"`
}

// Key of JWK representation.
type Key struct {
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	Kty string   `json:"kty"`
	Alg string   `json:"alg"`
	E   string   `json:"e"`
	N   string   `json:"n"`
	X5t string   `json:"x5T"`
	X5c []string `json:"x5C"`
}

// GetPublicKey return public key.
func (key *Key) GetPublicKey() (*rsa.PublicKey, error) {
	nBytes, nEncodingErr := base64.RawURLEncoding.DecodeString(key.N)
	if nEncodingErr != nil {
		return nil, nEncodingErr
	}

	eBytes, eEncodingErr := base64.RawURLEncoding.DecodeString(key.E)
	if eEncodingErr != nil {
		return nil, eEncodingErr
	}

	publicKey := new(rsa.PublicKey)
	publicKey.N = new(big.Int).SetBytes(nBytes)
	publicKey.E = int(new(big.Int).SetBytes(eBytes).Uint64())

	return publicKey, nil
}

// fetchKeys method to fetch jwk keys.
func fetchKeys(jwks string) (*JWK, error) {
	response, getErr := http.Get(jwks)
	if getErr != nil {
		return nil, fmt.Errorf("fail to fetch keys (JWK)")
	}

	body, readErr := io.ReadAll(response.Body)
	if readErr != nil {
		return nil, fmt.Errorf("fail to read keys (JWK)")
	}

	jwk := &JWK{}

	unmarshalErr := json.Unmarshal(body, &jwk)
	if unmarshalErr != nil {
		return nil, fmt.Errorf("fail to unmarshal keys (JWK)")
	}

	return jwk, nil
}
