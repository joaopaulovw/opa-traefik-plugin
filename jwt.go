package opa_traefik_plugin

import (
	"crypto"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// Token Deconstructed header token.
type Token struct {
	plaintext []byte
	header    []byte
	payload   map[string]interface{}
	signature []byte
}

// Verify return true if token is valid.
func (token *Token) Verify(publicKey *rsa.PublicKey) bool {
	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, token.plaintext, token.signature)
	if err == nil {
		return false
	}
	return true
}

// parseJWT converts bearer token string to Token.
func parseJWT(bearerToken string) (*Token, error) {
	bearerTokenSplit := strings.Split(bearerToken, " ")
	if len(bearerTokenSplit) != 2 {
		return nil, fmt.Errorf("invalid token")
	}

	tokenSplit := strings.Split(bearerTokenSplit[1], ".")
	if len(tokenSplit) != 3 {
		return nil, fmt.Errorf("invalid token")
	}

	header, headerDecodeErr := decodeBase64(tokenSplit[0])
	if headerDecodeErr != nil {
		return nil, fmt.Errorf("could not decode token header")
	}

	payload, payloadDecodeErr := decodeBase64(tokenSplit[1])
	if payloadDecodeErr != nil {
		return nil, fmt.Errorf("could not decode token payload")
	}

	signature, signatureDecodeErr := decodeBase64(tokenSplit[2])
	if signatureDecodeErr != nil {
		return nil, fmt.Errorf("could not decode token signature")
	}

	token := &Token{
		plaintext: []byte(strings.Join(tokenSplit[:2], ".")),
		header:    header,
		signature: signature,
	}

	unmarshalErr := json.Unmarshal(payload, &token.payload)
	if unmarshalErr != nil {
		return nil, unmarshalErr
	}

	return token, nil
}

// decodeBase64 decode base64.
func decodeBase64(b64 string) ([]byte, error) {
	bts, decodeErr := base64.RawURLEncoding.DecodeString(b64)
	if decodeErr != nil {
		return nil, fmt.Errorf("error decoding")
	}

	return bts, nil
}
