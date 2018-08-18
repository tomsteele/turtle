package schemes

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
)

// JWTScheme is an authentication scheme using JWT tokens.
type JWTScheme struct {
	Secret       []byte
	ValidateFunc func(claims jwt.MapClaims) (interface{}, error)
}

// Authenticate extracts and parses the JWT token from a requests authorization header.
func (s *JWTScheme) Authenticate(w http.ResponseWriter, r *http.Request) (interface{}, error) {
	header := r.Header.Get("Authorization")
	if header == "" {
		return nil, errors.New("missing Authorization header")
	}
	parts := strings.Split(header, " ")
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, errors.New("malformed Authorization header")
	}
	token, err := jwt.Parse(parts[1], func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %s", token.Header["alg"])
		}
		return s.Secret, nil
	})

	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("malformed claims")
	}
	return s.ValidateFunc(claims)
}
