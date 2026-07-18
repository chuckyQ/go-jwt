package jwt_test

import (
	"fmt"
	"testing"

	"github.com/chuckyQ/go-jwt"
)

func TestBasicClaims(t *testing.T) {

	secret := []byte("secret")

	subject := "abcdef"

	token, err := jwt.New(map[string]any{
		"abcd": "def",
	}, subject, 10, secret)

	if err != nil {
		t.Fatalf("failed to create jwt with error %v", err.Error())
	}

	valid, claims, err := jwt.Verify(token, secret)

	if !valid {
		t.Fatalf("jwt is not valid")
	}

	sub := claims["sub"]
	s, ok := sub.(string)
	if !ok {
		fmt.Println(claims)
		t.Fatalf("invalid subject")
	}

	if s != subject {
		t.Fatalf("invalid subject: expected %v, got %v", subject, s)
	}

}

func TestExpired(t *testing.T) {

	secret := []byte("secret")

	subject := "abcdef"
	badTimeout := -10
	token, err := jwt.New(map[string]any{
		"abcd": "def",
	}, subject, badTimeout, secret)

	if err != nil {
		t.Fatalf("failed to create jwt with error %v", err.Error())
	}

	valid, _, err := jwt.Verify(token, secret)

	if valid {
		t.Fatalf("jwt should not be valid")
	}

}

func TestWrongSecret(t *testing.T) {

	secret := []byte("secret")

	subject := "abcdef"

	token, err := jwt.New(map[string]any{
		"abcd": "def",
	}, subject, 10, secret)

	if err != nil {
		t.Fatalf("failed to create jwt with error %v", err.Error())
	}

	newSecret := []byte("newSecret")
	valid, _, _ := jwt.Verify(token, newSecret)

	if valid {
		t.Fatalf("jwt should not be valid")
	}

}
