package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"strings"
	"time"
)

type token struct {
	Header map[string]string      // Header is the first segment of the token in decoded form
	Claims map[string]interface{} // Claims is the second segment of the token in decoded form
}

// Feel free to change this to suit your needs
var hashFn = sha256.New

const alg = "HS256"

var headers = map[string]string{
	"typ": "JWT",
	"alg": alg,
}

func encodeSegment(seg []byte) string {
	return base64.RawURLEncoding.EncodeToString(seg)
}

func (t *token) SignedString(secret []byte) (string, error) {
	sstr, err := t.signingString()
	if err != nil {
		return "", err
	}

	hm := hmac.New(hashFn, secret)
	_, err = hm.Write([]byte(sstr))
	if err != nil {
		return "", err
	}

	sum := hm.Sum(nil)

	seg := encodeSegment(sum)
	return sstr + "." + seg, nil
}

func (t *token) Expired() bool {

	now := time.Now().Unix()

	// For some reason, this has to be a float64
	// comparison even though we only work with
	// int64s.
	expiration, ok := t.Claims["exp"]

	if !ok {
		return true
	}

	if exp, ok := expiration.(float64); ok {
		return exp < float64(now)
	}

	return true

}

func (t *token) Subject() string {

	subject, ok := t.Claims["sub"]

	if !ok {
		return ""
	}

	if sub, ok := subject.(string); ok {
		return sub
	}

	return ""

}

func (t *token) signingString() (string, error) {

	h, err := json.Marshal(t.Header)
	if err != nil {
		return "", err
	}

	c, err := json.Marshal(t.Claims)
	if err != nil {
		return "", err
	}

	return encodeSegment(h) + "." + encodeSegment(c), nil
}

// VerifyJWT verifies a given JWT and checks if it is expired.
func Verify(jwt string, secret []byte) (bool, map[string]interface{}, error) {

	parts := strings.Split(jwt, ".")

	if len(parts) != 3 {
		return false, nil, errors.New("JWT does not have 3 parts")
	}

	tok := &token{}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return false, nil, err
	}
	if err = json.Unmarshal(headerBytes, &tok.Header); err != nil {
		return false, nil, err
	}

	claimBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return false, nil, err
	}

	if err = json.Unmarshal(claimBytes, &tok.Claims); err != nil {
		return false, nil, err
	}

	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])

	if err != nil {
		return false, nil, err
	}

	h := hmac.New(hashFn, secret)
	sstr, _ := tok.signingString()
	h.Write([]byte(sstr))
	sum := h.Sum(nil)
	return hmac.Equal(signatureBytes, sum) && !tok.Expired(), tok.Claims, nil

}

func New(claims map[string]any, subject string, timeout int, secret []byte) (string, error) {

	newMap := maps.Clone(claims)

	now := time.Now().Unix()
	newMap["iss"] = now
	newMap["exp"] = now + int64(timeout)
	newMap["sub"] = subject

	t := token{
		Header: headers,
		Claims: newMap,
	}

	return t.SignedString(secret)

}
