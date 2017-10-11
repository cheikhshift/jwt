//go-jwt Cheikh Seck <cseck@orkiv.com>
package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"gopkg.in/mgo.v2/bson"
	"net/http"
	"strings"
)

var Key = "RandomCode"

type JSON bson.M

const Sha512Header = `{"typ":"JWT","alg":"HS256"}`

type Token struct {
	Header, Payload bson.M
}

func ToJWT(payload JSON) string {
	message := fmt.Sprintf("%s.%s", Base64(Sha512Header), Base64(tojson(payload)))
	return fmt.Sprintf("%s.%s", message, GenerateMAC([]byte(message)))
}

func Process(jwtstring string) (token Token, err error) {

	bits := strings.Split(jwtstring, ".")

	if len(bits) < 3 {
		err = errors.New("Invalid JWT token!")
		return
	}
	//...
	uDec, _ := base64.URLEncoding.DecodeString(bits[2])

	if !CheckMAC([]byte(fmt.Sprintf("%s.%s", bits[0], bits[1])), uDec) {
		err = errors.New("Invalid signature!")
		return
	}

	headerbase64, _ := base64.URLEncoding.DecodeString(bits[0])
	payloadbase64, _ := base64.URLEncoding.DecodeString(bits[1])

	err = json.Unmarshal(headerbase64, &token.Header)
	if err != nil {
		err = errors.New("Invalid header!")
		return
	}

	err = json.Unmarshal(payloadbase64, &token.Payload)
	if err != nil {
		err = errors.New("Invalid Payload!")
		return
	}

	return
}

func JWTFromRequest(r *http.Request) (token Token, err error) {
	/*if !strings.Contains(r.Header.Get("Authorization"), "Bearer") {
		err = errors.New("Invalid token type.")
		return
	}*/
	bits := strings.Split(r.Header.Get("Authorization"), " ")

	token, err = Process(bits[len(bits)-1])

	return
}

func CancelRequest(w http.ResponseWriter) {
	w.WriteHeader(http.StatusUnauthorized)
}

// https://golang.org/pkg/crypto/hmac/
func CheckMAC(message, messageMAC []byte) bool {
	mac := hmac.New(sha256.New, []byte(Key))
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return hmac.Equal(messageMAC, expectedMAC)
}

func Base64(str string) string {
	return base64.URLEncoding.EncodeToString([]byte(str))
}

func GenerateMAC(message []byte) string {
	mac := hmac.New(sha256.New, []byte(Key))
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	return base64.URLEncoding.EncodeToString(expectedMAC)
}
func tojson(v interface{}) string {
	data, _ := json.Marshal(&v)
	return string(data)
}
