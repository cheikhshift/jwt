# go-jwt

Generate and validate JWT ( open standard RFC 7519 )  tokens with Go. The project is also compatible with [gophersauce.com](http://gophersauce.com). This project only supports HMAC 256.

# Install

	go get github.com/cheikhshift/jwt

	...
	import "github.com/cheikhshift/jwt"

How to install on Go server

	<import src="github.com/cheikhshift/jwt/gos.gxml" />


#### Dependencies
The package depends on `gopkg.in/mgo.v2`

	go get gopkg.in/mgo.v2

### Package interfaces

#### JSON

	type JSON bson.M

Notes : This is the equivalent of `map[string]interface{}`


#### Token

	type Token struct {
		Header, Payload bson.M
	}

### Variables

#### Key

	var Key string
	
Secret key used to generate message signatures.

### Processing tokens

	func Process(jwtstring string) (token Token, err error)

The function `jwt.Process` will convert a JWT string into a [jwt.Token](#token).

Get token directly if your token is in an Authorization header :

	func JWTFromRequest(r *http.Request) (token Token, err error) 


### Handle Unauthorized request
Use the following function to set the unauthorized request code : 

	func CancelRequest(w http.ResponseWriter) 


### Create a new token

	func ToJWT(payload JSON) string

