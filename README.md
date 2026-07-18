# go-jwt
Golang implementation of JWTs using HMAC for signing

```golang
package main

import (
	"fmt"

	"github.com/chuckyQ/go-jwt"
)

func main() {

	secret := []byte("secret")

	claims := map[string]any{
		"abcdef": "acme",
	}

	token, err := jwt.New(claims, "subject", 10, secret)

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	valid, claims, err := jwt.Verify(token, secret)

	if !valid {
		fmt.Println("invalid token")
		return
	}

	if err != nil {
		fmt.Println(err.Error())
		return
	}

	fmt.Println(claims)

}
```
