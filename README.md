# gopbkdf2
Keycloak 암호화 모듈중 PBKDF2-SHA256 알고리즘구현을 위한 Wrapper 라이브러리


# example

* Hash a Password

```golang
package main

import(
	"fmt"
	"crypto/sha256"
	"github.com/parjom/gopbkdf2"
)

func main(){
	saltsize := 16
	keysize := 64
	iteration := 27500

	pass := gopbkdf2.NewPassword(sha256.New, saltsize, keysize, iteration)
	hashed := pass.HashPassword("p@ssw0rd")
	fmt.Println(hashed.CipherText) // base64 string
	fmt.Println(hashed.Salt)       // base64 string
}
```
* Verify a Password
```golang
package main

import(
	"fmt"
	"crypto/sha256"
	"github.com/parjom/gopbkdf2"
)

func main(){
	saltsize := 16
	keysize := 64
	iteration := 27500

	pass := gopbkdf2.NewPassword(sha256.New, saltsize, keysize, iteration)
	hashed := pass.HashPassword("p@ssw0rd")
	fmt.Println(hashed.CipherText) // base64 string
	fmt.Println(hashed.Salt)       // base64 string

	isValid := pass.VerifyPassword("p@ssw0rd", hashed.CipherText, hashed.Salt)

	fmt.Println(isValid)
}
```