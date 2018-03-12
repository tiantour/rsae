# rsae
rsa encrypt,decrypt,sign,verify wiht go

Base64Encode

```
package main

import (
	"fmt"

	"github.com/tiantour/rsae"
)

func main() {
	args := "input data"
	result := rsae.NewBase64().Encode([]byte(args))
	fmt.Println(result)
}
```

Base64Decode

```
package main

import (
	"fmt"

	"github.com/tiantour/rsae"
)

func main() {
	args := "input data"
	result, err := rsae.NewBase64().Decode(args)
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Println(string(result))
}
```

MD532

```
package main

import (
	"fmt"

	"github.com/tiantour/rsae"
)

func main() {
	args := "input data"
	result := rsae.NewMD5().Encode(args)
	fmt.Println(result)
}
```

SHA1

```
package main

import (
	"fmt"

	"github.com/tiantour/rsae"
)

func main() {
	args := "input data"
	result := rsae.NewSHA().SHA1(args)
	fmt.Println(result)
}
```

SHA256

```
package main

import (
	"fmt"

	"github.com/tiantour/rsae"
)

func main() {
	args := "input data"
	result := rsae.NewSHA().SHA256(args)
	fmt.Println(result)
}
```

HmacSha1


```
package main

import (
	"fmt"

	"github.com/tiantour/rsae"
)

func main() {
	publicKey := "public key"
	privateKey := "private key"
	result := rsae.NewSHA().HmacSha1(publicKey, privateKey)
	fmt.Println(result)
}
```

Pbkdf2Sha256


```
package main

import (
	"fmt"

	"github.com/tiantour/rsae"
)

func main() {
	data := "input date"
	salt := "input salt"
	iterations := 12000
	result := rsae.NewSHA().Pbkdf2Sha256(data, salt, iterations)
	fmt.Println(result)
}
```
Encrypt

```
package main

import (
	"fmt"

	"github.com/tiantour/imago"
	"github.com/tiantour/rsae"
)

func main() {
	origdata := "data"
	publicPath := "public key path"
	publicKey, err := imago.NewFile().Read(publicPath)
	if err != nil {
		fmt.Println("key error")
	}
	result, err := rsae.NewRSA().Encrypt(origdata, publicKey)
	if err != nil {
		fmt.Println("encrypt error")
	}
	fmt.Println(result)
}
```

Decrypt
```
package main

import (
	"fmt"

	"github.com/tiantour/imago"
	"github.com/tiantour/rsae"
)

func main() {
	origdata := "data"
	privatePath := "public key path"
	privateKey, err := imago.NewFile().Read(privatePath)
	if err != nil {
		fmt.Println("key error")
	}
	result, err := rsae.NewRSA().Decrypt(origdata, privateKey)
	if err != nil {
		fmt.Println("Decrypt error")
	}
	fmt.Println(result)
}
```
Sign

```
package main

import (
	"fmt"

	"github.com/tiantour/imago"
	"github.com/tiantour/rsae"
)

func main() {
	origdata := "data"
	privatePath := "public key path"
	privateKey, err := imago.NewFile().Read(privatePath)
	if err != nil {
		fmt.Println("key error")
	}
	result, err := rsae.NewRSA().Sign(origdata, privateKey)
	if err != nil {
		fmt.Println("Decrypt error")
	}
	fmt.Println(result)
}
```
Verify

```
package main

import (
	"fmt"

	"github.com/tiantour/imago"
	"github.com/tiantour/rsae"
)

func main() {
	origdata := "data"
	ciphertext := "result"
	publicPath := "public key path"
	publicKey, err := imago.NewFile().Read(publicPath)
	if err != nil {
		fmt.Println("key error")
	}
	result, err := rsae.NewRSA().Verify(origdata, ciphertext, publicKey)
	if err != nil {
		fmt.Println("Decrypt error")
	}
	fmt.Println(result)
}
```