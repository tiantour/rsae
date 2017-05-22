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
	result := rsae.NewRsae().Base64Encode([]byte(args))
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
	result, err := rsae.NewRsae().Base64Decode(args)
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
	result := rsae.NewRsae().Md532(args)
	fmt.Println(result)
}
```

MD516

```
package main

import (
	"fmt"

	"github.com/tiantour/rsae"
)

func main() {
	args := "input data"
	result := rsae.NewRsae().Md516(args)
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
	result := rsae.NewRsae().SHA1(args)
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
	result := rsae.NewRsae().SHA256(args)
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
	result := rsae.NewRsae().HmacSha1(publicKey, privateKey)
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
	result := rsae.NewRsae().Pbkdf2Sha256(data, salt, iterations)
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
	result, err := rsae.NewRsae().Encrypt(origdata, publicKey)
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
	result, err := rsae.NewRsae().Decrypt(origdata, privateKey)
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
	result, err := rsae.NewRsae().Sign(origdata, privateKey)
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
	result, err := rsae.NewRsae().Verify(origdata, ciphertext, publicKey)
	if err != nil {
		fmt.Println("Decrypt error")
	}
	fmt.Println(result)
}
```