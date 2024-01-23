### Go-Crypt
Helper functions for crypto


Sample Usage

```go

package main

import (
	"fmt"
	"github.com/skhatri/go-crypt/asymmetric"
	"log"
)

var pKey = "AGE-SECRET-KEY-1CFKFQSR8D82Z2PEFX2K2TRAT266T538WTSMZ3Z25332HNADY8JTQPF24Y8"
var pubKey = "age1gn26zalgf5xn5dn04lxemu4x4uapvkgh3jf4ajqwxklxdtdtdd3sy83wcx"

func main() {
	encrypted, err := asymmetric.AgeEncrypt(pubKey, "A quick brown jumped over")
	if err != nil {
		log.Fatalf("encrypt error %v", err)
	}
	fmt.Printf("encrypted: %s\n", encrypted)

	plain, dErr := asymmetric.AgeDecrypt(pKey, encrypted)
	if dErr != nil {
		log.Fatalf("decrypt error %v", dErr)
	}
	fmt.Printf("plain: %s\n", plain)
}
```