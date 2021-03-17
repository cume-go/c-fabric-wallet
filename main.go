package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/cume-go/c-fabric-wallet/address"
	"github.com/cume-go/c-fabric-wallet/crypto"
)

func main()  {
	pv ,err := crypto.GenerateKey()
	if err != nil {
		fmt.Println(err)
		return
	}
	key, err := crypto.NewKey(pv)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(key.GetPrivkey())
	fmt.Println(key.Address.String())

	addr, err := address.NewFromString("cfslkdltsw6ffri3sw47liic76qlx2kmyubqutq6a")
	fmt.Println(err)
	fmt.Println(addr)

	// addr:cf6g2fqbcvgimltd4yghnbvqijm7buzezqamxlfnq
	key2, err := crypto.NewKeyFromString("2a3ca355ce5654b7bb8fa062becd530d8c188c424d9f2df209b6aec39ad0df44")

	s, err := key2.Sign([]byte("aaaaa"))
	fmt.Println(err)
	fmt.Println(hex.EncodeToString(s))
	b, err := json.Marshal(addr)
	fmt.Println(string(b))

}
