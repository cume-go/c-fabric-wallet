package crypto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/cume-go/c-fabric-wallet/address"
	"github.com/minio/blake2b-simd"
	"reflect"
	"sort"
	"strings"
)

type Key struct {
	PrivateKey []byte

	PublicKey []byte
	Address   address.Address
}

func NewKey(pk []byte) (*Key, error) {
	//pk, err := hex.DecodeString(privateKey)
	//if err != nil {
	//	return nil, err
	//}
	k := &Key{
		//KeyInfo: keyinfo,
		PrivateKey: pk,
	}

	var err error
	k.PublicKey = PublicKey(k.PrivateKey)

	k.Address, err = address.NewSecp256k1Address(k.PublicKey)
	if err != nil {
		return nil, errors.New("converting Secp256k1 to address:" + err.Error())
	}

	return k, nil

}

func NewKeyFromString(privateKey string) (*Key, error) {
	pk, err := hex.DecodeString(privateKey)
	if err != nil {
		return nil, err
	}
	k := &Key{
		//KeyInfo: keyinfo,
		PrivateKey: pk,
	}

	//var err error
	k.PublicKey = PublicKey(k.PrivateKey)

	k.Address, err = address.NewSecp256k1Address(k.PublicKey)
	if err != nil {
		return nil, errors.New("converting Secp256k1 to address:" + err.Error())
	}

	return k, nil

}

func (k *Key) Sign(msg []byte) ([]byte, error) {
	b2sum := blake2b.Sum256(msg)
	sig, err := sign(k.PrivateKey, b2sum[:])
	if err != nil {
		return nil, err
	}

	return sig, nil
}

func (k *Key) GetPrivkey() (string) {
	return hex.EncodeToString(k.PrivateKey)
}

func VerifyFromAddress(sig []byte, addr string, msg []byte) error {
	b2sum := blake2b.Sum256(msg)
	pubk, err := EcRecover(b2sum[:], sig)
	if err != nil {
		return err
	}

	maybeaddr, err := address.NewSecp256k1Address(pubk)
	if err != nil {
		return err
	}


	if addr != maybeaddr.String() {
		return fmt.Errorf("signature did not match")
	}

	return nil
}

func GenPrivateFromMnemonic(mnemonic string) ([]byte, error) {
	reader := strings.NewReader(mnemonic)

	priv, err := GenerateKeyFromSeed(reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}
// 格式化要签名的参数
func FormatSignParam(i interface{})string{
	reflectValue := reflect.ValueOf(i)
	reflectType := reflect.TypeOf(i)
	var pList = make([]string, 0, 0)
	if reflectType.Kind() == reflect.Map {
		m := reflectValue.MapRange()
		for m.Next() {
			if reflect.TypeOf(m.Value().Interface()).Kind() == reflect.Slice {
				n:= reflect.ValueOf(m.Value().Interface())
				if n.Kind() == reflect.Slice {
					s := ""
					for k := 0; k < n.Len(); k++ {
						if len(s) > 0 {
							s = s+"&"
						}
						s = s+FormatSignParam(n.Index(k).Interface())
					}
					pList = append(pList, fmt.Sprint(m.Key())+"=["+s+"]")
				}
			} else {
				pList = append(pList, fmt.Sprint(m.Key())+"="+fmt.Sprint(m.Value()))
			}
		}
	} else if reflectType.Kind() == reflect.Struct {
		num := reflectType.NumField()
		for key:= 0; key<num; key++{
			if reflectValue.Field(key).Kind() == reflect.Slice {
				//fmt.Println(reflect.TypeOf(reflectValue.Field(key).Index(0).Interface()).Field(0))
				s := ""
				for k := 0; k < reflectValue.Field(key).Len(); k++ {
					if len(s) > 0 {
						s = s+"&"
					}
					s = s+FormatSignParam(reflectValue.Field(key).Index(k).Interface())
				}
				pList = append(pList, reflectType.Field(key).Name+"=["+s+"]")

			} else {
				pList = append(pList, reflectType.Field(key).Name+"="+fmt.Sprint(reflectValue.Field(key)))
			}
		}
	}


	sort.Strings(pList)
	return strings.Join(pList,"&")
}