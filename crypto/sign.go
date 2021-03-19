package crypto

import (
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/cume-go/c-fabric-wallet/address"
	"github.com/minio/blake2b-simd"
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

// 从签名信息中获取钱包地址
func GetAddressFromSignature(sig []byte, msg []byte) (string, error) {
	b2sum := blake2b.Sum256(msg)
	pubk, err := EcRecover(b2sum[:], sig)
	if err != nil {
		return "", err
	}

	addr, err := address.NewSecp256k1Address(pubk)
	if err != nil {
		return "", err
	}
	return addr.String(), nil
}
