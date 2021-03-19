package address

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/minio/blake2b-simd"
	"golang.org/x/xerrors"
)

//func init() {
//	cbor.RegisterCborType(addressAtlasEntry)
//}

//var addressAtlasEntry = atlas.BuildEntry(Address{}).Transform().
//	TransformMarshal(atlas.MakeMarshalTransformFunc(
//		func(a Address) (string, error) {
//			return string(a.Bytes()), nil
//		})).
//	TransformUnmarshal(atlas.MakeUnmarshalTransformFunc(
//		func(x string) (Address, error) {
//			return NewFromBytes([]byte(x))
//		})).
//	Complete()

// Address is the go type that represents an address in the filecoin network.
type Address struct{ str string }

// Undef is the type that represents an undefined address.
var Undef = Address{}

// MainnetPrefix is the main network prefix.
const MainnetPrefix = "cf"


// Protocol represents which protocol an address uses.
type Protocol = byte

// Payload returns the payload of the address.
func (a Address) Payload() []byte {
	if len(a.str) == 0 {
		return nil
	}
	return []byte(a.str)
}

// Bytes returns the address as bytes.
func (a Address) Bytes() []byte {
	return []byte(a.str)
}

// String returns an address encoded as a string.
func (a Address) String() string {
	str, err := encode(a)
	if err != nil {
		panic(err) // I don't know if this one is okay
	}
	return str
}

// Empty returns true if the address is empty, false otherwise.
func (a Address) Empty() bool {
	return a == Undef
}

//// Unmarshal unmarshals the cbor bytes into the address.
//func (a Address) Unmarshal(b []byte) error {
//	return cbor.DecodeInto(b, &a)
//}
//
//// Marshal marshals the address to cbor.
//func (a Address) Marshal() ([]byte, error) {
//	return cbor.DumpObject(a)
//}

// UnmarshalJSON implements the json unmarshal interface.
func (a *Address) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}

	addr, err := decode(s)
	if err != nil {
		return err
	}
	*a = addr
	return nil
}

// MarshalJSON implements the json marshal interface.
func (a Address) MarshalJSON() ([]byte, error) {
	return []byte(`"` + a.String() + `"`), nil
}

func (a *Address) Scan(value interface{}) error {
	switch value := value.(type) {
	case string:
		a1, err := decode(value)
		if err != nil {
			return err
		}

		*a = a1

		return nil
	default:
		return xerrors.New("non-string types unsupported")
	}
}

// NewSecp256k1Address returns an address using the SECP256K1 protocol.
func NewSecp256k1Address(pubkey []byte) (Address, error) {
	return newAddress(addressHash(pubkey))
}


// NewFromString returns the address represented by the string `addr`.
func NewFromString(addr string) (Address, error) {
	return decode(addr)
}

//// NewFromBytes return the address represented by the bytes `addr`.
//func NewFromBytes(addr []byte) (Address, error) {
//	if len(addr) == 0 {
//		return Undef, nil
//	}
//	if len(addr) == 1 {
//		return Undef, ErrInvalidLength
//	}
//	return newAddress(addr[0], addr[1:])
//}

// Checksum returns the checksum of `ingest`.
func Checksum(ingest []byte) []byte {
	return hash(ingest, checksumHashConfig)
}

// ValidateChecksum returns true if the checksum of `ingest` is equal to `expected`>
func ValidateChecksum(ingest, expect []byte) bool {
	digest := Checksum(ingest)
	return bytes.Equal(digest, expect)
}

func addressHash(ingest []byte) []byte {
	return hash(ingest, payloadHashConfig)
}

func newAddress( payload []byte) (Address, error) {
	if len(payload) != PayloadHashLength {
		return Undef, ErrInvalidPayload
	}
	explen := len(payload)
	buf := make([]byte, explen)

	copy(buf, payload)

	return Address{string(buf)}, nil
}

func encode(addr Address) (string, error) {
	if addr == Undef {
		return UndefAddressString, nil
	}
	var ntwk = MainnetPrefix


	var strAddr string
	cksm := Checksum(addr.Payload())
	strAddr = ntwk + AddressEncoding.WithPadding(-1).EncodeToString(append(addr.Payload(), cksm[:]...))

	return strAddr, nil
}

func decode(a string) (Address, error) {
	if len(a) == 0 {
		return Undef, nil
	}
	if a == UndefAddressString {
		return Undef, nil
	}
	if len(a) > MaxAddressStringLength || len(a) < 3 {
		return Undef, ErrInvalidLength
	}

	if string(a[:2]) != MainnetPrefix {
		return Undef, ErrUnknownNetwork
	}

	raw := a[2:]
	payloadcksm, err := AddressEncoding.WithPadding(-1).DecodeString(raw)
	if err != nil {
		return Undef, err
	}

	if len(payloadcksm)-ChecksumHashLength < 0 {
		return Undef, ErrInvalidChecksum
	}

	payload := payloadcksm[:len(payloadcksm)-ChecksumHashLength]
	cksm := payloadcksm[len(payloadcksm)-ChecksumHashLength:]

	if len(payload) != 20 {
		return Undef, ErrInvalidPayload
	}

	if !ValidateChecksum(payload, cksm) {
		return Undef, ErrInvalidChecksum
	}

	return newAddress(payload)
}

func hash(ingest []byte, cfg *blake2b.Config) []byte {
	hasher, err := blake2b.New(cfg)
	if err != nil {
		// If this happens sth is very wrong.
		panic(fmt.Sprintf("invalid address hash configuration: %v", err)) // ok
	}
	if _, err := hasher.Write(ingest); err != nil {
		// blake2bs Write implementation never returns an error in its current
		// setup. So if this happens sth went very wrong.
		panic(fmt.Sprintf("blake2b is unable to process hashes: %v", err)) // ok
	}
	return hasher.Sum(nil)
}

func (a Address) MarshalBinary() ([]byte, error) {
	return a.Bytes(), nil
}

//func (a *Address) UnmarshalBinary(b []byte) error {
//	newAddr, err := NewFromBytes(b)
//	if err != nil {
//		return err
//	}
//	*a = newAddr
//	return nil
//}
//
//func (a *Address) MarshalCBOR(w io.Writer) error {
//	if a == nil {
//		_, err := w.Write(cbg.CborNull)
//		return err
//	}
//
//	if *a == Undef {
//		return fmt.Errorf("cannot marshal undefined address")
//	}
//
//	if err := cbg.WriteMajorTypeHeader(w, cbg.MajByteString, uint64(len(a.str))); err != nil {
//		return err
//	}
//
//	if _, err := io.WriteString(w, a.str); err != nil {
//		return err
//	}
//
//	return nil
//}
//
//func (a *Address) UnmarshalCBOR(r io.Reader) error {
//	br := cbg.GetPeeker(r)
//
//	maj, extra, err := cbg.CborReadHeader(br)
//	if err != nil {
//		return err
//	}
//
//	if maj != cbg.MajByteString {
//		return fmt.Errorf("cbor type for address unmarshal was not byte string")
//	}
//
//	if extra > 64 {
//		return fmt.Errorf("too many bytes to unmarshal for an address")
//	}
//
//	buf := make([]byte, int(extra))
//	if _, err := io.ReadFull(br, buf); err != nil {
//		return err
//	}
//
//	addr, err := NewFromBytes(buf)
//	if err != nil {
//		return err
//	}
//	if addr == Undef {
//		return fmt.Errorf("cbor input should not contain empty addresses")
//	}
//
//	*a = addr
//
//	return nil
//}
//
