package global

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"golang.org/crypto/ripemd160"
	"log"
	"math/big"
)

var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

func ReverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}
func Base58Encode(input []byte) []byte {
	var result []byte
	x := big.NewInt(0).SetBytes(input)
	base := big.NewInt(int64(len(b58Alphabet)))
	zero := big.NewInt(0)
	mod := &big.Int{}

	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)
		result = append(result, b58Alphabet[mod.Int64()])
	}
	ReverseBytes(result)
	for b := range input {
		if b == 0x00 {
			result = append([]byte{b58Alphabet[0]}, result...)
		} else {
			break
		}
	}
	return result
}

func IntToHex(num uint64) []byte {
	buff := new(bytes.Buffer)
	err := binary.Write(buff, binary.BigEndian, num)
	if err != nil {
		log.Panic(err)
	}
	return buff.Bytes()
}
func MyError(err error) {
	if err != nil {
		log.Panic(err)
	}
}
func HashPubKey(pubKey []byte) []byte {
	//256
	publicSHA256 := sha256.Sum256(pubKey)
	//160
	RIPEMD160Hasher := ripemd160.New()
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	MyError(err)
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)
	return publicRIPEMD160
}
func CheckSum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])
	return secondSHA[:AddressChecksumLen]
}
func GetAddress(pubKey []byte) []byte {
	//1、先将publicKey hash160
	pubKeyHash := HashPubKey(pubKey)
	//添加version
	versionedPayload := append([]byte{Version}, pubKeyHash...)

	checkSumBytes := CheckSum(versionedPayload)
	//checkSumBytes:=CheckSum(pubKeyHash)

	fullPayload := append(versionedPayload, checkSumBytes...)
	address := Base58Encode(fullPayload)
	return address
}
