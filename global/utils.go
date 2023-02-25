package global

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"github.com/bolt"
	"github.com/yonggewang/bdls"
	"golang.org/crypto/ripemd160"
	"log"
	"math/big"
)

var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

//通过私钥产生公钥
func NewKeyPair() (ecdsa.PrivateKey, []byte) {
	//curve := elliptic.P256()
	private, err := ecdsa.GenerateKey(bdls.S256Curve, rand.Reader)
	MyError(err)
	pubKey := append(private.PublicKey.X.Bytes(), private.Y.Bytes()...)
	return *private, pubKey
}
func VerifyKeyPair(pri ecdsa.PrivateKey, pub []byte) bool {
	pubBytes := append(pri.PublicKey.X.Bytes(), pri.PublicKey.Y.Bytes()...)
	return bytes.Compare(pubBytes, pub) == 0
}

//将秘钥转化为字符串
func StringPrivate(priKey ecdsa.PrivateKey) string {
	var content bytes.Buffer
	gob.Register(elliptic.P256())
	encoder := gob.NewEncoder(&content)
	err := encoder.Encode(priKey)
	MyError(err)
	return hex.EncodeToString(content.Bytes())
}

//将字符串转秘钥
func BackPrivate(private string) ecdsa.PrivateKey {
	var priKey ecdsa.PrivateKey
	keyBytes, err := hex.DecodeString(private)
	MyError(err)
	gob.Register(elliptic.P256())
	decoder := gob.NewDecoder(bytes.NewReader(keyBytes))
	err = decoder.Decode(&priKey)
	MyError(err)
	return priKey
}
func ReverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}
func GetBlockChain(portId string) *BlockChain {
	dbName := fmt.Sprintf(DBName, portId)
	var tipHashUser []byte
	var tipHashCertificate []byte
	log.Print("open database...")
	db, err := bolt.Open(dbName, 0600, nil)
	MyError(err)
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(TableName))
		if b != nil {
			tipHashUser = b.Get([]byte(RecentBlockName_User))
			tipHashCertificate = b.Get([]byte(RecentBlockName_Train))
		}
		return nil
	})
	MyError(err)
	return &BlockChain{db, tipHashUser, tipHashCertificate}
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
