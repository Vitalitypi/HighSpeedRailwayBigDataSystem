package common

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/yonggewang/bdls/global"
	"math/big"
	"rlp"
)

//用户信息
type InfoUser struct {
	Hash         []byte
	PublicKey    []byte //对信息签名的管理员公钥
	Signature    []byte //r,s签名
	Account      []byte //账户
	UInfo        []byte
	PreviousUser []byte //注册该账户的用户所注册的上一个用户
}

func (infoUser *InfoUser) VerifyInfoUserHash() bool {
	copyInfoUser := &InfoUser{nil, infoUser.PublicKey, infoUser.Signature, infoUser.Account, infoUser.UInfo, infoUser.PreviousUser}
	copyInfoUser.SetInfoUserHash()
	return bytes.Compare(infoUser.Hash, copyInfoUser.Hash) == 0
}
func (infoUser *InfoUser) SerializeInfoUser() []byte {
	bytes, err := rlp.EncodeToBytes(infoUser)
	global.MyError(err)
	return bytes
}
func DeserializeInfoUser(bytes []byte) *InfoUser {
	infoUser := &InfoUser{}
	err := rlp.DecodeBytes(bytes, infoUser)
	global.MyError(err)
	return infoUser
}
func (infoUser *InfoUser) SetInfoUserHash() {
	hash := sha256.Sum256(infoUser.SerializeInfoUser())
	infoUser.Hash = hash[:]
}
func GetStringInfoUser(infoUserBytes []byte) string {
	result := "|||用户信息：\n|||"
	infoUser := DeserializeInfoUser(infoUserBytes)
	result += "Hash:" +
		hex.EncodeToString(infoUser.Hash) + "\n|||公钥:|||" +
		hex.EncodeToString(infoUser.PublicKey) + "\n|||签名:|||" +
		hex.EncodeToString(infoUser.Signature) + "\n|||账户:|||" +
		hex.EncodeToString(infoUser.Account) + "\n|||信息:|||" +
		hex.EncodeToString(infoUser.UInfo) + "\n\n"
	return result
}
func (infoUser *InfoUser) PrintInfoUser() {
	fmt.Printf("Hash:%x\n", infoUser.Hash)
	fmt.Printf("PublicKey:%x\n", infoUser.PublicKey)
	fmt.Printf("Signature:%x\n", infoUser.Signature)
	fmt.Printf("Account:%x\n", infoUser.Account)
	fmt.Printf("账户身份:%s\n", string(infoUser.UInfo))
}
func (infoUser *InfoUser) isCoinBaseInfoUser() bool {
	return len(infoUser.Hash) == 0
}
func (infoUser *InfoUser) TrimmedCopy() InfoUser {
	userCopy := InfoUser{nil, nil, nil, infoUser.Account, infoUser.UInfo, infoUser.PreviousUser}
	return userCopy
}

//获取hash值为空时的hash值
func (infoUser *InfoUser) HashInfoUser() []byte {
	var hash [32]byte
	Copy := *infoUser
	Copy.Hash = []byte{}
	hash = sha256.Sum256(Copy.SerializeInfoUser())
	return hash[:]
}

//Sign只对Account、UInfo等信息进行签名
func (infoUser *InfoUser) Sign(privateKey ecdsa.PrivateKey) {
	userCopy := infoUser.TrimmedCopy()
	//cerCopy.TrainInformation.Signature = nil
	userCopy.Hash = userCopy.HashInfoUser()
	//cerCopy.TrainInformation.PublicKey=append(privateKey.PublicKey.X.Bytes(),privateKey.Y.Bytes()...)
	//签名代码
	r, s, err := ecdsa.Sign(rand.Reader, &privateKey, userCopy.Hash)
	global.MyError(err)
	signature := global.GetFillBytes(r, s)
	infoUser.Signature = signature
	infoUser.Hash = infoUser.HashInfoUser()
}
func (infoUser *InfoUser) Verify() bool {
	userCopy := infoUser.TrimmedCopy()      //将其他信息剪除
	userCopy.Hash = userCopy.HashInfoUser() //获取信息的简要信息
	r := big.Int{}
	s := big.Int{}
	sign := infoUser.Signature
	signLen := len(sign)
	r.SetBytes(sign[:(signLen / 2)])
	s.SetBytes(sign[(signLen / 2):])
	x := big.Int{}
	y := big.Int{}
	pubKey := infoUser.PublicKey
	pubKeyLen := len(pubKey)
	x.SetBytes(pubKey[:(pubKeyLen / 2)])
	y.SetBytes(pubKey[(pubKeyLen / 2):])
	public := ecdsa.PublicKey{global.S256Curve, &x, &y}
	if !ecdsa.Verify(&public, userCopy.Hash, &r, &s) {
		return false
	}
	return true
}
