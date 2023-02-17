package common

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/yonggewang/bdls/global"
	"math/big"
	"rlp"
	"time"
)

//用户信息
type InfoUser struct {
	Hash      []byte
	PublicKey []byte
	Signature []byte
	Account   []byte
	UInfo     []byte
}

func (userInfo *InfoUser) VerifyInfoUserHash() bool {
	copyUserInfo := &InfoUser{nil, userInfo.PublicKey, userInfo.Signature, userInfo.Account, userInfo.UInfo}
	copyUserInfo.SetUserInfoHash()
	return bytes.Compare(userInfo.Hash, copyUserInfo.Hash) == 0
}
func (userInfo *InfoUser) SerializeUserInfo() []byte {
	bytes, err := rlp.EncodeToBytes(userInfo)
	global.MyError(err)
	return bytes
}
func DeserializeUserInfo(bytes []byte) *InfoUser {
	userInfo := &InfoUser{}
	err := rlp.DecodeBytes(bytes, userInfo)
	global.MyError(err)
	return userInfo
}
func (userInfo *InfoUser) SetUserInfoHash() {
	hash := sha256.Sum256(userInfo.SerializeUserInfo())
	userInfo.Hash = hash[:]
}
func GetStringUserInfo(userInfoBytes []byte) string {
	result := "|||用户信息：\n|||"
	userInfo := DeserializeUserInfo(userInfoBytes)
	result += "Hash:" +
		hex.EncodeToString(userInfo.Hash) + "\n|||公钥:|||" +
		hex.EncodeToString(userInfo.PublicKey) + "\n|||签名:|||" +
		hex.EncodeToString(userInfo.Signature) + "\n|||账户:|||" +
		hex.EncodeToString(userInfo.Account) + "\n|||信息:|||" +
		hex.EncodeToString(userInfo.UInfo) + "\n\n"
	return result
}
func (userInfo *InfoUser) PrintUserInfo() {
	fmt.Printf("Hash:%x\n", userInfo.Hash)
	fmt.Printf("PublicKey:%x\n", userInfo.PublicKey)
	fmt.Printf("Signature:%x\n", userInfo.Signature)
	fmt.Printf("Account:%x\n", userInfo.Account)
	fmt.Printf("UInfo:%x\n", userInfo.UInfo)
}
func (userInfo *InfoUser) isCoinBaseUserInfo() bool {
	return len(userInfo.Hash) == 0
}
func (userInfo *InfoUser) TrimmedCopy() InfoUser {
	userCopy := InfoUser{userInfo.Hash, nil, nil, userInfo.Account, userInfo.UInfo}
	return userCopy
}
func (userInfo *InfoUser) HashUserInfo() []byte {
	var hash [32]byte
	Copy := *userInfo
	Copy.Hash = []byte{}
	hash = sha256.Sum256(Copy.SerializeUserInfo())
	return hash[:]
}
func (userInfo *InfoUser) Sign(privateKey ecdsa.PrivateKey) {
	if userInfo.isCoinBaseUserInfo() {
		return
	}
	userCopy := userInfo.TrimmedCopy()
	//cerCopy.TrainInformation.Signature = nil
	userCopy.Hash = userCopy.HashUserInfo()
	//cerCopy.TrainInformation.PublicKey=append(privateKey.PublicKey.X.Bytes(),privateKey.Y.Bytes()...)
	//签名代码
	r, s, err := ecdsa.Sign(rand.Reader, &privateKey, userCopy.Hash)
	global.MyError(err)
	signature := append(r.Bytes(), s.Bytes()...)
	userInfo.Signature = signature
}
func Register(pubKey []byte, infos []byte) *InfoUser {
	//fmt.Println("infos")
	//创建用户信息
	info, _ := hex.DecodeString(time.Now().String())
	userInfo := &InfoUser{nil, global.PublicKey, nil, pubKey, info}
	userInfo.SetUserInfoHash()
	userInfo.Sign(global.PrivateKey) //进行签名
	userInfo.Hash = userInfo.HashUserInfo()

	//nodeUser:= NewNodeUser(pubKey,userInfo.Hash,nil)
	//address:=hex.EncodeToString(Global.GetAddress(pubKey))
	//Map_UserInfo[address]=userInfo
	//Map_NodeUser[address]=nodeUser
	return userInfo
}
func (userInfo *InfoUser) Verify() bool {
	if userInfo.isCoinBaseUserInfo() {
		return true
	}
	userCopy := userInfo.TrimmedCopy()
	curve := elliptic.P256()
	userCopy.Hash = userCopy.HashUserInfo()
	r := big.Int{}
	s := big.Int{}
	sign := userInfo.Signature
	signLen := len(sign)
	r.SetBytes(sign[:(signLen / 2)])
	s.SetBytes(sign[(signLen / 2):])
	x := big.Int{}
	y := big.Int{}
	pubKey := userInfo.PublicKey
	pubKeyLen := len(pubKey)
	x.SetBytes(pubKey[:(pubKeyLen / 2)])
	y.SetBytes(pubKey[(pubKeyLen / 2):])
	rawPubKey := ecdsa.PublicKey{curve, &x, &y}
	if !ecdsa.Verify(&rawPubKey, userCopy.Hash, &r, &s) {
		return false
	}
	return true
}
