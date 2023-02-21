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
)

type InfoTrain struct {
	Hash      []byte   //列车编号
	PublicKey []byte   //公钥
	Signature []byte   //数字签名
	CtName    string   //列车名称
	UserName  []string //列车人员姓名
	//RipeMd160Hash []byte
	Time  string //时间
	Other string //其他信息
}

func Save(workNames string, userNames []string, times string, others string) *InfoTrain {
	InfoTrain := &InfoTrain{nil, global.PublicKey, nil, workNames, userNames, times, others}
	InfoTrain.Sign(global.PrivateKey)
	InfoTrain.SetInfoTrainHash()
	//Map_InfoTrain[hex.EncodeToString(InfoTrain.Hash)]=InfoTrain
	//InfoTrainPool = append(InfoTrainPool, InfoTrain)
	return InfoTrain
}
func GetStringInfoTrain(infoBytes []byte) string {
	info := &InfoTrain{}
	userNames := ""
	if len(infoBytes) == 0 {
		return ""
	}
	err := rlp.DecodeBytes(infoBytes, info)
	global.MyError(err)
	for _, name := range info.UserName {
		userNames += name
	}
	result := "\n列车信息：|||公钥：" + hex.EncodeToString(info.PublicKey) + "\n|||签名：" + hex.EncodeToString(info.Signature) + "" +
		"\n|||Hash:" + hex.EncodeToString(info.Hash) +
		"\n|||作品名称：" + info.CtName +
		"\n|||作者：" + userNames +
		"\n|||时间：" + info.Time +
		"\n|||其他：" + info.Other
	return result
}
func (info *InfoTrain) PrintInfoTrain() {
	fmt.Printf("当前列车信息hash：%x\n", info.Hash)
	fmt.Printf("当前列车信息公钥：%x\n", info.PublicKey)
	fmt.Printf("当前列车信息数字签名：%x\n", info.Signature)
	fmt.Println("列车名称：", info.CtName)
	fmt.Println("获奖人员姓名：", info.UserName)
	fmt.Println("时间：", info.Time)
	fmt.Println("其他信息：", info.Other)
}
func (info *InfoTrain) SerializeInfoTrain() []byte {
	bytes, err := rlp.EncodeToBytes(info)
	global.MyError(err)
	return bytes
}
func DeserializeInfoTrain(bytes []byte) *InfoTrain {
	info := &InfoTrain{}
	err := rlp.DecodeBytes(bytes, info)
	global.MyError(err)
	return info
}
func (info *InfoTrain) VerifyInfoTrainHash() bool {
	copyInfo := &InfoTrain{nil, info.PublicKey, info.Signature, info.CtName, info.UserName, info.Time, info.Other}
	copyInfo.SetInfoTrainHash()
	return bytes.Compare(info.Hash, copyInfo.Hash) == 0
}
func (info *InfoTrain) SetInfoTrainHash() {
	hash := sha256.Sum256(info.SerializeInfoTrain())
	info.Hash = hash[:]
}

func (info *InfoTrain) IsCoinBaseCertificate() bool {
	return info.Time == "" && info.CtName == ""
}

//获取列车的hash值
func (info *InfoTrain) HashInfoTrain() []byte {
	var hash [32]byte
	Copy := *info
	Copy.Hash = []byte{}
	hash = sha256.Sum256(Copy.SerializeInfoTrain())
	return hash[:]
}

func (info *InfoTrain) Verify() bool {
	if info.IsCoinBaseCertificate() {
		return true
	}
	cerCopy := info.TrimmedCopy()
	curve := elliptic.P256()
	cerCopy.Hash = cerCopy.HashInfoTrain()
	r := big.Int{}
	s := big.Int{}
	sign := info.Signature
	signLen := len(sign)
	r.SetBytes(sign[:(signLen / 2)])
	s.SetBytes(sign[(signLen / 2):])

	x := big.Int{}
	y := big.Int{}
	pubKey := info.PublicKey
	pubKeyLen := len(pubKey)
	x.SetBytes(pubKey[:(pubKeyLen / 2)])
	y.SetBytes(pubKey[(pubKeyLen / 2):])
	rawPubKey := ecdsa.PublicKey{curve, &x, &y}
	if !ecdsa.Verify(&rawPubKey, cerCopy.Hash, &r, &s) {
		return false
	}
	return true
}

func (info *InfoTrain) TrimmedCopy() InfoTrain {
	copyInfoTrain := InfoTrain{info.Hash,
		nil,
		nil,
		info.CtName,
		info.UserName,
		//info.RipeMd160Hash,
		info.Time,
		info.Other,
	}
	//cerCopy:=InfoTrain{info.Hash, info.PublicKey,nil,info.CtName}
	return copyInfoTrain
}

func (info *InfoTrain) Sign(privateKey ecdsa.PrivateKey) {
	if info.IsCoinBaseCertificate() {
		return
	}

	cerCopy := info.TrimmedCopy()
	//cerCopy.InfoTrainrmation.Signature = nil
	cerCopy.Hash = cerCopy.HashInfoTrain()
	//cerCopy.InfoTrainrmation.PublicKey=append(privateKey.PublicKey.X.Bytes(),privateKey.Y.Bytes()...)
	//签名代码
	r, s, err := ecdsa.Sign(rand.Reader, &privateKey, cerCopy.Hash)
	global.MyError(err)
	signature := append(r.Bytes(), s.Bytes()...)
	info.Signature = signature
}
