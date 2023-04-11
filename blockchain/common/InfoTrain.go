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

type InfoTrain struct {
	Hash          []byte //列车信息hash
	PublicKey     []byte //公钥
	Signature     []byte //数字签名
	Event         string //列车名称
	UserName      string //列车人员姓名
	Time          string //时间
	Infos         string //其他信息
	PreviousTrain []byte //发布该列车信息的乘务员所发布的前一信息
}

func GetStringInfoTrain(infoBytes []byte) string {
	info := &InfoTrain{}
	if len(infoBytes) == 0 {
		return ""
	}
	err := rlp.DecodeBytes(infoBytes, info)
	global.MyError(err)
	userNames := info.UserName
	result := "\n列车信息：|||公钥：" + hex.EncodeToString(info.PublicKey) + "\n|||签名：" + hex.EncodeToString(info.Signature) + "" +
		"\n|||Hash:" + hex.EncodeToString(info.Hash) +
		"\n|||作品名称：" + info.Event +
		"\n|||作者：" + userNames +
		"\n|||时间：" + info.Time +
		"\n|||其他：" + info.Infos
	return result
}
func (info *InfoTrain) PrintInfoTrain() {
	fmt.Printf("当前列车信息hash：%x\n", info.Hash)
	fmt.Printf("当前列车信息公钥：%x\n", info.PublicKey)
	fmt.Printf("当前列车信息数字签名：%x\n", info.Signature)
	fmt.Println("列车事件：", info.Event)
	fmt.Println("登记人员：", info.UserName)
	fmt.Println("时间：", info.Time)
	fmt.Println("其他信息：", info.Infos)
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
	copyInfo := &InfoTrain{nil, info.PublicKey, info.Signature, info.Event, info.UserName, info.Time, info.Infos, info.PreviousTrain}
	copyInfo.SetInfoTrainHash()
	return bytes.Compare(info.Hash, copyInfo.Hash) == 0
}
func (info *InfoTrain) SetInfoTrainHash() {
	hash := sha256.Sum256(info.SerializeInfoTrain())
	info.Hash = hash[:]
}

func (info *InfoTrain) IsCoinBaseTrain() bool {
	return info.Time == "" && info.Event == ""
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
	if info.IsCoinBaseTrain() {
		return true
	}
	cerCopy := info.TrimmedCopy()
	//curve := elliptic.P256()
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
	rawPubKey := ecdsa.PublicKey{global.S256Curve, &x, &y}
	if !ecdsa.Verify(&rawPubKey, cerCopy.Hash, &r, &s) {
		return false
	}
	return true
}

func (info *InfoTrain) TrimmedCopy() InfoTrain {
	copyInfoTrain := InfoTrain{info.Hash,
		nil,
		nil,
		info.Event,
		info.UserName,
		//info.RipeMd160Hash,
		info.Time,
		info.Infos,
		info.PreviousTrain,
	}
	//cerCopy:=InfoTrain{info.Hash, info.PublicKey,nil,info.ItName}
	return copyInfoTrain
}

func (info *InfoTrain) Sign(privateKey ecdsa.PrivateKey) {
	if info.IsCoinBaseTrain() {
		return
	}

	cerCopy := info.TrimmedCopy()
	//cerCopy.InfoTrainrmation.Signature = nil
	cerCopy.Hash = cerCopy.HashInfoTrain()
	//cerCopy.InfoTrainrmation.PublicKey=append(privateKey.PublicKey.X.Bytes(),privateKey.Y.Bytes()...)
	//签名代码
	r, s, err := ecdsa.Sign(rand.Reader, &privateKey, cerCopy.Hash)
	global.MyError(err)
	signature := global.GetFillBytes(r, s)
	info.Signature = signature
	info.Hash = info.HashInfoTrain()
}
