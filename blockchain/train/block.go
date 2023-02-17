package train

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/yonggewang/bdls/blockchain/common"
	"github.com/yonggewang/bdls/global"
	"rlp"
	"strconv"
	"time"
)

func SetNewBodyTrain() {
	body := &Block_Body_Train{
		nil,
		GetInfoTrainHashes(),
	}
	body.SetBodyHash()
	NewBodyTrain = body
}
func SetNewHeaderTrain() {
	blockchainTrain := &BlockChain_Train{global.BlockChainTotal.TipHashTrain, global.BlockChainTotal.DB}
	lastHeader := blockchainTrain.Iterator().Next()
	header := &Block_Header_Train{
		lastHeader.Height + 1,
		global.AggQC,
		lastHeader.Hash,
		NewBodyTrain.Hash,
		uint64(time.Now().Unix()),
		nil,
		0,
	}
	header.SetHeaderHash()
	NewHeaderTrain = header
}
func (block *Block_Header_Train) SerializeBlockHeader() []byte {
	bytes, err := rlp.EncodeToBytes(block)
	global.MyError(err)
	return bytes
}
func (block *Block_Body_Train) SerializeBlockBody() []byte {
	bytes, err := rlp.EncodeToBytes(block)
	global.MyError(err)
	return bytes
}
func (header *Block_Header_Train) VerifyTrainHeaderHash() bool {
	copyHeader := &Block_Header_Train{header.Height, header.Qc, header.PreviousHash,
		header.BlockBodyHashTrain, header.TimeStamp, nil, header.Nonce}
	copyHeader.SetHeaderHash()
	return bytes.Compare(header.Hash, copyHeader.Hash) == 0
}
func (body *Block_Body_Train) VerifyTrainBodyHash() bool {
	copyBody := &Block_Body_Train{nil, body.InfoHash}
	copyBody.SetBodyHash()
	return bytes.Compare(body.Hash, copyBody.Hash) == 0
}
func DeserializeBlockHeader(bytes []byte) *Block_Header_Train {
	header := &Block_Header_Train{}
	err := rlp.DecodeBytes(bytes, header)
	global.MyError(err)
	return header
}
func DeserializeBlockBody(bytes []byte) *Block_Body_Train {
	body := &Block_Body_Train{}
	err := rlp.DecodeBytes(bytes, body)
	global.MyError(err)
	return body
}

//func (body *Block_Body_Train)GetTrainBlockBodyHash() []byte {
//	bytes:=body.SerializeBlockBody()
//	hash:=sha256.Sum256(bytes)
//	return hash[:]
//}
func (header *Block_Header_Train) PrintTrainHeader() {
	fmt.Println("证书区块链高度：", header.Height)
	fmt.Printf("证书区块链Qc:%x\n", header.Qc)
	fmt.Printf("上一区块hash：%x\n", header.PreviousHash)
	fmt.Printf("证书区块体根hash：%x\n", header.BlockBodyHashTrain)
	fmt.Printf("TimeStamp:%s\n", time.Unix(int64(header.TimeStamp), 0).Format("2006-01-02 03:04:05 PM"))
	fmt.Printf("当前区块hash：%x\n", header.Hash)
	fmt.Println("Nounce:", header.Nonce)

}
func (header *Block_Header_Train) SetHeaderHash() {
	heightBytes := global.IntToHex(header.Height)
	timeString := strconv.FormatInt(int64(header.TimeStamp), 2)
	timeBytes := []byte(timeString)
	totalBytes := bytes.Join([][]byte{
		heightBytes,
		header.PreviousHash,
		header.BlockBodyHashTrain,
		timeBytes,
		header.Hash,
	}, []byte{})
	hash := sha256.Sum256(totalBytes)
	header.Hash = hash[:]
}
func (body *Block_Body_Train) SetBodyHash() {
	bytes := body.SerializeBlockBody()
	hash := sha256.Sum256(bytes)
	body.Hash = hash[:]
}

//先进行排序，再进行加入数组
func GetInfoTrainHashes() [][]byte {
	var hashes [][]byte
	for _, v := range common.Map_InfoTrain {
		hashes = append(hashes, v.Hash)
		length := len(hashes)
		for i := length - 1; i > 0; i-- {
			if hex.EncodeToString(hashes[i]) < hex.EncodeToString(hashes[i-1]) {
				hashes[i], hashes[i-1] = hashes[i-1], hashes[i]
			} else {
				break
			}
		}
	}
	//fmt.Println("TrainHash:",hashes)
	//for _,i:=range global_InfoTrains{
	//	hashes = append(hashes,i.Hash)
	//}
	return hashes
}
func NewBlock(height uint64, previousHash []byte) (*Block_Header_Train, *Block_Body_Train) {
	body := &Block_Body_Train{
		nil,
		GetInfoTrainHashes(),
	}
	body.SetBodyHash()
	header := &Block_Header_Train{
		height,
		nil,
		previousHash,
		body.Hash,
		uint64(time.Now().Unix()),
		nil,
		0,
	}
	header.SetHeaderHash()
	return header, body
}

func CreateGenesisBlock() (*Block_Header_Train, *Block_Body_Train) {
	//公钥转字节数组
	bytes, err := hex.DecodeString("73ccd17cdc6275381f365f14e24ccae8e95a216d399889ff793a7a59e134795ce7270a9009b11b250235d314499f2258d9c8952a298bc2d5b09ae80c821f676d")
	global.MyError(err)

	info := &common.InfoTrain{
		nil,
		bytes,
		nil,
		"...",
		[]string{"管理员"},
		"2022.3.2",
		"",
	}
	info.SetInfoTrainHash()
	//info.Sign()
	//info.Sign()
	common.Map_InfoTrain[hex.EncodeToString(info.Hash)] = info
	//global_InfoTrains=InsertInfoTrain(info,global_InfoTrains)
	header, body := NewBlock(1, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	return header, body

}
