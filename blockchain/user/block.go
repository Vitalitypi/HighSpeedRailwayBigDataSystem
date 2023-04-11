package user

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

func (body *Block_Body_User) PrintBodyUser() {
	fmt.Println("开始打印用户区块体...")
	fmt.Printf("Body hash :%x", body.Hash)
	fmt.Printf("Body UserInfoAddr :%x", body.InfoHashes)
}
func (header *Block_Header_User) PrintUserHeader() {
	fmt.Println("用户区块链高度：", header.Height)
	//fmt.Printf("列车区块链Qc:%x\n", header.Qc)
	fmt.Printf("上一区块hash：%x\n", header.PreviousHash)
	fmt.Printf("用户节点根hash：%x\n", header.BlockBodyHashUser)
	fmt.Printf("TimeStamp:%s\n", time.Unix(int64(header.TimeStamp), 0).Format("2006-01-02 03:04:05 PM"))
	fmt.Printf("当前区块hash：%x\n", header.Hash)
	fmt.Println("Nonce:", header.Nonce)
}

//将区块信息序列化为字节数组
func (block *Block_Header_User) SerializeBlockHeader() []byte {
	result, err := rlp.EncodeToBytes(block)
	global.MyError(err)
	return result
}
func (block *Block_Body_User) SerializeBlockBody() []byte {
	result, err := rlp.EncodeToBytes(block)
	global.MyError(err)
	return result
}
func DeserializeBlockHeader(bytes []byte) *Block_Header_User {
	header := &Block_Header_User{}
	err := rlp.DecodeBytes(bytes, header)
	global.MyError(err)
	return header
}
func DeserializeBlockBody(bytes []byte) *Block_Body_User {
	body := &Block_Body_User{}
	err := rlp.DecodeBytes(bytes, body)
	global.MyError(err)
	return body
}
func (header *Block_Header_User) SetHeaderHash() {
	heightBytes := global.IntToHex(header.Height)
	timeString := strconv.FormatInt(int64(header.TimeStamp), 2)
	timeBytes := []byte(timeString)
	totalBytes := bytes.Join([][]byte{
		heightBytes,
		header.PreviousHash,
		header.BlockBodyHashUser,
		timeBytes,
		header.Hash,
	}, []byte{})
	hash := sha256.Sum256(totalBytes)
	header.Hash = hash[:]
}
func (body *Block_Body_User) SetBodyHash() {
	bytes := body.SerializeBlockBody()
	hash := sha256.Sum256(bytes)
	body.Hash = hash[:]
}
func (header *Block_Header_User) VerifyHeaderHashUser() bool {
	copyHeader := &Block_Header_User{header.Height, header.PreviousHash,
		header.BlockBodyHashUser, header.TimeStamp, nil, header.Nonce}
	copyHeader.SetHeaderHash()
	return bytes.Compare(header.Hash, copyHeader.Hash) == 0
}
func (body *Block_Body_User) VerifyBodyHashUser() bool {
	copyBody := &Block_Body_User{nil, body.InfoHashes}
	copyBody.SetBodyHash()
	return bytes.Compare(body.Hash, copyBody.Hash) == 0
}
func GetNodeUsersHashes() [][]byte {
	var hashes [][]byte
	for _, v := range common.InfoUserPool {
		hashes = append(hashes, v.Hash)
	}
	return hashes
}
func SetNewBodyUser() {
	body := &Block_Body_User{
		nil,
		GetNodeUsersHashes(),
	}
	body.SetBodyHash()
	NewBodyUser = body
}
func SetNewHeaderUser(timeStamp uint64) []byte {
	SetNewBodyUser()
	blockchainUser := &BlockChain_User{global.BlockChainTotal.TipHashUser, global.BlockChainTotal.DB}
	lastHeader := blockchainUser.Iterator().Next()
	header := &Block_Header_User{
		lastHeader.Height + 1,
		//global.AggQC,
		lastHeader.Hash,
		NewBodyUser.Hash,
		timeStamp,
		nil,
		0,
	}
	header.SetHeaderHash()
	//NewHeaderUser = header
	return header.SerializeBlockHeader()
}
func (body *Block_Body_User) GetUserInfoMapRootHash() []byte {
	bytes := body.SerializeBlockBody()
	hash := sha256.Sum256(bytes)
	return hash[:]
}
func CreateGenesisBlock() (*Block_Header_User, *Block_Body_User) {
	//将所有管理员信息添加到用户信息、用户节点
	for i := 0; i < len(global.Admin); i++ {
		pubKey := global.Admin[i]
		//公钥转字节数组
		bytes, err := hex.DecodeString(pubKey)
		global.MyError(err)
		userInfo := &common.InfoUser{nil,
			bytes,
			nil,
			bytes,
			[]byte("bureau"),
			[]byte{},
		}
		userInfo.SetInfoUserHash()
		//Global_UserInfos=InsertGlobalUserInfo(userInfo,Global_UserInfos)
		//common.Map_InfoUser[address] = userInfo
		common.InfoUserPool = append(common.InfoUserPool, userInfo)
		//加入新的用户节点
	}

	header, body := NewBlock(1, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	return header, body
}
func NewBlock(height uint64, previousHash []byte) (*Block_Header_User, *Block_Body_User) {
	body := &Block_Body_User{
		nil,
		GetNodeUsersHashes(),
	}
	body.SetBodyHash()
	header := &Block_Header_User{
		height,
		//nil,
		previousHash,
		body.Hash,
		uint64(time.Now().Unix()),
		nil,
		0,
	}
	header.SetHeaderHash()
	return header, body
}
