package train

import "github.com/bolt"

type Block_Header_Train struct {
	Height             uint64
	Qc                 []byte
	PreviousHash       []byte
	BlockBodyHashTrain []byte
	TimeStamp          uint64
	Hash               []byte
	Nonce              uint64
}
type Block_Body_Train struct {
	Hash     []byte
	InfoHash [][]byte
}

//区块链
type BlockChain_Train struct {
	//Blocks []*Block//储存有序区块
	TipTrain []byte   //最新区块的hash
	DB       *bolt.DB //数据库
}
type BlockChainIteratorTrain struct {
	CurrentHash []byte
	DB          *bolt.DB
}

//相关变量
var BlockchainTrain *BlockChain_Train
var NewBodyTrain *Block_Body_Train
var NewHeaderTrain *Block_Header_Train
