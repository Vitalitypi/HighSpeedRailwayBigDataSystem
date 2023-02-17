package user

import "github.com/bolt"

//定义区块头
type Block_Header_User struct {
	Height            uint64
	Qc                []byte
	PreviousHash      []byte
	BlockBodyHashUser []byte
	TimeStamp         uint64
	Hash              []byte
	Nonce             uint64
}

//定义区块体
type Block_Body_User struct {
	Hash          []byte
	NodeHashUsers [][]byte
}

//区块链
type BlockChain_User struct {
	TipUser []byte   //最新区块的hash
	DB      *bolt.DB //数据库指针
}
type BlockChainIteratorUser struct {
	CurrentHash []byte
	DB          *bolt.DB
}

//相关变量
var BlockchainUser *BlockChain_User
var NewBodyUser *Block_Body_User
var NewHeaderUser *Block_Header_User
