package common

import "github.com/bolt"

//存储区块链指针
type BlockChain struct {
	DB           *bolt.DB //数据库
	TipHashUser  []byte
	TipHashTrain []byte
}

var BlockChainTotal *BlockChain
