package global

import "github.com/bolt"

type BlockChainUserData struct {
	HeaderBytes    [][]byte
	BodyBytes      [][]byte
	NodeUserBytes  [][][]byte
	NodeTrainBytes [][][]byte
	UserInfoBytes  [][]byte
}
type BlockChainTrainData struct {
	HeaderBytes    [][]byte
	BodyBytes      [][]byte
	TrainInfoBytes [][][]byte
}

//存储区块链指针
type BlockChain struct {
	DB           *bolt.DB //数据库
	TipHashUser  []byte
	TipHashTrain []byte
}
