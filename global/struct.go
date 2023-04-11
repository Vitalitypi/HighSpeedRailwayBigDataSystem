package global

import (
	"github.com/bolt"
	"math/big"
)

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
type Config struct {
	Next  [][]string `json:"next"` //address:Ip+Port
	Prev  []string   `json:"prev"`
	Group [][]string `json:"group"`
}
type ConsensusInfo struct {
	Type string //user or train
	Data []byte //info of user or train
}
type BlockInfos struct {
	Infos []*ConsensusInfo
}
type BlockData struct {
	//HeaderUser  []byte
	//HeaderTrain []byte
	Hash      []byte
	Info      []byte
	TimeStamp uint64
}
type BlockDataInfos struct {
	Blocks [][]byte
}

//生成秘钥
type AccountConfig struct {
	Accounts []*Account `json:"accounts"`
}
type Account struct {
	Admin [][]string `json:"admin"`
	Users [][]string `json:"users"`
}
type Quorums struct {
	Keys map[string]*big.Int `json:"keys"`
}
