package global

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"github.com/yonggewang/bdls/crypto/btcec"
	"math/big"
	"sync"
)

//系统相关
var Cfg *Config
var ConsensusInfoPool = &BlockInfos{}
var RWMutexConsensusPool sync.RWMutex
var S256Curve elliptic.Curve = btcec.S256()
var Blocks = &BlockDataInfos{}
var RWMutexBlock sync.RWMutex
var (
	ChBlockchainUser  = make(chan struct{})
	ChBlockchainTrain = make(chan struct{})
)
var (
	InfoUserCount  uint64
	InfoTrainCount uint64
	CurrentId      int
)
var MapBlockData = make(map[uint64][]byte)
var MapBlocksData = make(map[uint64][]byte)
var MapUserData = make(map[string]*big.Int)

//应用层
var Admin []string //管理员公钥数组
var Keys []*big.Int
var UserKeys = make([][]*big.Int, NumGroup)
var Users = make([][]string, NumGroup)
var PublicKey []byte             //当前登录用户公钥
var PrivateKey *ecdsa.PrivateKey //当前登录用户私钥
var D *big.Int                   //存储当前账户的D值
var StatusLogin NodeStatus       //记录当前的身份状态

//网络层
var PortId string //同层通信端口
var HttpId string //其他通信端口

//数据结构层
var BlockChainTotal *BlockChain

//记录上一区块的高度
var BlockchainHeightTrain uint64
var BlockchainHeightUser uint64
