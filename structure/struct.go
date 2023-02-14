package structure

//定义区块链的一些数据结构，包括：用户链、客运链

//创世区块，第一个元素为区块头、第二个元素为区块体
type BlockGenesis struct {
	BlockUser  [][]byte //用户区块
	BlockTrain [][]byte //客运区块
	InfoTrain  []byte   //创世区块证书信息
	InfoUser   []byte   //用户信息字节
	NodeUser   []byte   //用户节点字节
}
