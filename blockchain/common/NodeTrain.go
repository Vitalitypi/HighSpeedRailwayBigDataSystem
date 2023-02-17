package common

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/yonggewang/bdls/global"
	"rlp"
)

type NodeTrain struct {
	Hash          []byte   //当前节点hash
	TrainInfoHash [][]byte //证书信息hash
	PreviousHash  []byte   //之前区块的证书节点hash
	NextHash      []byte   //下一个节点hash//初始为nil
}

func (node *NodeTrain) SerializeNodeTrain() []byte {
	bytes, err := rlp.EncodeToBytes(node)
	global.MyError(err)
	return bytes
}
func (node *NodeTrain) PrintNodeTrain() {
	fmt.Println("开始打印NodeTrain...")
	fmt.Printf("Hash:%x\n", node.Hash)
	fmt.Printf("CertificateInfoHash:%x\n", node.TrainInfoHash)
	fmt.Printf("PreviousHash:%x\n", node.PreviousHash)
	fmt.Printf("NextHash:%x\n", node.NextHash)
	fmt.Println("打印结束...")
}
func DeserializeNodeTrain(bytes []byte) *NodeTrain {
	node := &NodeTrain{}
	if len(bytes) == 0 {
		return nil
	}
	err := rlp.DecodeBytes(bytes, node)
	global.MyError(err)
	return node
}
func (node *NodeTrain) VerifyNodeTrainHash() bool {
	copyNode := &NodeTrain{nil, node.TrainInfoHash, node.PreviousHash, node.NextHash}
	copyNode.SetNodeTrainHash()
	return bytes.Compare(node.Hash, copyNode.Hash) == 0
}
func (node *NodeTrain) SetNodeTrainHash() {
	hash := sha256.Sum256(node.SerializeNodeTrain())
	node.Hash = hash[:]
}

func NewNodeTrain(infoHash [][]byte, previousHash []byte, nextNodeHash []byte) *NodeTrain {
	var node *NodeTrain
	node = &NodeTrain{nil, infoHash, previousHash, nextNodeHash}
	node.SetNodeTrainHash()
	return node
}
