package common

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"github.com/yonggewang/bdls/global"
	"rlp"
)

//用户节点
type NodeUser struct {
	Hash              []byte //用户节点的hash
	PubKey            []byte //用户公钥
	UserInfoHash      []byte //用户信息hash
	NodeTrainRootHash []byte //列车节点根hash
}

func (node *NodeUser) PrintNodeUser() {
	fmt.Println("开始打印用户节点")
	fmt.Printf("Hash:%x\n", node.Hash)
	fmt.Printf("PubKey:%x\n", node.PubKey)
	fmt.Printf("UserInfoHash:%x\n", node.UserInfoHash)
	fmt.Printf("NodeTrainRootHash:%x\n", node.NodeTrainRootHash)
	//获取列车节点根hash
}
func (nodeUser *NodeUser) SetNodeUserHash() {
	hash := sha256.Sum256(nodeUser.SerializeNodeUser())
	nodeUser.Hash = hash[:]
}
func (nodeUser *NodeUser) SerializeNodeUser() []byte {
	bs, err := rlp.EncodeToBytes(nodeUser)
	global.MyError(err)
	return bs
}
func (nodeUser *NodeUser) VerifyNodeUserHash() bool {
	copyNodeUser := &NodeUser{nil, nodeUser.PubKey, nodeUser.UserInfoHash, nodeUser.NodeTrainRootHash}
	copyNodeUser.SetNodeUserHash()
	return bytes.Compare(nodeUser.Hash, copyNodeUser.Hash) == 0
}
func NewNodeUser(pubKey []byte, userInfoHash []byte, nodeTrainRootHash []byte) *NodeUser {
	var node *NodeUser
	node = &NodeUser{nil, pubKey, userInfoHash, nodeTrainRootHash}
	node.SetNodeUserHash()
	return node
}
func DeserializeNodeUser(bytes []byte) *NodeUser {
	node := &NodeUser{}
	//fmt.Println("nodeUserBytes:\n",bytes)
	err := rlp.DecodeBytes(bytes, node)
	global.MyError(err)
	return node
}
