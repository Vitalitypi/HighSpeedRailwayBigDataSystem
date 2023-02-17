package global

import "crypto/ecdsa"

//应用层
var PublicKey []byte            //当前登录用户公钥
var PrivateKey ecdsa.PrivateKey //当前登录用户私钥
var AddressString string        //当前用户地址字符串

//共识层
var AggQC []byte

//网络层
var PortId string //当前节点端口号
var MyNode string //本机地址 例如：127.0.0.1:1111

//数据结构层
var BlockChainTotal *BlockChain
