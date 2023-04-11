package common

import "sync"

//user
//var Map_NodeUser = make(map[string]*NodeUser) //用户节点
//var Map_InfoUser = make(map[string]*InfoUser) //用户信息
var InfoUserPool = []*InfoUser{}

var RWUserPool sync.RWMutex

//用户信息池
//var InfoUserPool = []*InfoUser{}

//string(列车信息的hash)与列车信息的map
//var Map_InfoTrain = make(map[string]*InfoTrain)

//存储区块链的指针

//列车信息池
var InfoTrainPool = []*InfoTrain{}

var RWTrainPool sync.RWMutex
