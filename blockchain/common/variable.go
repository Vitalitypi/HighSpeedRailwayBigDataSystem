package common

//user
var Map_NodeUser = make(map[string]*NodeUser) //用户节点
var Map_UserInfo = make(map[string]*InfoUser) //用户信息
//用户信息池
var UserInfoPool = []*InfoUser{}

//string(证书信息的hash)与证书信息的map
var Map_InfoTrain = make(map[string]*InfoTrain)

//var Map_CertificateInfo_Buff=make()
//存储区块链的指针

//证书信息池
var InfoTrainPool = []*InfoTrain{}
