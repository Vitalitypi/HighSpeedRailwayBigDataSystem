package global

//system相关的常量
const AddressChecksumLen = 4
const (
	BlockchainTrain = "train"
	BlockchainUser  = "user"
)

//系统相关路径
const QrCodePath = "D:\\program\\go\\Goland\\program\\src\\HighSpeedRailwayBigDataSystem\\file\\images\\qrcode\\"
const ConfigPath = "D:\\program\\go\\Goland\\program\\src\\HighSpeedRailwayBigDataSystem\\file\\configs\\"
const DatabasePath = "D:\\program\\go\\Goland\\program\\src\\HighSpeedRailwayBigDataSystem\\file\\dbs"
const GenesisPath = ConfigPath + "HSRBDS_.db"

type NodeStatus uint

const (
	BureauStatus NodeStatus = iota
	TrainStatus
	UserStatus
)

//即，每隔3s会定时清空Pool,但是Pool的长度超过3000也将会进行清除
//系统update延迟系数
const UpdateDelay = 100
const NumMember = 5

//系统共识池溢出系数
const PoolFill = 500
const NumGroup = 4
const BasePort = 5000
const CmdLength = 12
const Version = 1
const DBName = DatabasePath + "\\HSRBDS_%s.db"
const TableName = "blockchain"

//const Admin = "93dc18ad4422244e58c23d1d878a87ba1b6d9d86e94c151307308256a646ddfe5c6b23900db7436925defab49ad17fb2ad7a847de926a88bde550f6db0076f70" //管理员公钥字符串
const Protocol = "tcp"
const RecentBlockName_User = "recentUser"
const RecentBlockName_Train = "recentTrain"

const GenesisBlockName_User = "genesisBlockUser"
const GenesisBlockName_Train = "genesisBlockTrain"
