package global

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/bolt"
	"golang.org/crypto/ripemd160"
	"log"
	"math/big"
	"os"
	"rlp"
	"time"
)

var b58Alphabet = []byte("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz")

//将秘钥转化为字符串
func StringPrivate(priKey ecdsa.PrivateKey) string {
	var content bytes.Buffer
	gob.Register(S256Curve)
	encoder := gob.NewEncoder(&content)
	err := encoder.Encode(priKey)
	MyError(err)
	return hex.EncodeToString(content.Bytes())
}

//将字符串转秘钥
func BackPrivate(private string) ecdsa.PrivateKey {
	var priKey ecdsa.PrivateKey
	keyBytes, err := hex.DecodeString(private)
	MyError(err)
	gob.Register(S256Curve)
	decoder := gob.NewDecoder(bytes.NewReader(keyBytes))
	err = decoder.Decode(&priKey)
	MyError(err)
	return priKey
}
func ReverseBytes(data []byte) {
	for i, j := 0, len(data)-1; i < j; i, j = i+1, j-1 {
		data[i], data[j] = data[j], data[i]
	}
}
func GetBlockChain(portId string) *BlockChain {
	dbName := fmt.Sprintf(DBName, portId)
	var tipHashUser []byte
	var tipHashCertificate []byte
	log.Print("open database...")
	db, err := bolt.Open(dbName, 0600, nil)
	MyError(err)
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(TableName))
		if b != nil {
			tipHashUser = b.Get([]byte(RecentBlockName_User))
			tipHashCertificate = b.Get([]byte(RecentBlockName_Train))
		}
		return nil
	})
	MyError(err)
	return &BlockChain{db, tipHashUser, tipHashCertificate}
}

//获取当前账户的最新记录
func GetPrevious(bts []byte) []byte {
	var ans []byte
	err := BlockChainTotal.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(TableName))
		if b != nil {
			ans = b.Get(bts)
		}
		return nil
	})
	MyError(err)
	return ans
}
func SerializeBlocks() []byte {
	RWMutexBlock.Lock()
	bts, err := rlp.EncodeToBytes(Blocks)
	MyError(err)
	Blocks.Blocks = [][]byte{}
	RWMutexBlock.Unlock()
	return bts
}
func SetBlocksInfoBytes(bts []byte) error {
	blocks := &BlockDataInfos{}
	err := rlp.DecodeBytes(bts, blocks)
	RWMutexBlock.Lock()
	Blocks.Blocks = append(Blocks.Blocks, blocks.Blocks...)
	RWMutexBlock.Unlock()
	return err
}
func DeserializeBlockDataInfos(bts []byte) *BlockDataInfos {
	blocks := &BlockDataInfos{}
	err := rlp.DecodeBytes(bts, blocks)
	MyError(err)
	return blocks
}
func SerializeBlockInfos() []byte {
	RWMutexConsensusPool.Lock()
	pool := &BlockInfos{}
	if len(ConsensusInfoPool.Infos) > PoolFill*3/5 {
		pool.Infos = ConsensusInfoPool.Infos[:PoolFill*3/5]
		ConsensusInfoPool.Infos = ConsensusInfoPool.Infos[PoolFill*3/5:]
	} else {
		pool.Infos = ConsensusInfoPool.Infos
		ConsensusInfoPool.Infos = []*ConsensusInfo{}
	}
	bts, err := rlp.EncodeToBytes(pool)
	MyError(err)
	RWMutexConsensusPool.Unlock()
	return bts
}
func HashBlockData(bts []byte) []byte {
	hash := sha256.Sum256(bts)
	return hash[:]
}
func SerializeBlockData() []byte {
	timeStamp := uint64(time.Now().Unix())
	blockData := &BlockData{nil, SerializeBlockInfos(), timeStamp}
	//blockData.Hash = hashBlockData(blockData)
	bts, err := rlp.EncodeToBytes(blockData)
	MyError(err)
	return bts
}
func DeserializeBlockInfos(infoBytes []byte) *BlockInfos {
	blockInfos := &BlockInfos{}
	err := rlp.DecodeBytes(infoBytes, blockInfos)
	MyError(err)
	return blockInfos
}
func DeserializeBlockData(infoBytes []byte) *BlockData {
	blockData := &BlockData{}
	//fmt.Println("DeserializeBlockData", len(infoBytes))
	err := rlp.DecodeBytes(infoBytes, blockData)
	MyError(err)
	return blockData
}
func SetConsensusInfoBytes(infoBytes []byte) error {
	infos := &BlockInfos{}
	err := rlp.DecodeBytes(infoBytes, infos)
	MyError(err)
	RWMutexConsensusPool.Lock()
	ConsensusInfoPool.Infos = append(ConsensusInfoPool.Infos, infos.Infos...)
	RWMutexConsensusPool.Unlock()
	return err
}
func Base58Encode(input []byte) []byte {
	var result []byte
	x := big.NewInt(0).SetBytes(input)
	base := big.NewInt(int64(len(b58Alphabet)))
	zero := big.NewInt(0)
	mod := &big.Int{}

	for x.Cmp(zero) != 0 {
		x.DivMod(x, base, mod)
		result = append(result, b58Alphabet[mod.Int64()])
	}
	ReverseBytes(result)
	for b := range input {
		if b == 0x00 {
			result = append([]byte{b58Alphabet[0]}, result...)
		} else {
			break
		}
	}
	return result
}

func IntToHex(num uint64) []byte {
	buff := new(bytes.Buffer)
	err := binary.Write(buff, binary.BigEndian, num)
	if err != nil {
		log.Panic(err)
	}
	return buff.Bytes()
}
func MyError(err error) {
	if err != nil {
		log.Panic(err)
	}
}
func HashPubKey(pubKey []byte) []byte {
	//256
	publicSHA256 := sha256.Sum256(pubKey)
	//160
	RIPEMD160Hasher := ripemd160.New()
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	MyError(err)
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)
	return publicRIPEMD160
}
func CheckSum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])
	return secondSHA[:AddressChecksumLen]
}
func GetAddress(pubKey []byte) []byte {
	//1、先将publicKey hash160
	pubKeyHash := HashPubKey(pubKey)
	//添加version
	versionedPayload := append([]byte{Version}, pubKeyHash...)

	checkSumBytes := CheckSum(versionedPayload)
	//checkSumBytes:=CheckSum(pubKeyHash)

	fullPayload := append(versionedPayload, checkSumBytes...)
	address := Base58Encode(fullPayload)
	return address
}

//配置文件相关
func CreateConfigUsers(account *Account) {
	//创建用户配置
	config := &Config{}
	config.Group = account.Users
	config.Prev = account.Admin[0]
	for i := 0; i < len(account.Users); i++ {
		fileName := fmt.Sprintf(ConfigPath+"config_%s.json", account.Users[i][1])
		file, err := os.Create(fileName)
		MyError(err)
		enc := json.NewEncoder(file)
		enc.SetIndent("", "\t")
		err = enc.Encode(config)
		MyError(err)
		file.Close()
	}
}
func CreateConfigAdmin(account *Account, groups [][]string) {
	//创建管理员配置
	config := &Config{}
	config.Group = groups
	config.Next = account.Users
	fileName := fmt.Sprintf(ConfigPath+"config_%s.json", account.Admin[0][1])
	file, err := os.Create(fileName)
	MyError(err)
	enc := json.NewEncoder(file)
	enc.SetIndent("", "\t")
	err = enc.Encode(config)
	MyError(err)
	file.Close()
}
func GetPublicKey(public ecdsa.PublicKey) []byte {
	btsX := make([]byte, 32)
	btsY := make([]byte, 32)
	public.X.FillBytes(btsX)
	public.Y.FillBytes(btsY)
	return append(btsX, btsY...)
}
func GetFillBytes(x, y *big.Int) []byte {
	btsX := make([]byte, 32)
	btsY := make([]byte, 32)
	x.FillBytes(btsX)
	y.FillBytes(btsY)
	return append(btsX, btsY...)
}
