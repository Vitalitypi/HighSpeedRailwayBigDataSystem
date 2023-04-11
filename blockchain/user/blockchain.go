package user

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/bolt"
	"github.com/yonggewang/bdls/blockchain/common"
	"github.com/yonggewang/bdls/global"
	"log"
	"math/big"
	"time"
)

//返回一个二维字节数组，依次为区块头字节数组，区块体，用户节点，用户信息
func (blockchain *BlockChain_User) PrintBlockChainUser() {
	var header *Block_Header_User
	var body *Block_Body_User
	var currentHash = blockchain.TipUser
	for {
		err := blockchain.DB.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(global.TableName))
			if b != nil {
				//获取当前区块
				headerBytes := b.Get(currentHash)
				header = DeserializeBlockHeader(headerBytes)
				bodyBytes := b.Get(header.BlockBodyHashUser)
				body = DeserializeBlockBody(bodyBytes)
				header.PrintUserHeader()
				fmt.Println("\n===========\n开始打印用户区块体")
				for _, hash := range body.InfoHashes {
					bts := b.Get(hash)
					infoUser := common.DeserializeInfoUser(bts)
					infoUser.PrintInfoUser()
				}
				fmt.Println("用户区块体打印完毕\n===========")
			}
			return nil
		})
		global.MyError(err)
		var hashInt big.Int
		hashInt.SetBytes(header.PreviousHash)
		if big.NewInt(0).Cmp(&hashInt) == 0 {
			break
		} else {
			currentHash = header.PreviousHash
		}
	}
}

func (blockchain *BlockChain_User) GetUserHashes() [][]byte {
	var hashes [][]byte
	iterator := blockchain.Iterator()
	for {
		header := iterator.Next()
		//添加区块头hash
		if header == nil {
			break
		}
		hashes = append(hashes, header.Hash)
		//添加区块体hash
		//hashes = append(hashes, header.TrainBlockBodyHash)
		var hashInt big.Int
		hashInt.SetBytes(header.PreviousHash)
		if hashInt.Cmp(big.NewInt(0)) == 0 {
			break
		}
	}
	return hashes
}

func (blockchain *BlockChain_User) UiLoginVerify(d *big.Int) string {
	//admin, err := hex.DecodeString(global.Admin[0])
	//global.MyError(err)
	ans := "error"
	x, y := global.S256Curve.ScalarBaseMult(d.Bytes())
	public := global.GetFillBytes(x, y)
	addressBytes := global.GetAddress(public)
	//if bytes.Compare(public, admin) == 0 {
	//	return "admin"
	//}
	err := blockchain.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			//通过公钥字节数组获取用户信息
			bytes := b.Get(addressBytes)
			//fmt.Println(len(bytes))
			if len(bytes) != 0 {
				infoUser := common.DeserializeInfoUser(bytes)
				ans = string(infoUser.UInfo)
			}
		}
		return nil
	})
	global.MyError(err)
	return ans
}

func AddBlock(timeStamp uint64) {
	common.RWUserPool.Lock()
	SetNewBodyUser()
	blockchain := BlockChain_User{global.BlockChainTotal.TipHashUser, global.BlockChainTotal.DB}
	blockchain.AddBlockToBlockChain(timeStamp, NewBodyUser)
	//清空相关变量
	//NewHeaderUser = nil
	NewBodyUser = nil
	common.RWUserPool.Unlock()
	global.ChBlockchainUser <- struct{}{}
	fmt.Println("用户链区块添加成功...,已处理数目：", global.InfoUserCount)
}

func CreateBlockChainUser() *BlockChain_User {
	//dbName := fmt.Sprintf(global.DBName, global.PortId)
	var headerHash []byte
	log.Print("Create User BlockChain...")
	common.RWUserPool.Lock()
	db, err := bolt.Open(global.GenesisPath, 0600, nil)
	global.MyError(err)
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b == nil {
			b, err = tx.CreateBucket([]byte(global.TableName))
			global.MyError(err)
		}
		if b != nil {
			//创建创世区块
			genesisHeader, genesisBody := CreateGenesisBlock()
			//将创世区块头存储到表中
			headerBytes := genesisHeader.SerializeBlockHeader()
			err = b.Put([]byte(global.GenesisBlockName_User), headerBytes)
			global.MyError(err)
			err = b.Put(genesisHeader.Hash, headerBytes)
			global.MyError(err)
			//将创世区块体存储到表中
			err = b.Put(genesisHeader.BlockBodyHashUser, genesisBody.SerializeBlockBody())
			global.MyError(err)
			for i := 0; i < len(common.InfoUserPool); i++ {
				infoUser := common.InfoUserPool[i]
				infoUserBytes := infoUser.SerializeInfoUser()
				addressBytes := global.GetAddress(infoUser.Account)
				//将用户信息Hash-信息存储到数据库
				err = b.Put(infoUser.Hash, infoUserBytes)
				global.MyError(err)
				//6、将地址与用户信息存储到表
				err = b.Put(addressBytes, infoUserBytes)
				global.MyError(err)
			}
			//6、清空全局变量
			common.InfoUserPool = []*common.InfoUser{}
			err = b.Put([]byte(global.RecentBlockName_User), genesisHeader.Hash)
			global.MyError(err)
			headerHash = genesisHeader.Hash
		}
		return nil
	})
	fmt.Println("用户区块链已创建...")
	global.MyError(err)
	common.RWUserPool.Unlock()
	return &BlockChain_User{headerHash, db}
}

func (blockchain *BlockChain_User) AddUserToBlockchain() {
	common.RWUserPool.Lock()
	for i := 0; i < len(global.Users); i++ {
		key := global.Keys[i]
		priv := new(ecdsa.PrivateKey)
		priv.PublicKey.Curve = global.S256Curve
		priv.D = key
		priv.PublicKey.X, priv.PublicKey.Y = global.S256Curve.ScalarBaseMult(priv.D.Bytes())
		pub := global.GetFillBytes(priv.X, priv.Y)
		var previousUser []byte
		for j := 0; j < len(global.Users[i]); j++ {
			bts, err := hex.DecodeString(global.Users[i][j])
			global.MyError(err)
			infoUser := &common.InfoUser{nil, pub, nil, bts, []byte("train"), previousUser}
			infoUser.Sign(*priv)
			previousUser = infoUser.Hash
			common.InfoUserPool = append(common.InfoUserPool, infoUser)
		}
		MapRootUser[hex.EncodeToString(pub)] = previousUser
	}
	SetNewBodyUser()
	blockchain.AddBlockToBlockChain(uint64(time.Now().Unix()), NewBodyUser)
	//清空相关变量
	NewBodyUser = nil
	fmt.Println("用户链区块添加成功...,已处理数目：", global.InfoUserCount)
	common.RWUserPool.Unlock()
}

func (blockchain *BlockChain_User) AddBlockToBlockChain(timeStamp uint64, body *Block_Body_User) {
	err := blockchain.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			if global.BlockchainHeightUser == 0 {
				//	获取最新高度
				if len(blockchain.TipUser) == 0 {
					global.MyError(fmt.Errorf("TipUser为0"))
				}
				headerBytes := b.Get(blockchain.TipUser)
				if len(headerBytes) > 0 {
					prevHeader := DeserializeBlockHeader(headerBytes)
					global.BlockchainHeightUser = prevHeader.Height
				} else {
					global.MyError(fmt.Errorf("header为0"))
				}
			}
			newHeader := &Block_Header_User{
				global.BlockchainHeightUser + 1,
				blockchain.TipUser,
				body.Hash,
				timeStamp,
				nil,
				0,
			}
			newHeader.SetHeaderHash()
			//1、将区块头存储到表
			err := b.Put(newHeader.Hash, newHeader.SerializeBlockHeader())
			global.MyError(err)
			if !newHeader.VerifyHeaderHashUser() {
				fmt.Println("Header hash verify error!")
			}
			//2、将区块体存储到表
			err = b.Put(newHeader.BlockBodyHashUser, body.SerializeBlockBody())
			global.MyError(err)
			if !body.VerifyBodyHashUser() {
				fmt.Println("Body hash verify error!")
			}
			//保存用户信息
			for i := 0; i < len(common.InfoUserPool); i++ {
				infoUser := common.InfoUserPool[i]
				if !infoUser.VerifyInfoUserHash() {
					fmt.Println("UserInfoHash verify error!")
				} else {
					global.InfoUserCount++
				}
				infoUserBytes := infoUser.SerializeInfoUser()
				addressBytes := global.GetAddress(infoUser.Account)
				//将用户信息Hash-信息存储
				err = b.Put(infoUser.Hash, infoUserBytes)
				global.MyError(err)
				err = b.Put(addressBytes, infoUserBytes)
				global.MyError(err)
			}
			//更新授权该账户的根用户
			for k, v := range MapRootUser {
				bts, err := hex.DecodeString(k)
				global.MyError(err)
				err = b.Put(bts, v)
				global.MyError(err)
			}
			//6、清空全局变量
			common.InfoUserPool = []*common.InfoUser{}
			MapRootUser = make(map[string][]byte)
			err = b.Put([]byte(global.RecentBlockName_User), newHeader.Hash)
			//更新最新的全局区块链指针
			global.BlockChainTotal.TipHashUser = newHeader.Hash
			BlockchainUser.TipUser = newHeader.Hash
			global.MyError(err)
		}
		return nil
	})
	global.MyError(err)
}

func (blockchain *BlockChain_User) VerifyUserInfo(userInfo *common.InfoUser) bool {
	return userInfo.Verify()
}

func (blockchain *BlockChain_User) SignUserInfo(userInfo *common.InfoUser, privateKey ecdsa.PrivateKey) {
	userInfo.Sign(privateKey)
}

//查询某用户曾授权的所有用户
func QueryUserInfo(pubKey []byte) error {
	err := global.BlockChainTotal.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			prev := pubKey
			//获取用户地址
			addBts := b.Get(prev)
			if len(addBts) == 0 {
				fmt.Println("该用户暂未授权其他账户...")
				return nil
			}
			for bts := b.Get(addBts); len(bts) > 0; bts = b.Get(addBts) {
				infoUser := common.DeserializeInfoUser(bts)
				//打印用户信息
				infoUser.PrintInfoUser()
				//获取前一个用户指针
				addBts = infoUser.PreviousUser
			}
			fmt.Println("查询完毕！")
		}
		return nil
	})
	global.MyError(err)
	//返回一个字节数组，列车节点根hash
	return err
}
