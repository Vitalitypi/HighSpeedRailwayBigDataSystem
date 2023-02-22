package user

import (
	"bytes"
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/bolt"
	"github.com/yonggewang/bdls/blockchain/common"
	"github.com/yonggewang/bdls/global"
	"log"
	"math/big"
)

func (blockchain *BlockChain_User) SetBlockChainBytes(blockchainBytes *global.BlockChainUserData) {
	headerBytesArr := blockchainBytes.HeaderBytes
	bodyBytesArr := blockchainBytes.BodyBytes
	nodeUserBytesArr := blockchainBytes.NodeUserBytes
	nodeTrainBytesArr := blockchainBytes.NodeTrainBytes
	userInfoBytesArr := blockchainBytes.UserInfoBytes
	indexUserInfo := 0
	map_pubKeyNodeUser := make(map[string]int)
	err := blockchain.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			for index1, headerBytes := range headerBytesArr {
				header := DeserializeBlockHeader(headerBytes)
				if index1 == 0 {
					//设置hash
					err := b.Put([]byte(global.RecentBlockName_User), header.Hash)
					global.MyError(err)
					common.BlockChainTotal.TipHashUser = header.Hash
					BlockchainUser.TipUser = header.Hash
				}
				if !header.VerifyHeaderHashUser() {
					fmt.Println("Verify UserBlockHeaderHash error...")
				}
				err := b.Put(header.Hash, headerBytes)
				global.MyError(err)

				body := DeserializeBlockBody(bodyBytesArr[index1])
				if !body.VerifyBodyHashUser() {
					fmt.Println("Verify UserBodyHash error...")
				}
				err = b.Put(header.BlockBodyHashUser, bodyBytesArr[index1])
				global.MyError(err)
				for _, nodeUserBytes := range nodeUserBytesArr[index1] {
					nodeUser := common.DeserializeNodeUser(nodeUserBytes)
					if !nodeUser.VerifyNodeUserHash() {
						fmt.Println("Verify NodeUserHash error...")
					}
					err = b.Put(nodeUser.Hash, nodeUserBytes)
					global.MyError(err)
					if map_pubKeyNodeUser[hex.EncodeToString(nodeUser.PubKey)] == 0 {
						err = b.Put(nodeUser.PubKey, nodeUserBytes)
						global.MyError(err)
						map_pubKeyNodeUser[hex.EncodeToString(nodeUser.PubKey)] = 1
					}
					if len(nodeUser.UserInfoHash) != 0 {
						//存储用户信息
						userInfo := common.DeserializeInfoUser(userInfoBytesArr[indexUserInfo])
						if !userInfo.VerifyInfoUserHash() {
							fmt.Println("Verify UserInfoHash error...")
						}
						err = b.Put(nodeUser.UserInfoHash, userInfoBytesArr[indexUserInfo])
						global.MyError(err)
						err = b.Put(global.GetAddress(nodeUser.PubKey), userInfoBytesArr[indexUserInfo])
						global.MyError(err)
						indexUserInfo += 1
					}
				}
				for _, nodeTrainBytes := range nodeTrainBytesArr[index1] {
					nodeTrain := common.DeserializeNodeTrain(nodeTrainBytes)
					if nodeTrain == nil {
						break
					}
					if !nodeTrain.VerifyNodeTrainHash() {
						fmt.Println("Verify NodeTrain error...")
					}
					err = b.Put(nodeTrain.Hash, nodeTrainBytes)
					global.MyError(err)
				}
			}
		}
		return nil
	})
	map_pubKeyNodeUser = make(map[string]int)
	global.MyError(err)
	//global.LabelTip.SetText(global.MyNode + "用户链区块同步完成!")
}

func (blockchain *BlockChain_User) GetBlocksAboveHeight(height uint64) *global.BlockChainUserData {
	var headerBytesArr [][]byte //保存所有区块头的字节
	var bodyBytesArr [][]byte
	var nodeUserBytesArr [][][]byte
	var userInfoBytesArr [][]byte
	var nodeTrainBytesArr [][][]byte
	var currentHeight uint64
	var headerBytes []byte
	var header *Block_Header_User
	var nodeUser *common.NodeUser
	err := blockchain.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			//获取hash字节
			hashBytes := b.Get([]byte(global.RecentBlockName_User))
			headerBytes = b.Get(hashBytes)
			header = DeserializeBlockHeader(headerBytes)
			currentHeight = header.Height
			//当前区块大于目标高度
			for currentHeight > height {
				//将区块头字节数组添加
				headerBytesArr = append(headerBytesArr, headerBytes)
				//获取区块体字节
				bodyBytes := b.Get(header.BlockBodyHashUser)
				bodyBytesArr = append(bodyBytesArr, bodyBytes)
				body := DeserializeBlockBody(bodyBytes)
				//获取所有的用户节点字节
				var nodeUserBytes [][]byte
				var nodeTrainBytes [][]byte
				for _, hash := range body.NodeHashUsers {
					nodeUserByte := b.Get(hash)
					nodeUserBytes = append(nodeUserBytes, nodeUserByte)
					nodeUser = common.DeserializeNodeUser(nodeUserByte)
					if len(nodeUser.UserInfoHash) != 0 {
						userInfoBytes := b.Get(nodeUser.UserInfoHash)
						userInfoBytesArr = append(userInfoBytesArr, userInfoBytes)
					}
					if len(nodeUser.NodeTrainRootHash) != 0 {
						//获取列车节点
						nodeTrainByte := b.Get(nodeUser.NodeTrainRootHash)
						nodeTrainBytes = append(nodeTrainBytes, nodeTrainByte)
						nodeTrain := common.DeserializeNodeTrain(nodeTrainByte)
						nodeTrainHash := nodeTrain.NextHash
						for len(nodeTrainHash) != 0 {
							nodeTrainByte = b.Get(nodeTrainHash)
							nodeTrainBytes = append(nodeTrainBytes, nodeTrainByte)
							nodeTrain = common.DeserializeNodeTrain(nodeTrainByte)
							if nodeTrain == nil {
								break
							}
							nodeTrainHash = nodeTrain.NextHash
						}
					}
				}
				nodeTrainBytesArr = append(nodeTrainBytesArr, nodeTrainBytes)
				nodeUserBytesArr = append(nodeUserBytesArr, nodeUserBytes)
				//更新区块高度
				headerBytes = b.Get(header.PreviousHash)
				header = DeserializeBlockHeader(headerBytes)
				currentHeight = header.Height
			}
		}
		return nil
	})
	global.MyError(err)
	blocksBytes := &global.BlockChainUserData{headerBytesArr, bodyBytesArr, nodeUserBytesArr, nodeTrainBytesArr, userInfoBytesArr}
	return blocksBytes
}
func SetGenesisBlock(genesisBlockBytes [][]byte, nodeUserBytes []byte, userInfoBytes []byte) *BlockChain_User {
	dbName := fmt.Sprintf(global.DBName, global.PortId)
	var headerHash []byte
	log.Print("Set User BlockChain...")
	db, err := bolt.Open(dbName, 0600, nil)
	global.MyError(err)
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b == nil {
			b, err = tx.CreateBucket([]byte(global.TableName))
			global.MyError(err)
		}
		if b != nil {
			err = b.Put([]byte(global.GenesisBlockName_User), genesisBlockBytes[0])
			global.MyError(err)
			genesisHeader := DeserializeBlockHeader(genesisBlockBytes[0])
			err = b.Put(genesisHeader.Hash, genesisBlockBytes[0])
			global.MyError(err)
			//将创世区块体存储到表中
			err = b.Put(genesisHeader.BlockBodyHashUser, genesisBlockBytes[1])
			global.MyError(err)
			//设置公钥-用户节点
			nodeUser := common.DeserializeNodeUser(nodeUserBytes)
			err = b.Put(nodeUser.PubKey, nodeUserBytes)
			global.MyError(err)
			//存储用户信息hash-用户信息
			err = b.Put(nodeUser.UserInfoHash, userInfoBytes)
			global.MyError(err)
			//存储用户节点hash-用户节点
			err = b.Put(nodeUser.Hash, nodeUserBytes)
			global.MyError(err)
			//获取地址
			addressBytes := global.GetAddress(nodeUser.PubKey)
			//存储地址-用户信息
			err = b.Put(addressBytes, userInfoBytes)
			global.MyError(err)
			err = b.Put([]byte(global.RecentBlockName_User), genesisHeader.Hash)
			global.MyError(err)
			headerHash = genesisHeader.Hash
		}
		return nil
	})
	fmt.Println("用户区块链已设置...")
	global.MyError(err)
	return &BlockChain_User{headerHash, db}
}

//返回一个二维字节数组，依次为区块头字节数组，区块体，用户节点，用户信息
func (blockchain *BlockChain_User) GetGenesisBlock() [][]byte {
	var genesisBlockBytes [][]byte
	err := blockchain.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			headerBytes := b.Get([]byte(global.GenesisBlockName_User))
			//headerBytes:=b.Get([]byte("genesisBlockUser"))
			genesisBlockBytes = append(genesisBlockBytes, headerBytes)
			header := DeserializeBlockHeader(headerBytes)
			bodyBytes := b.Get(header.BlockBodyHashUser)
			genesisBlockBytes = append(genesisBlockBytes, bodyBytes)
			body := DeserializeBlockBody(bodyBytes)
			nodeBytes := b.Get(body.NodeHashUsers[0])
			genesisBlockBytes = append(genesisBlockBytes, nodeBytes)
			node := common.DeserializeNodeUser(nodeBytes)
			userInfoBytes := b.Get(node.UserInfoHash)
			genesisBlockBytes = append(genesisBlockBytes, userInfoBytes)
		}
		return nil
	})
	global.MyError(err)
	return genesisBlockBytes
}
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
				//body.VerifyUserBlockBodyHash()
				hashNodeUser := body.NodeHashUsers
				for _, hash := range hashNodeUser {
					nodeBytes := b.Get(hash)
					node := common.DeserializeNodeUser(nodeBytes)
					node.PrintNodeUser()
					userInfoBytes := b.Get(node.UserInfoHash)
					userInfo := common.DeserializeInfoUser(userInfoBytes)
					userInfo.PrintInfoUser()
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

func (blockchain *BlockChain_User) QueryUser(pubKey []byte) ([]byte, []byte, string) {
	var rootHash []byte
	var userInfoBytes []byte
	var result string
	err := blockchain.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			nodeUserBytes := b.Get(pubKey)
			if len(nodeUserBytes) == 0 {
				result = "error"
				return nil
			}
			result = "ok"
			nodeUser := common.DeserializeNodeUser(nodeUserBytes)
			//fmt.Println("nodeUser_UserInfoHash:",nodeUser.UserInfoHash)
			//根据用户地址来获取
			addressBytes := global.GetAddress(pubKey)
			userInfoBytes = b.Get(addressBytes)
			if len(userInfoBytes) == 0 {
				//未获取到信息
				userInfoBytes = b.Get(nodeUser.UserInfoHash)
			}
			rootHash = nodeUser.NodeTrainRootHash //获取列车节点根hash
		}
		return nil
	})
	global.MyError(err)
	//返回一个字节数组，列车节点根hash
	return rootHash, userInfoBytes, result
}
func (blockchain *BlockChain_User) UiLoginVerify(pubKey []byte, priKey ecdsa.PrivateKey) string {
	ans := ""
	adminPubKey, err := hex.DecodeString("73ccd17cdc6275381f365f14e24ccae8e95a216d399889ff793a7a59e134795ce7270a9009b11b250235d314499f2258d9c8952a298bc2d5b09ae80c821f676d")
	global.MyError(err)
	publicBytes := append(priKey.PublicKey.X.Bytes(), priKey.Y.Bytes()...)
	if bytes.Compare(publicBytes, pubKey) != 0 {
		return ans
	}
	if bytes.Compare(adminPubKey, pubKey) == 0 {
		return "admin"
	}
	err = blockchain.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			//通过公钥字节数组获取用户节点
			bytes := b.Get(pubKey)
			if len(bytes) != 0 {
				ans = "user"
			}
		}
		return nil
	})
	global.MyError(err)
	return ans
}

func (blockchain *BlockChain_User) GetBlock(hash []byte) ([]byte, error) {
	var headerBytes []byte
	err := blockchain.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			headerBytes = b.Get(hash)
		}
		return nil
	})
	return headerBytes, err
}
func AddBlock() {
	blockchain := BlockChain_User{common.BlockChainTotal.TipHashUser, common.BlockChainTotal.DB}
	blockchain.AddBlockToBlockChain(NewHeaderUser, NewBodyUser)
	//清空相关变量
	NewHeaderUser = nil
	NewBodyUser = nil
	fmt.Println("用户链添加成功！")
}

//获取区块高度
func (blockchain *BlockChain_User) GetHeight() uint64 {
	var header *Block_Header_User
	err := blockchain.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			blockchain.TipUser = b.Get([]byte(global.RecentBlockName_User))
			headerBytes := b.Get(blockchain.TipUser)
			header = DeserializeBlockHeader(headerBytes)
			//更新全局区块链指针的hash
			common.BlockChainTotal.TipHashUser = header.Hash
			BlockchainUser.TipUser = header.Hash
		}
		return nil
	})
	global.MyError(err)
	return header.Height
}
func (blockchain *BlockChain_User) GetLowHeight() uint64 {
	iterator := blockchain.Iterator()
	var height uint64
	for {
		header := iterator.Next()
		//添加区块头hash
		if header == nil {
			break
		}
		height = header.Height
		//添加区块体hash
		//hashes = append(hashes, header.TrainBlockBodyHash)
		var hashInt big.Int
		hashInt.SetBytes(header.PreviousHash)
		if hashInt.Cmp(big.NewInt(0)) == 0 {
			break
		}
	}
	return height
}
func CreateBlockChainUser() *BlockChain_User {
	dbName := fmt.Sprintf(global.DBName, global.PortId)
	var headerHash []byte
	log.Print("Create User BlockChain...")
	db, err := bolt.Open(dbName, 0600, nil)
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
			//string(公钥)与用户节点映射
			for k, v := range common.Map_NodeUser {
				nodeUserBytes := v.SerializeNodeUser()
				userInfoBytes := common.Map_UserInfo[k].SerializeInfoUser()
				addressBytes := global.GetAddress(v.PubKey)
				//3、将公钥与用户节点字节存储到表
				err = b.Put(v.PubKey, nodeUserBytes)
				global.MyError(err)
				//4、将用户信息hash与用户信息字节存储到表
				err = b.Put(v.UserInfoHash, userInfoBytes)
				global.MyError(err)
				//5、将用户节点hash与用户节点字节存储到表
				err = b.Put(v.Hash, nodeUserBytes)
				global.MyError(err)
				//6、将地址与用户信息存储到表
				err = b.Put(addressBytes, userInfoBytes)
			}
			//6、清空全局变量
			common.Map_UserInfo = make(map[string]*common.InfoUser)
			common.Map_NodeUser = make(map[string]*common.NodeUser)
			err = b.Put([]byte(global.RecentBlockName_User), genesisHeader.Hash)
			global.MyError(err)
			headerHash = genesisHeader.Hash
		}
		return nil
	})
	fmt.Println("用户区块链已创建...")
	global.MyError(err)
	return &BlockChain_User{headerHash, db}
}

func GetBlockChain(nodeId string) *BlockChain_User {
	dbName := fmt.Sprintf(global.DBName, nodeId)
	var tipHash []byte
	log.Print("open database...")
	db, err := bolt.Open(dbName, 0600, nil)
	global.MyError(err)
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			tipHash = b.Get([]byte(global.RecentBlockName_User))
		}
		return nil
	})
	global.MyError(err)
	return &BlockChain_User{tipHash, db}
}

func (blockchain *BlockChain_User) AddBlockToBlockChain(header *Block_Header_User, body *Block_Body_User) {
	err := blockchain.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			//1、将区块头存储到表
			err := b.Put(header.Hash, header.SerializeBlockHeader())
			global.MyError(err)
			if !header.VerifyHeaderHashUser() {
				fmt.Println("Header hash verify error!")
			}
			//2、将区块体存储到表
			err = b.Put(header.BlockBodyHashUser, body.SerializeBlockBody())
			global.MyError(err)
			if !body.VerifyBodyHashUser() {
				fmt.Println("Body hash verify error!")
			}
			var bytes []byte
			//保存用户信息

			for k, v := range common.Map_UserInfo {
				userInfoBytes := v.SerializeInfoUser()
				//4、将用户信息hash与用户信息字节存储到表
				err = b.Put(v.Hash, userInfoBytes)
				global.MyError(err)
				if !v.VerifyInfoUserHash() {
					fmt.Println("UserInfoHash verify error!")
				}
				//将用户信息地址-信息存储
				addressBytes, err := hex.DecodeString(k)
				global.MyError(err)
				//fmt.Printf("addressBytes:%x\n",addressBytes)
				//fmt.Printf("userInfoBytes:%x\n",userInfoBytes)
				err = b.Put(addressBytes, userInfoBytes)
				global.MyError(err)
			}
			//保存用户节点
			for _, v := range common.Map_NodeUser {
				bytes = v.SerializeNodeUser()
				//3、将公钥与用户节点字节存储到表
				err = b.Put(v.PubKey, bytes)
				global.MyError(err)
				if !v.VerifyNodeUserHash() {
					fmt.Println("NodeUser Hash error!")
				}
				//5、将用户节点hash与用户节点字节存储到表
				//fmt.Println(v.Hash,bytes)
				err = b.Put(v.Hash, bytes)
				global.MyError(err)
			}
			////6、清空全局变量
			//common.Map_UserInfo =make(map[string]*common.InfoUser)
			//common.Map_NodeUser =make(map[string]*common.NodeUser)
			err = b.Put([]byte(global.RecentBlockName_User), header.Hash)
			//更新最新的全局区块链指针
			common.BlockChainTotal.TipHashUser = header.Hash
			BlockchainUser.TipUser = header.Hash
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
