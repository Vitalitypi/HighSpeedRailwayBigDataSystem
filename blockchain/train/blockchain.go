package train

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"github.com/bolt"
	"github.com/yonggewang/bdls/blockchain/common"
	"github.com/yonggewang/bdls/global"
	"log"
	"math/big"
)

//收到区块数据，进行本地数据库设置
func (blockchain *BlockChain_Train) SetBlockChainBytes(blockchainBytes *global.BlockChainTrainData) {
	headerBytesArr := blockchainBytes.HeaderBytes
	bodyBytesArr := blockchainBytes.BodyBytes
	TrainInfoBytesArr := blockchainBytes.TrainInfoBytes
	err := blockchain.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			for index1, headerBytes := range headerBytesArr {
				header := DeserializeBlockHeader(headerBytes)
				if index1 == 0 {
					//设置最新的hash
					err := b.Put([]byte(global.RecentBlockName_Train), header.Hash)
					global.MyError(err)
					//更新全局区块链指针的hash
					global.BlockChainTotal.TipHashTrain = header.Hash
					BlockchainTrain.TipTrain = header.Hash
				}
				if !header.VerifyTrainHeaderHash() {
					fmt.Println("Verify TrainHeader Hash error...")
				}
				err := b.Put(header.Hash, headerBytes)
				global.MyError(err)
				body := DeserializeBlockBody(bodyBytesArr[index1])
				if !body.VerifyTrainBodyHash() {
					fmt.Println("Verify TrainBodyHash error...")
				}
				err = b.Put(header.BlockBodyHashTrain, bodyBytesArr[index1])
				global.MyError(err)
				for index2, infoHash := range body.InfoHash {
					info := common.DeserializeInfoTrain(TrainInfoBytesArr[index1][index2])
					if !info.VerifyInfoTrainHash() {
						fmt.Println("Verify TrainInfoHash error...")
					}
					err = b.Put(infoHash, TrainInfoBytesArr[index1][index2])
					global.MyError(err)
				}
			}
		}
		return nil
	})
	global.MyError(err)
	//global.LabelTip.SetText(global.MyNode + "证书链区块同步完成!")
}
func (blockchain *BlockChain_Train) GetBlocksAboveHeight(height uint64) *global.BlockChainTrainData {
	var headerBytesArr [][]byte
	var bodyBytesArr [][]byte
	var TrainInfoBytesArr [][][]byte
	var currentHeight uint64
	var header *Block_Header_Train
	var body *Block_Body_Train
	err := blockchain.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			//获取hash字节数组
			hashBytes := b.Get([]byte(global.RecentBlockName_Train))
			headerBytes := b.Get(hashBytes)
			header = DeserializeBlockHeader(headerBytes)
			currentHeight = header.Height
			for currentHeight > height {
				headerBytesArr = append(headerBytesArr, headerBytes)
				bodyBytes := b.Get(header.BlockBodyHashTrain)
				bodyBytesArr = append(bodyBytesArr, bodyBytes)
				body = DeserializeBlockBody(bodyBytes)
				var TrainInfoBytes [][]byte
				for _, hash := range body.InfoHash {
					infoByes := b.Get(hash)
					TrainInfoBytes = append(TrainInfoBytes, infoByes)
				}
				TrainInfoBytesArr = append(TrainInfoBytesArr, TrainInfoBytes)
				//更新循环变量
				headerBytes = b.Get(header.PreviousHash)
				header = DeserializeBlockHeader(headerBytes)
				currentHeight = header.Height
			}
		}
		return nil
	})
	global.MyError(err)
	blocksBytes := &global.BlockChainTrainData{headerBytesArr, bodyBytesArr, TrainInfoBytesArr}
	return blocksBytes
}
func SetGenesisBlock(genesisBlockBytes [][]byte, infoBytes []byte) *BlockChain_Train {
	dbName := fmt.Sprintf(global.DBName, global.PortId)
	var headerHash []byte
	log.Print("Set Train BlockChain...")
	db, err := bolt.Open(dbName, 0600, nil)
	global.MyError(err)
	err = db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b == nil {
			b, err = tx.CreateBucket([]byte(global.TableName))
			global.MyError(err)
		}
		if b != nil {
			err = b.Put([]byte(global.GenesisBlockName_Train), genesisBlockBytes[0])
			genesisHeader := DeserializeBlockHeader(genesisBlockBytes[0])
			global.MyError(err)
			err = b.Put(genesisHeader.Hash, genesisBlockBytes[0])
			global.MyError(err)
			//将区块体存储到表
			err = b.Put(genesisHeader.BlockBodyHashTrain, genesisBlockBytes[1])
			global.MyError(err)
			//存储证书hash-证书信息
			info := common.DeserializeInfoTrain(infoBytes)
			err = b.Put(info.Hash, infoBytes)
			global.MyError(err)

			err = b.Put([]byte(global.RecentBlockName_Train), genesisHeader.Hash)
			global.MyError(err)
			headerHash = genesisHeader.Hash
		}
		return nil
	})
	fmt.Println("证书区块链已设置...")
	global.MyError(err)
	return &BlockChain_Train{headerHash, db}
}
func (blockchain *BlockChain_Train) GetGenesisBlock() ([]byte, []byte, []byte) {
	//返回区块头字节数组、区块体字节数组、证书信息字节数组
	var headerBytes, bodyBytes, infoBytes []byte
	err := blockchain.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			headerBytes = b.Get([]byte(global.GenesisBlockName_Train))
			header := DeserializeBlockHeader(headerBytes)
			bodyBytes = b.Get(header.BlockBodyHashTrain)
			body := DeserializeBlockBody(bodyBytes)
			fmt.Println("len of body's infoHash is ", len(body.InfoHash))
			infoBytes = b.Get(body.InfoHash[0])
		}
		return nil
	})
	global.MyError(err)
	return headerBytes, bodyBytes, infoBytes
}
func (blockchain *BlockChain_Train) GetTrainHashes() [][]byte {
	var hashes [][]byte
	iterator := blockchain.Iterator()
	for {
		header := iterator.Next()
		//添加区块头hash
		if header == nil {
			break
		}
		hashString := hex.EncodeToString(header.PreviousHash)
		fmt.Println("previous hash ", hashString)
		hashes = append(hashes, header.Hash)
		//添加区块体hash
		//hashes = append(hashes, header.BlockBodyHashTrain)
		var hashInt big.Int
		hashInt.SetBytes(header.PreviousHash)
		if hashInt.Cmp(big.NewInt(0)) == 0 {
			break
		}
	}
	return hashes
}

func (blockchain *BlockChain_Train) QueryNodeTrainRootHash(rootHash []byte) [][]byte {
	var infos [][]byte
	err := blockchain.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			for len(rootHash) != 0 {
				//获取证书节点字节
				nodeTrainBytes := b.Get(rootHash)
				fmt.Println("rootHash:\n", rootHash)
				nodeTrain := common.DeserializeNodeTrain(nodeTrainBytes)
				//获取证书信息字节
				for _, hash := range nodeTrain.TrainInfoHash {
					TrainInfoBytes := b.Get(hash)
					infos = append(infos, TrainInfoBytes)
				}
				nodeTrain.PrintNodeTrain()
				if len(nodeTrain.NextHash) != 0 {
					fmt.Println("next hash:", rootHash)
					rootHash = nodeTrain.NextHash
				} else if len(nodeTrain.PreviousHash) != 0 {
					rootHash = nodeTrain.PreviousHash
					fmt.Println("Previous hash:", rootHash)
				} else {
					rootHash = []byte{}
				}
			}
		}
		return nil
	})
	global.MyError(err)
	return infos
}
func (blockchain *BlockChain_Train) QueryTrain(bytes []byte) *common.InfoTrain {
	//bytes,err:=hex.DecodeString(hash)
	//global.MyError(err)
	var TrainInfo *common.InfoTrain
	err := blockchain.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			//获取指定hash的区块
			TrainInfoBytes := b.Get(bytes)
			TrainInfo = common.DeserializeInfoTrain(TrainInfoBytes)
		}
		return nil
	})
	global.MyError(err)
	return TrainInfo
}
func (blockchain *BlockChain_Train) PrintBlockChain_Train() {
	var header *Block_Header_Train
	var body *Block_Body_Train
	var currentHash = blockchain.TipTrain
	for {
		err := blockchain.DB.View(func(tx *bolt.Tx) error {
			b := tx.Bucket([]byte(global.TableName))
			if b != nil {
				//获取当前区块
				blockBytes := b.Get(currentHash)
				header = DeserializeBlockHeader(blockBytes)
				bodyBytes := b.Get(header.BlockBodyHashTrain)
				body = DeserializeBlockBody(bodyBytes)
				header.PrintTrainHeader()
				fmt.Println("===========\n开始打印证书区块体")
				for _, info := range body.InfoHash {
					infoBytes := b.Get(info)
					TrainInfo := common.DeserializeInfoTrain(infoBytes)
					TrainInfo.PrintInfoTrain()
				}
				fmt.Println("证书区块体打印完毕\n===========")
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
func (blockchain *BlockChain_Train) GetBlock(hash []byte) ([]byte, error) {
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
	blockchain := BlockChain_Train{global.BlockChainTotal.TipHashTrain, global.BlockChainTotal.DB}
	blockchain.AddBlockToBlockChain(NewHeaderTrain, NewBodyTrain)
	//清空相关变量
	NewHeaderTrain = nil
	NewBodyTrain = nil
	fmt.Println("证书链区块添加成功...")
}

func (blockchain *BlockChain_Train) GetHeight() uint64 {
	var header *Block_Header_Train
	err := blockchain.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			blockchain.TipTrain = b.Get([]byte(global.RecentBlockName_Train))
			headerBytes := b.Get(blockchain.TipTrain)
			header = DeserializeBlockHeader(headerBytes)
			//更新全局区块链指针的hash
			global.BlockChainTotal.TipHashTrain = header.Hash
			BlockchainTrain.TipTrain = header.Hash
		}
		return nil
	})
	global.MyError(err)
	return header.Height
}
func (blockchain *BlockChain_Train) GetLowHeight() uint64 {
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
		//hashes = append(hashes, header.BlockBodyHashTrain)
		var hashInt big.Int
		hashInt.SetBytes(header.PreviousHash)
		if hashInt.Cmp(big.NewInt(0)) == 0 {
			break
		}
	}
	return height
}

func CreateBlockChain_Train() *BlockChain_Train {
	dbName := fmt.Sprintf(global.DBName, global.PortId)
	var headerHash []byte
	log.Print("Create Train BlockChain...")
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
			//将区块头存储到表中
			headerBytes := genesisHeader.SerializeBlockHeader()
			err = b.Put([]byte(global.GenesisBlockName_Train), headerBytes)
			global.MyError(err)
			err = b.Put(genesisHeader.Hash, headerBytes)
			global.MyError(err)
			//将区块体存储到表
			err = b.Put(genesisHeader.BlockBodyHashTrain, genesisBody.SerializeBlockBody())
			global.MyError(err)
			//string(证书Hash)与证书信息的映射
			//fmt.Println(Map_InfoTrain)
			for _, v := range common.Map_InfoTrain {
				err = b.Put(v.Hash, v.SerializeInfoTrain())
				global.MyError(err)
			}
			//清空全局变量
			common.Map_InfoTrain = make(map[string]*common.InfoTrain)
			//global_TrainInfos=[]*TrainInfo{}
			err = b.Put([]byte(global.RecentBlockName_Train), genesisHeader.Hash)
			global.MyError(err)
			headerHash = genesisHeader.Hash
		}
		return nil
	})
	fmt.Println("证书区块链已创建...")
	global.MyError(err)
	return &BlockChain_Train{headerHash, db}
}

func GetBlockChain(nodeId string) *BlockChain_Train {
	dbName := fmt.Sprintf(global.DBName, nodeId)
	var tipHash []byte
	log.Print("open database...")
	db, err := bolt.Open(dbName, 0600, nil)
	global.MyError(err)
	err = db.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			tipHash = b.Get([]byte(global.RecentBlockName_Train))
		}
		return nil
	})
	global.MyError(err)
	return &BlockChain_Train{tipHash, db}
}
func (blockchain *BlockChain_Train) AddBlockToBlockChain(header *Block_Header_Train, body *Block_Body_Train) {
	err := blockchain.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			//1、将区块头存储到表
			err := b.Put(header.Hash, header.SerializeBlockHeader())
			global.MyError(err)
			if !header.VerifyTrainHeaderHash() {
				fmt.Println("Header hash Verify error!")
			}
			//2、将区块体存储到表
			err = b.Put(header.BlockBodyHashTrain, body.SerializeBlockBody())
			global.MyError(err)
			if !body.VerifyTrainBodyHash() {
				fmt.Println("Body hash Verify error!")
			}

			var nodeUser, newNodeUser *common.NodeUser
			var nodeTrain *common.NodeTrain
			//fmt.Println("NewBodyTrain",NewBodyTrain)
			TrainInfo := common.Map_InfoTrain[hex.EncodeToString(NewBodyTrain.InfoHash[0])]
			addressBytes := global.GetAddress(TrainInfo.PublicKey)
			addressString := hex.EncodeToString(addressBytes)
			if common.Map_NodeUser[addressString] == nil {
				//从区块链中获取
				nodeUserBytes := b.Get(TrainInfo.PublicKey)
				nodeUser = common.DeserializeNodeUser(nodeUserBytes)
				nodeTrain = common.NewNodeTrain(NewBodyTrain.InfoHash, nodeUser.NodeTrainRootHash, []byte{})
			} else {
				//从全局变量获取
				nodeUser = common.Map_NodeUser[addressString]
				nodeTrain = common.NewNodeTrain(NewBodyTrain.InfoHash, []byte{}, nodeUser.NodeTrainRootHash)
			}
			//nodeTrain.PrintNodeTrain()
			newNodeUser = common.NewNodeUser(TrainInfo.PublicKey, []byte{}, nodeTrain.Hash)
			common.Map_NodeUser[addressString] = newNodeUser
			err = b.Put(nodeTrain.Hash, nodeTrain.SerializeNodeTrain())
			global.MyError(err)
			if !nodeTrain.VerifyNodeTrainHash() {
				fmt.Println("NodeTrain Hash error!")
			}

			for _, v := range common.Map_InfoTrain {
				err = b.Put(v.Hash, v.SerializeInfoTrain())
				global.MyError(err)
				if !v.VerifyInfoTrainHash() {
					fmt.Println("TrainInfoHash verify error!")
				}
			}
			////清空全局变量：证书信息
			//common.Map_InfoTrain =make(map[string]*common.InfoTrain)
			//更新最近的区块hash
			err = b.Put([]byte(global.RecentBlockName_Train), header.Hash)
			//更新全局区块链指针的hash
			global.BlockChainTotal.TipHashTrain = header.Hash
			BlockchainTrain.TipTrain = header.Hash
			global.MyError(err)
		}
		return nil
	})
	global.MyError(err)
	fmt.Println("证书数据已写入区块链...")
}
func (blockchain *BlockChain_Train) VerifyTrainInfo(info *common.InfoTrain) bool {
	return info.Verify()
}
func (blockchain *BlockChain_Train) SignTrainInfo(info *common.InfoTrain, privateKey ecdsa.PrivateKey) {
	info.Sign(privateKey)
}
