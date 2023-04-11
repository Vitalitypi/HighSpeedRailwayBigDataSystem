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
				fmt.Println("===========\n开始打印列车区块体")
				for _, info := range body.InfoHashes {
					infoBytes := b.Get(info)
					TrainInfo := common.DeserializeInfoTrain(infoBytes)
					TrainInfo.PrintInfoTrain()
				}
				fmt.Println("列车区块体打印完毕\n===========")
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

func AddBlock(timeStamp uint64) {
	common.RWTrainPool.Lock()
	SetNewBodyTrain()
	blockchain := BlockChain_Train{global.BlockChainTotal.TipHashTrain, global.BlockChainTotal.DB}
	blockchain.AddBlockToBlockChain(timeStamp, NewBodyTrain)
	//清空相关变量
	//NewHeaderTrain = nil
	NewBodyTrain = nil
	common.RWTrainPool.Unlock()
	global.ChBlockchainTrain <- struct{}{}
	fmt.Println("列车链区块添加成功...,已处理数目：", global.InfoTrainCount)
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

func CreateBlockChainTrain() *BlockChain_Train {
	//dbName := fmt.Sprintf(global.DBName, global.PortId)
	var headerHash []byte
	log.Print("Create Train BlockChain...")
	common.RWTrainPool.Lock()
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
			//将区块头存储到表中
			headerBytes := genesisHeader.SerializeBlockHeader()
			err = b.Put([]byte(global.GenesisBlockName_Train), headerBytes)
			global.MyError(err)
			err = b.Put(genesisHeader.Hash, headerBytes)
			global.MyError(err)
			//将区块体存储到表
			err = b.Put(genesisHeader.BlockBodyHashTrain, genesisBody.SerializeBlockBody())
			global.MyError(err)
			//string(列车Hash)与列车信息的映射
			//fmt.Println(Map_InfoTrain)
			for _, v := range common.InfoTrainPool {
				err = b.Put(v.Hash, v.SerializeInfoTrain())
				global.MyError(err)
			}
			//清空全局变量
			common.InfoTrainPool = []*common.InfoTrain{}
			//global_TrainInfos=[]*TrainInfo{}
			err = b.Put([]byte(global.RecentBlockName_Train), genesisHeader.Hash)
			global.MyError(err)
			headerHash = genesisHeader.Hash
		}
		return nil
	})
	fmt.Println("列车区块链已创建...")
	global.MyError(err)
	common.RWTrainPool.Unlock()
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
func (blockchain *BlockChain_Train) AddBlockToBlockChain(timeStamp uint64, body *Block_Body_Train) {
	err := blockchain.DB.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			if global.BlockchainHeightTrain == 0 {
				//获取最新高度
				headerBytes := b.Get(blockchain.TipTrain)
				if len(headerBytes) > 0 {
					prevHeader := DeserializeBlockHeader(headerBytes)
					global.BlockchainHeightTrain = prevHeader.Height
				} else {
					global.MyError(fmt.Errorf("header为0"))
				}
			}
			newHeader := &Block_Header_Train{
				global.BlockchainHeightTrain + 1,
				blockchain.TipTrain,
				body.Hash,
				timeStamp,
				nil,
				0,
			}
			newHeader.SetHeaderHash()
			//1、将区块头存储到表
			err := b.Put(newHeader.Hash, newHeader.SerializeBlockHeader())
			global.MyError(err)
			if !newHeader.VerifyTrainHeaderHash() {
				fmt.Println("Header hash Verify error!")
			}
			//2、将区块体存储到表
			err = b.Put(newHeader.BlockBodyHashTrain, body.SerializeBlockBody())
			global.MyError(err)
			if !body.VerifyTrainBodyHash() {
				fmt.Println("Body hash Verify error!")
			}
			for _, v := range common.InfoTrainPool {
				err = b.Put(v.Hash, v.SerializeInfoTrain())
				global.MyError(err)
				if !v.VerifyInfoTrainHash() {
					fmt.Println("TrainInfoHash verify error!")
				}
				global.InfoTrainCount++
			}
			//更新发布该信息的根用户
			for k, v := range MapOtherTrain {
				bts, err := hex.DecodeString(k)
				global.MyError(err)
				err = b.Put(bts, v)
				global.MyError(err)
			}
			////清空全局变量：列车信息
			common.InfoTrainPool = []*common.InfoTrain{}
			MapOtherTrain = make(map[string][]byte)
			//更新最近的区块hash
			err = b.Put([]byte(global.RecentBlockName_Train), newHeader.Hash)
			//更新全局区块链指针的hash
			global.BlockChainTotal.TipHashTrain = newHeader.Hash
			global.BlockchainHeightTrain++
			BlockchainTrain.TipTrain = newHeader.Hash
			global.MyError(err)
		}
		return nil
	})
	global.MyError(err)

	//fmt.Println("列车数据已写入区块链...")
}
func (blockchain *BlockChain_Train) VerifyTrainInfo(info *common.InfoTrain) bool {
	return info.Verify()
}
func (blockchain *BlockChain_Train) SignTrainInfo(info *common.InfoTrain, privateKey ecdsa.PrivateKey) {
	info.Sign(privateKey)
}
func QueryTrainInfo(pubKey []byte) error {
	err := global.BlockChainTotal.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			//获取列车信息Hash
			prev := b.Get(pubKey)
			if len(prev) == 0 {
				fmt.Println("该用户暂未发布列车信息...")
				return nil
			}
			for bts := b.Get(prev); len(bts) > 0; bts = b.Get(prev) {
				//获取列车信息
				infoTrain := common.DeserializeInfoTrain(bts)
				infoTrain.PrintInfoTrain()
				prev = infoTrain.PreviousTrain
				if len(prev) != 0 {
					break
				}
			}
			fmt.Println("查询完毕！")
		}
		return nil
	})
	global.MyError(err)
	//返回一个字节数组，列车节点根hash
	return err
}
