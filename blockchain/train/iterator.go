package train

import (
	"github.com/bolt"
	"github.com/yonggewang/bdls/global"
)

func (blockchain *BlockChain_Train) Iterator() *BlockChainIteratorTrain {
	return &BlockChainIteratorTrain{blockchain.TipTrain, blockchain.DB}
}

func (blockchainIterator *BlockChainIteratorTrain) Next() *Block_Header_Train {
	var header *Block_Header_Train
	err := blockchainIterator.DB.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte(global.TableName))
		if b != nil {
			currentBlockBytes := b.Get(blockchainIterator.CurrentHash)
			//获取当前迭代器的区块
			if len(currentBlockBytes) == 0 {
				return nil
			}
			header = DeserializeBlockHeader(currentBlockBytes)
			//更新迭代器内的信息
			blockchainIterator.CurrentHash = header.PreviousHash
		}
		return nil
	})
	global.MyError(err)
	return header
}
