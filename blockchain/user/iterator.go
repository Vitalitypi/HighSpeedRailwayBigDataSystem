package user

import (
	"github.com/bolt"
	"github.com/yonggewang/bdls/global"
)

func (blockchain *BlockChain_User) Iterator() *BlockChainIteratorUser {
	return &BlockChainIteratorUser{blockchain.TipUser, blockchain.DB}
}
func (blockchainIterator *BlockChainIteratorUser) Next() *Block_Header_User {
	var header *Block_Header_User
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
