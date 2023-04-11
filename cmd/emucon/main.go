package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/skip2/go-qrcode"
	"github.com/yonggewang/bdls/blockchain/train"
	"github.com/yonggewang/bdls/blockchain/user"
	"github.com/yonggewang/bdls/global"
	"log"
	"math/big"
	"os"
	"strconv"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/yonggewang/bdls"
	"github.com/yonggewang/bdls/agent-tcp"
	"github.com/yonggewang/bdls/crypto/blake2b"
)

// A quorum set for consenus
type Quorum struct {
	Keys    []*big.Int `json:"keys"` // pem formatted keys,
	Account []string   `json:"account"`
}

//当前节点的ID
var Id int
var NumAccount int

//4、8、16、24、32（12、20）
//5+strconv.Itoa(Id)=同层通信端口
//4+strconv.Itoa(Id)=其他通信端口

//生成创世区块
func genesisBlock() {
	//创建区块链
	chainUser := user.CreateBlockChainUser()
	user.BlockchainUser = chainUser
	global.BlockChainTotal = &global.BlockChain{}
	global.BlockChainTotal.DB = chainUser.DB
	//将用户信息加入区块链
	chainUser.AddUserToBlockchain()
	chainUser.DB.Close()
	chainTrain := train.CreateBlockChainTrain()
	chainTrain.DB.Close()
	ConfigSystem()
}
func CreateConfig() {
	config := &global.Config{}
	group := [][]string{}
	for i := 0; i < len(global.Admin); i++ {
		//生成一级共识成员
		group = append(group, []string{global.Admin[i], strconv.Itoa(global.BasePort + i*1000)})
	}
	config.Group = group
	file, err := os.Create(global.ConfigPath + "config_genesis.json")
	global.MyError(err)
	enc := json.NewEncoder(file)
	enc.SetIndent("", "\t")
	err = enc.Encode(config)
	global.MyError(err)
	file.Close()
}
func createQuorum(quorum *Quorum, config string) {
	file, err := os.Create(config)
	if err != nil {
		return
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "\t")
	err = enc.Encode(quorum)
	if err != nil {
		return
	}
	file.Close()
}

func ConfigSystem() {
	createConfigs()
	CreateConfig()
	//	打开总账户配置文件
	file, err := os.Open(global.ConfigPath + "accounts.json")
	global.MyError(err)
	defer file.Close()
	accounts := new(global.AccountConfig)
	err = json.NewDecoder(file).Decode(accounts)
	global.MyError(err)
	admins := [][]string{}
	for i := 0; i < len(accounts.Accounts); i++ {
		currentAccount := accounts.Accounts[i]
		admins = append(admins, currentAccount.Admin[0])
		global.CreateConfigUsers(currentAccount)
	}
	for i := 0; i < len(admins); i++ {
		global.CreateConfigAdmin(accounts.Accounts[i], admins)
	}
}
func createConfigs() {
	quorums := &global.Quorums{}
	quorums.Keys = make(map[string]*big.Int)
	for i := 0; i < global.NumGroup; i++ {
		port := global.BasePort + i*1000
		quorums.Keys[strconv.Itoa(port)] = global.Keys[i]
		qrcode.WriteFile(global.Keys[i].String()+"|"+strconv.Itoa(port), qrcode.Medium, 256, global.QrCodePath+strconv.Itoa(port)+".png")
		for j := 0; j < len(global.UserKeys[i]); j++ {
			port = port + 50
			quorums.Keys[strconv.Itoa(port)] = global.UserKeys[i][j]
			qrcode.WriteFile(global.UserKeys[i][j].String()+"|"+strconv.Itoa(port), qrcode.Medium, 256, global.QrCodePath+strconv.Itoa(port)+".png")
		}
	}
	//获取当前端口的秘钥
	file, err := os.Create(global.ConfigPath + "configs.json")
	if err != nil {
		return
	}
	enc := json.NewEncoder(file)
	enc.SetIndent("", "\t")
	err = enc.Encode(quorums)
	if err != nil {
		return
	}
	file.Close()
}

//将用户分为四组
func createAccounts(addresses []string) {
	accounts := &global.AccountConfig{}
	base := global.BasePort
	for i := 0; i < 4; i++ {
		accounts.Accounts = append(accounts.Accounts, &global.Account{})
	}
	var account *global.Account
	for i := 0; i < NumAccount; i++ {
		index := base + i%(NumAccount/global.NumGroup)*50
		if index%1000 == 0 {
			//	一级节点
			account = accounts.Accounts[i/(NumAccount/global.NumGroup)]
			account.Admin = [][]string{{addresses[i], strconv.Itoa(index)}}
			account.Users = [][]string{}
		} else {
			account.Users = append(account.Users, []string{addresses[i], strconv.Itoa(index)})
			if (i%(NumAccount/global.NumGroup) + 1) == (NumAccount / global.NumGroup) {
				accounts.Accounts[i/(NumAccount/global.NumGroup)] = account
				base += 1000
			}
		}
	}
	file, err := os.Create(global.ConfigPath + "accounts.json")
	global.MyError(err)
	enc := json.NewEncoder(file)
	enc.SetIndent("", "\t")
	err = enc.Encode(accounts)
	global.MyError(err)
	file.Close()
}

func OpenConfig(port int) {
	// open configs
	fileName := fmt.Sprintf(global.ConfigPath+"config_%d.json", port)
	file1, err := os.Open(fileName)
	global.MyError(err)
	defer file1.Close()
	config := new(global.Config)
	err = json.NewDecoder(file1).Decode(config)
	global.MyError(err)
	global.Cfg = config
	//获取当前端口的秘钥
	file2, err := os.Open(global.ConfigPath + "configs.json")
	global.MyError(err)
	defer file2.Close()
	keys := new(global.Quorums)
	err = json.NewDecoder(file2).Decode(keys)
	global.MyError(err)
	global.D = keys.Keys[strconv.Itoa(port)]
}

func main() {
	app := &cli.App{
		Name:                 "A high-speed railway big data system based on BDLS consensus protocol",
		Usage:                "Generate genesis block or login the system or generate keys or run the system",
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			{
				Name:  "genesis",
				Usage: "generate a genesis block",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "configs",
						Value: "./quorum.json",
						Usage: "the shared quorum configs file",
					},
					&cli.IntFlag{
						Name:  "listen",
						Value: 3000,
						Usage: "the client's listening port",
					},
				},
				Action: func(c *cli.Context) error {
					//global.PortId = strconv.Itoa(c.Int("listen"))
					// open quorum configs
					file, err := os.Open(c.String("configs"))
					if err != nil {
						return err
					}
					defer file.Close()

					quorum := new(Quorum)
					err = json.NewDecoder(file).Decode(quorum)
					if err != nil {
						return err
					}
					//将所有共识委员加入到管理员数组
					length := len(quorum.Keys)
					index := -1
					for k := range quorum.Keys {
						priv := new(ecdsa.PrivateKey)
						priv.PublicKey.Curve = bdls.S256Curve
						priv.D = quorum.Keys[k]
						priv.PublicKey.X, priv.PublicKey.Y = bdls.S256Curve.ScalarBaseMult(priv.D.Bytes())
						address := hex.EncodeToString(global.GetFillBytes(priv.X, priv.Y))
						if k%(length/global.NumGroup) == 0 {
							global.Admin = append(global.Admin, address)
							global.Keys = append(global.Keys, quorum.Keys[k])
							index++
						} else {
							global.UserKeys[index] = append(global.UserKeys[index], quorum.Keys[k])
							global.Users[index] = append(global.Users[index], address)
						}
					}
					genesisBlock()
					return nil
				},
			},
			{
				Name:  "login",
				Usage: "login system to start a consensus",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "account",
						Value: "",
						Usage: "string of registration",
					},
					&cli.IntFlag{
						Name:  "port",
						Value: 0,
						Usage: "the client's listening port",
					},
				},
				Action: func(c *cli.Context) error {
					port := c.Int("port")
					if port == 0 {
						return errors.New(fmt.Sprint("Port cannot be a zero"))
					}
					OpenConfig(port)
					//account := c.String("account")
					//获取该账户的私钥
					d := global.D
					priv := new(ecdsa.PrivateKey)
					priv.PublicKey.Curve = bdls.S256Curve
					priv.D = d
					priv.PublicKey.X, priv.PublicKey.Y = bdls.S256Curve.ScalarBaseMult(priv.D.Bytes())
					//获取该账户的公钥
					pubStr := hex.EncodeToString(global.GetFillBytes(priv.X, priv.Y))
					//if len(account) == 0 {
					//	return errors.New(fmt.Sprint("Account cannot be a zero"))
					//}
					// create configuration
					config := new(bdls.Config)
					config.Epoch = time.Now()
					config.CurrentHeight = 0
					config.StateCompare = func(a bdls.State, b bdls.State) int { return bytes.Compare(a, b) }
					config.StateValidate = func(bdls.State) bool { return true }
					for _, pair := range global.Cfg.Group {
						if pair[0] == pubStr {
							//该账户为当前登录账户
							global.PortId = "5" + pair[1]
							global.HttpId = "4" + pair[1]
							Id, _ = strconv.Atoi(pair[1])
							global.CurrentId = Id
						}
						pub := new(ecdsa.PublicKey)
						pub.Curve = bdls.S256Curve
						pubBytes, _ := hex.DecodeString(pair[0])
						x, y := new(big.Int), new(big.Int)
						x.SetBytes(pubBytes[:len(pubBytes)/2])
						y.SetBytes(pubBytes[len(pubBytes)/2:])
						pub.X, pub.Y = x, y
						config.Participants = append(config.Participants, bdls.DefaultPubKeyToIdentity(pub))
					}
					config.PrivateKey = priv
					//进行全局相关变量配置以及登录操作
					if len(global.PortId) != 5 {
						return errors.New(fmt.Sprint("The account is not registered in the system"))
					}
					fmt.Println("当前账户ID为：", Id)
					global.PublicKey = global.GetFillBytes(priv.X, priv.Y)
					global.PrivateKey = priv
					global.BlockChainTotal = global.GetBlockChain(strconv.Itoa(Id))
					defer global.BlockChainTotal.DB.Close()
					user.BlockchainUser = &user.BlockChain_User{global.BlockChainTotal.TipHashUser, global.BlockChainTotal.DB}
					train.BlockchainTrain = &train.BlockChain_Train{global.BlockChainTotal.TipHashTrain, global.BlockChainTotal.DB}
					//验证账户是否有效、合法
					status := user.BlockchainUser.UiLoginVerify(d)
					fmt.Println("当前账户身份：", status)
					if status == "error" {
						return errors.New(fmt.Sprint("Account cannot login to the system"))
					}
					if c.Int("port")%1000 == 0 {
						global.StatusLogin = global.BureauStatus
					} else {
						global.StatusLogin = global.TrainStatus
					}
					if err := startConsensus(config); err != nil {
						return err
					}
					return nil
				},
			},
			{
				Name:  "genkeys",
				Usage: "generate quorum to participant in consensus",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:  "count",
						Value: 4,
						Usage: "number of participant in quorum",
					},
					&cli.StringFlag{
						Name:  "configs",
						Value: "./quorum.json",
						Usage: "output quorum file",
					},
				},
				Action: func(c *cli.Context) error {
					count := c.Int("count")
					NumAccount = count
					quorum := &Quorum{}
					// generate private keys
					for i := 0; i < count; i++ {
						privateKey, err := ecdsa.GenerateKey(bdls.S256Curve, rand.Reader)
						if err != nil {
							return err
						}

						quorum.Keys = append(quorum.Keys, privateKey.D)
						quorum.Account = append(quorum.Account, hex.EncodeToString(global.GetFillBytes(privateKey.X, privateKey.Y)))
					}
					createQuorum(quorum, c.String("configs"))
					createAccounts(quorum.Account)

					log.Println("generate", c.Int("count"), "keys")

					return nil
				},
			},
		},

		Action: func(c *cli.Context) error {
			cli.ShowAppHelp(c)
			return nil
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}

}

// consensus for one round with full procedure
func startConsensus(config *bdls.Config) error {
	// create consensus
	consensus, err := bdls.NewConsensus(config)
	if err != nil {
		return err
	}
	consensus.SetLatency(200 * time.Millisecond)
	// initiate tcp agent
	tagent := agent.NewTCPAgent(consensus, config.PrivateKey)
	if err != nil {
		return err
	}
	// start updater
	tagent.Update()

	go tagent.ReceiverTcp()
	go tagent.ConnectPeer()
	go tagent.HttpServer()
	lastHeight := uint64(0)
NEXTHEIGHT:
	for {
		//if global.StatusLogin == global.TrainStatus {
		//	fmt.Println("propose:")
		//	tagent.Propose([]byte("hello, I'm " + global.PortId + time.Now().String()))
		//}
		for {
			newHeight, newRound, newState := tagent.GetLatestState()
			if newHeight > lastHeight {
				h := blake2b.Sum256(newState)
				////是一个BlockData数据
				//go UpdateBlockchain(newState)
				//获取到数据
				log.Printf("<decide> at height:%v round:%v hash:%v\n", newHeight, newRound, hex.EncodeToString(h[:]))
				//if Id == 5100 {
				//	total += time.Since(start)
				//	log.Printf(" TimeCost:%v Count:%v TotalCost:%v", time.Since(start), count, total)
				//}
				lastHeight = newHeight
				continue NEXTHEIGHT
			}
			// wait
			<-time.After(20 * time.Millisecond)
		}
	}
}
