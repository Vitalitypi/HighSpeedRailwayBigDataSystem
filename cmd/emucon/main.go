package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/yonggewang/bdls/blockchain/train"
	"github.com/yonggewang/bdls/blockchain/user"
	"github.com/yonggewang/bdls/global"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/urfave/cli/v2"
	"github.com/yonggewang/bdls"
	"github.com/yonggewang/bdls/agent-tcp"
	"github.com/yonggewang/bdls/crypto/blake2b"
)

// A quorum set for consenus
type Quorum struct {
	Keys []*big.Int `json:"keys"` // pem formatted keys
}

var Id int

//生成创世区块
func genesisBlock() {
	bytes, err := hex.DecodeString(global.Admin)
	global.MyError(err)
	global.PublicKey = bytes
	global.AddressString = hex.EncodeToString(global.GetAddress(bytes))
	chainUser := user.CreateBlockChainUser()
	chainUser.DB.Close()
	chainTrain := train.CreateBlockChainTrain()
	chainTrain.DB.Close()
}

func main() {
	app := &cli.App{
		Name:                 "BDLS consensus protocol emulator",
		Usage:                "Generate quorum then emulate participants",
		EnableBashCompletion: true,
		Commands: []*cli.Command{
			{
				Name:  "genesis",
				Usage: "generate a genesis block",
				Flags: []cli.Flag{},
				Action: func(c *cli.Context) error {
					genesisBlock()
					return nil
				},
			},
			{
				Name:  "login",
				Usage: "login system to begin",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "account",
						Value: "",
						Usage: "string of registration",
					},
				},
				Action: func(c *cli.Context) error {
					account := c.String("account")
					global.D = account
					global.BlockChainTotal = global.GetBlockChain(global.PortId)
					user.BlockchainUser = &user.BlockChain_User{global.BlockChainTotal.TipHashUser, global.BlockChainTotal.DB}
					train.BlockchainTrain = &train.BlockChain_Train{global.BlockChainTotal.TipHashTrain, global.BlockChainTotal.DB}
					fmt.Println()
					//验证账户是否有效、合法
					global.StatusLogin = user.BlockchainUser.UiLoginVerify()
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
						Name:  "config",
						Value: "./quorum.json",
						Usage: "output quorum file",
					},
				},
				Action: func(c *cli.Context) error {
					count := c.Int("count")
					quorum := &Quorum{}
					// generate private keys
					for i := 0; i < count; i++ {
						privateKey, err := ecdsa.GenerateKey(bdls.S256Curve, rand.Reader)
						if err != nil {
							return err
						}

						quorum.Keys = append(quorum.Keys, privateKey.D)
					}

					file, err := os.Create(c.String("config"))
					if err != nil {
						return err
					}
					enc := json.NewEncoder(file)
					enc.SetIndent("", "\t")
					err = enc.Encode(quorum)
					if err != nil {
						return err
					}
					file.Close()

					log.Println("generate", c.Int("count"), "keys")
					return nil
				},
			},
			{
				Name:  "run",
				Usage: "start a consensus agent",
				Flags: []cli.Flag{
					&cli.StringFlag{
						Name:  "listen",
						Value: ":4680",
						Usage: "the client's listening port",
					},
					&cli.IntFlag{
						Name:  "id",
						Value: 0,
						Usage: "the node id, will use the n-th private key in quorum.json",
					},
					&cli.StringFlag{
						Name:  "config",
						Value: "./quorum.json",
						Usage: "the shared quorum config file",
					},
					&cli.StringFlag{
						Name:  "peers",
						Value: "./peers.json",
						Usage: "all peers's ip:port list to connect, as a json array",
					},
				},
				Action: func(c *cli.Context) error {
					// open quorum config
					file, err := os.Open(c.String("config"))
					if err != nil {
						return err
					}
					defer file.Close()

					quorum := new(Quorum)
					err = json.NewDecoder(file).Decode(quorum)
					if err != nil {
						return err
					}

					id := c.Int("id")
					if id >= len(quorum.Keys) {
						return errors.New(fmt.Sprint("cannot locate private key for id:", id))
					}
					log.Println("identity:", id)
					Id = id
					// create configuration
					config := new(bdls.Config)
					config.Epoch = time.Now()
					config.CurrentHeight = 0
					config.StateCompare = func(a bdls.State, b bdls.State) int { return bytes.Compare(a, b) }
					config.StateValidate = func(bdls.State) bool { return true }

					for k := range quorum.Keys {
						priv := new(ecdsa.PrivateKey)
						priv.PublicKey.Curve = bdls.S256Curve
						priv.D = quorum.Keys[k]
						priv.PublicKey.X, priv.PublicKey.Y = bdls.S256Curve.ScalarBaseMult(priv.D.Bytes())
						// myself
						if id == k {
							config.PrivateKey = priv
						}

						// set validator sequence
						config.Participants = append(config.Participants, bdls.DefaultPubKeyToIdentity(&priv.PublicKey))
					}
					if err := startConsensus(c, config); err != nil {
						return err
					}
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
func startConsensus(c *cli.Context, config *bdls.Config) error {
	// create consensus
	consensus, err := bdls.NewConsensus(config)
	if err != nil {
		return err
	}
	consensus.SetLatency(200 * time.Millisecond)

	// load endpoints
	file, err := os.Open(c.String("peers"))
	if err != nil {
		return err
	}
	defer file.Close()

	var peers []string
	err = json.NewDecoder(file).Decode(&peers)
	if err != nil {
		return err
	}

	// start listener
	tcpaddr, err := net.ResolveTCPAddr("tcp", c.String("listen"))
	if err != nil {
		return err
	}

	l, err := net.ListenTCP("tcp", tcpaddr)
	if err != nil {
		return err
	}
	defer l.Close()
	log.Println("listening on:", c.String("listen"))

	// initiate tcp agent
	tagent := agent.NewTCPAgent(consensus, config.PrivateKey)
	if err != nil {
		return err
	}

	// start updater
	tagent.Update()

	// passive connection from peers
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			log.Println("peer connected from:", conn.RemoteAddr())
			// peer endpoint created
			p := agent.NewTCPPeer(conn, tagent)
			tagent.AddPeer(p)
			// prove my identity to this peer
			p.InitiatePublicKeyAuthentication()
		}
	}()

	// active connections to peers
	for k := range peers {
		go func(raddr string) {
			for {
				conn, err := net.Dial("tcp", raddr)
				if err == nil {
					log.Println("connected to peer:", conn.RemoteAddr())
					// peer endpoint created
					p := agent.NewTCPPeer(conn, tagent)
					tagent.AddPeer(p)
					// prove my identity to this peer
					p.InitiatePublicKeyAuthentication()
					return
				}
				<-time.After(time.Second)
			}
		}(peers[k])
	}

	lastHeight := uint64(0)
	go startHttpServer()
NEXTHEIGHT:
	for {
		//获取到数据

		//fmt.Println("propose...")
		for {
			newHeight, newRound, newState := tagent.GetLatestState()
			if newHeight > lastHeight {
				h := blake2b.Sum256(newState)
				log.Printf("<decide> at height:%v round:%v hash:%v", newHeight, newRound, hex.EncodeToString(h[:]))
				lastHeight = newHeight
				continue NEXTHEIGHT
			}
			// wait
			<-time.After(20 * time.Millisecond)
		}
	}
}

func startHttpServer() {
	// 1.创建路由
	r := gin.Default()
	// 2.绑定路由规则，执行的函数
	// gin.Context，封装了request和response
	r.GET("/", func(c *gin.Context) {
		c.String(http.StatusOK, "hello World!")
	})
	r.POST("/register", func(c *gin.Context) {
		fmt.Println(c.PostForm("name"))
		c.JSON(http.StatusOK, gin.H{
			"status": gin.H{
				"code":    http.StatusOK,
				"success": true,
			},
			"name": "Jane",
			"nick": "123",
		})
	})
	// 3.监听端口，默认在8080
	// Run("里面不指定端口号默认为8080")
	r.Run(":8000")
}
